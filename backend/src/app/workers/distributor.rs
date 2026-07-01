use std::time::Duration;

use clickhouse::Client as ChClient;
use redis::aio::ConnectionManager;
use uuid::Uuid;

use crate::app::databases::clickhouse::queries::agents;
use crate::app::databases::redis::tasks;

const BATCH_SIZE: isize = 10;
const MAX_TARGETS_PER_AGENT: u32 = 10;

struct AgentSelection {
    pub id: Uuid,
    pub ip: String,
    pub port: i32,
}

async fn pick_agent(
    ch: &ChClient,
    conn: &mut ConnectionManager,
    task_target_count: u32,
) -> Option<AgentSelection> {
    let agents_list = match agents::list_active(ch).await {
        Ok(a) => a,
        Err(_) => return None,
    };
    if agents_list.is_empty() {
        return None;
    }

    let mut best: Option<(&agents::AgentInfo, u32)> = None;
    for agent in &agents_list {
        let id = match Uuid::parse_str(&agent.id) {
            Ok(id) => id,
            Err(_) => continue,
        };
        let task_count = tasks::count_agent_tasks(conn, id).await;
        if task_count as i32 >= agent.max_concurrent_tasks {
            continue;
        }
        let target_count = tasks::count_agent_targets(conn, id).await;
        if target_count + task_target_count > MAX_TARGETS_PER_AGENT {
            continue;
        }
        match best {
            Some((_, best_count)) if task_count >= best_count => {}
            _ => best = Some((agent, task_count)),
        }
    }

    best.map(|(a, _)| {
        let id = Uuid::parse_str(&a.id).unwrap();
        AgentSelection {
            id,
            ip: a.ip.clone(),
            port: a.port,
        }
    })
}

pub async fn run(ch: ChClient, mut redis: ConnectionManager, api_key: String) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.tick().await;

    loop {
        interval.tick().await;

        let task_id_str = match tasks::pop_pending(&mut redis).await {
            Some(id) => id,
            None => continue,
        };

        let task_id = match Uuid::parse_str(&task_id_str) {
            Ok(id) => id,
            Err(_) => continue,
        };

        let target_count = tasks::get_target_count(&mut redis, &task_id_str).await;

        let agent = match pick_agent(&ch, &mut redis, target_count).await {
            Some(a) => a,
            None => {
                tracing::warn!(
                    "no agent available for task {} ({} targets), re-queuing",
                    task_id,
                    target_count
                );
                tasks::mark_pending(&mut redis, &task_id_str).await;
                continue;
            }
        };

        tasks::assign(&mut redis, task_id, agent.id, target_count).await;
        tracing::info!(
            "distributor: task {} -> agent {}:{}",
            task_id,
            agent.ip,
            agent.port
        );

        let mut offset: isize = 0;
        loop {
            let targets = tasks::get_targets(&mut redis, &task_id_str, offset, BATCH_SIZE).await;
            if targets.is_empty() {
                break;
            }

            tasks::push_targets(
                &mut redis, task_id, &targets, &agent.ip, agent.port, &api_key,
            )
            .await;

            tracing::info!(
                "distributor: task {} pushed {}-{} / pushed to agent",
                task_id,
                offset,
                offset + targets.len() as isize
            );

            offset += targets.len() as isize;
        }

        tracing::info!("distributor: task {} fully distributed", task_id);
    }
}
