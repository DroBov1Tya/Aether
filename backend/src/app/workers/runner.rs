use clickhouse::Client as ChClient;
use redis::aio::ConnectionManager;
use serde_json::json;
use uuid::Uuid;

use super::controller;
use crate::app::databases::clickhouse::queries::agents;
use crate::app::databases::redis::tasks;

pub struct PipelineTask {
    pub task_id: Uuid,
    pub cidrs: Option<Vec<String>>,
    pub ranges: Option<Vec<String>>,
    pub ips: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
    pub methods: Option<Vec<String>>,
}

struct AgentSelection {
    id: Uuid,
    ip: String,
    port: i32,
}

async fn pick_agent(ch: &ChClient, conn: &mut ConnectionManager) -> Option<AgentSelection> {
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
        let count = tasks::count_agent_tasks(conn, id).await;
        if count as i32 >= agent.max_concurrent_tasks {
            continue;
        }
        match best {
            Some((_, best_count)) if count >= best_count => {}
            _ => best = Some((agent, count)),
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

pub async fn run_pipeline(task: PipelineTask, ch: &ChClient, conn: &mut ConnectionManager, api_key: &str) {
    let cidrs = task.cidrs.as_deref().unwrap_or(&[]);
    let ranges = task.ranges.as_deref().unwrap_or(&[]);
    let ips = task.ips.as_deref().unwrap_or(&[]);
    let domains = task.domains.as_deref().unwrap_or(&[]);

    let expanded = controller::expand_targets(cidrs, ranges, ips);

    tasks::init(conn, task.task_id).await;

    if !expanded.is_empty() {
        for ip in &expanded {
            tracing::info!("task {} -> target IP: {}", task.task_id, ip);
            tasks::add_target(conn, task.task_id, ip).await;
        }
    }

    if !domains.is_empty() {
        for domain in domains {
            tracing::info!("task {} -> domain: {}", task.task_id, domain);
        }
    }

    if let Some(agent) = pick_agent(ch, conn).await {
        tasks::assign(conn, task.task_id, agent.id).await;
        tracing::info!("task {} assigned to agent {}:{}", task.task_id, agent.ip, agent.port);

        let client = reqwest::Client::new();
        for ip in &expanded {
            let url = format!("http://{}:{}/api/scan", agent.ip, agent.port);
            let body = json!({
                "target": ip,
                "task_uid": task.task_id.to_string(),
            });
            match client.post(&url).header("X-API-KEY", api_key).json(&body).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        tracing::info!("task {} pushed target {} to agent", task.task_id, ip);
                    } else {
                        tracing::warn!(
                            "task {} agent {} rejected target {}: {}",
                            task.task_id, agent.id, ip, resp.status()
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "task {} failed to push target {} to agent {}: {}",
                        task.task_id, ip, agent.id, e
                    );
                }
            }
        }
    } else {
        tracing::warn!("task {} no available agent", task.task_id);
    }
}
