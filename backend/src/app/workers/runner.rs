use anyhow::Result;
use clickhouse::Client as ChClient;
use redis::aio::ConnectionManager;
use uuid::Uuid;

use super::controller;
use crate::app::databases::redis::tasks;

pub struct PipelineTask {
    pub task_id: Uuid,
    pub cidrs: Option<Vec<String>>,
    pub ranges: Option<Vec<String>>,
    pub ips: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
    pub methods: Option<Vec<String>>,
}

const TARGETS_PER_TASK: usize = 10;

async fn create_subtask(conn: &mut ConnectionManager, targets: &[String]) {
    let subtask_id = Uuid::new_v4();
    tasks::init(conn, subtask_id).await;
    tasks::add_targets(conn, subtask_id, targets).await;
    tasks::mark_pending(conn, &subtask_id.to_string()).await;
    tracing::info!(
        "subtask {} created with {} targets",
        subtask_id,
        targets.len()
    );
}

async fn drain_buffer(conn: &mut ConnectionManager, buf: &mut Vec<String>, total: &mut u64) {
    if buf.is_empty() {
        return;
    }
    create_subtask(conn, buf).await;
    *total += buf.len() as u64;
    buf.clear();
}

pub async fn run_pipeline(
    task: PipelineTask,
    _ch: &ChClient,
    conn: &mut ConnectionManager,
    _api_key: &str,
) -> Result<()> {
    let cidrs = task.cidrs.as_deref().unwrap_or(&[]);
    let ranges = task.ranges.as_deref().unwrap_or(&[]);
    let ips = task.ips.as_deref().unwrap_or(&[]);
    let domains = task.domains.as_deref().unwrap_or(&[]);

    let mut total: u64 = 0;
    let mut buf: Vec<String> = Vec::with_capacity(TARGETS_PER_TASK);

    for cidr in cidrs {
        if let Some((start, end)) = controller::parse_cidr(cidr) {
            for n in start..=end {
                buf.push(controller::u32_to_ipv4(n).to_string());
                if buf.len() >= TARGETS_PER_TASK {
                    drain_buffer(conn, &mut buf, &mut total).await;
                }
            }
            drain_buffer(conn, &mut buf, &mut total).await;
        }
    }

    for range in ranges {
        if let Some((start, end)) = controller::parse_range(range) {
            for n in start..=end {
                buf.push(controller::u32_to_ipv4(n).to_string());
                if buf.len() >= TARGETS_PER_TASK {
                    drain_buffer(conn, &mut buf, &mut total).await;
                }
            }
            drain_buffer(conn, &mut buf, &mut total).await;
        }
    }

    for ip in ips {
        if ip.parse::<std::net::Ipv4Addr>().is_ok() {
            buf.push(ip.clone());
            if buf.len() >= TARGETS_PER_TASK {
                drain_buffer(conn, &mut buf, &mut total).await;
            }
        }
    }
    drain_buffer(conn, &mut buf, &mut total).await;

    if !domains.is_empty() {
        for domain in domains {
            tracing::info!("task {} -> domain: {}", task.task_id, domain);
        }
    }

    if total == 0 {
        let sid = Uuid::new_v4();
        tasks::init(conn, sid).await;
        tasks::mark_pending(conn, &sid.to_string()).await;
    }

    tracing::info!(
        "task {} ready with {} targets (split into subtasks of {})",
        task.task_id,
        total,
        TARGETS_PER_TASK
    );

    Ok(())
}
