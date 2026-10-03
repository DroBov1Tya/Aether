use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use chrono::{DateTime, Utc};
use clickhouse::{Client, Row};
use serde::Serialize;

#[derive(Debug, Row, Serialize)]
struct TaskQueueRow {
    id: u64,
    task_id: String,
    target: String,
    payload: String,
    #[serde(with = "clickhouse::serde::chrono::datetime::option")]
    assigned_at: Option<DateTime<Utc>>,
    #[serde(with = "clickhouse::serde::chrono::datetime::option")]
    finished_at: Option<DateTime<Utc>>,
    #[serde(with = "clickhouse::serde::chrono::datetime::option")]
    lease_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Row, Serialize)]
struct TaskUpdateRow {
    id: u64,
    task_id: String,
    target: String,
    payload: String,
    status: String,
    agent_id: String,
    attempts: u8,
    error: String,
    #[serde(with = "clickhouse::serde::chrono::datetime::option")]
    assigned_at: Option<DateTime<Utc>>,
    #[serde(with = "clickhouse::serde::chrono::datetime::option")]
    finished_at: Option<DateTime<Utc>>,
    #[serde(with = "clickhouse::serde::chrono::datetime::option")]
    lease_until: Option<DateTime<Utc>>,
}

pub const LEASE_MINUTES: i64 = 10;
pub const MAX_ATTEMPTS: u8 = 3;

fn now() -> DateTime<Utc> {
    Utc::now()
}

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

async fn next_id(client: &Client) -> u64 {
    if NEXT_ID.load(Ordering::SeqCst) == 0 {
        let seed = match client
            .query("SELECT max(id) AS m FROM task_queue")
            .fetch_bytes("JSONEachRow")
        {
            Ok(mut c) => {
                let b = c.collect().await.unwrap_or_default();
                b.split(|&x| x == b'\n')
                    .find(|l| !l.is_empty())
                    .and_then(|l| serde_json::from_slice::<serde_json::Value>(l).ok())
                    .and_then(|v| v["m"].as_u64())
                    .unwrap_or(0)
                    + 1
            }
            Err(e) => {
                tracing::warn!("id seed query failed ({e}); starting from 1");
                1
            }
        };
        let _ = NEXT_ID.compare_exchange(0, seed, Ordering::SeqCst, Ordering::SeqCst);
    }
    NEXT_ID.fetch_add(1, Ordering::SeqCst)
}

pub async fn enqueue(
    client: &Client,
    task_id: &str,
    targets: &[String],
    payload: &str,
) -> Result<u64> {
    if targets.is_empty() {
        return Ok(0);
    }

    const BATCH: usize = 5000;
    let mut queued: u64 = 0;
    for chunk in targets.chunks(BATCH) {
        let mut inserter = client.insert::<TaskQueueRow>("task_queue").await?;
        for target in chunk {
            let id = next_id(client).await;
            inserter
                .write(&TaskQueueRow {
                    id,
                    task_id: task_id.to_string(),
                    target: target.to_string(),
                    payload: payload.to_string(),
                    assigned_at: None,
                    finished_at: None,
                    lease_until: None,
                })
                .await?;
        }
        inserter.end().await?;
        queued += chunk.len() as u64;
    }
    Ok(queued)
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaimedTask {
    pub id: u64,
    pub task_id: String,
    pub target: String,
    pub payload: String,
}

pub async fn claim(client: &Client, agent_id: &str, n: u32) -> Result<Vec<ClaimedTask>> {
    let lease_until = now() + chrono::Duration::minutes(LEASE_MINUTES);

    let bytes = client
        .query("SELECT id, task_id, target, payload \
                FROM task_queue FINAL \
                WHERE (status = 'queued') \
                   OR (status = 'claimed' AND lease_until IS NOT NULL AND lease_until <= now()) \
                ORDER BY id \
                LIMIT ?")
        .bind(n)
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;

    let mut out = Vec::new();
    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        let id = match v["id"].as_u64() {
            Some(id) => id,
            None => continue,
        };
        let task_id = v["task_id"].as_str().unwrap_or_default().to_string();
        let target = v["target"].as_str().unwrap_or_default().to_string();
        let payload = v["payload"].as_str().unwrap_or_default().to_string();

        let attempts: u8 = {
            let c = client
                .query("SELECT attempts FROM task_queue FINAL WHERE id = ?")
                .bind(id)
                .fetch_bytes("JSONEachRow");
            match c {
                Ok(mut c) => c
                    .collect()
                    .await
                    .map(|b| {
                        b.split(|&x| x == b'\n')
                            .find(|l| !l.is_empty())
                            .and_then(|l| serde_json::from_slice::<serde_json::Value>(l).ok())
                            .and_then(|v| v["attempts"].as_u64())
                            .unwrap_or(0) as u8
                    })
                    .unwrap_or(0),
                Err(_) => 0,
            }
        };

        let row = TaskUpdateRow {
            id,
            task_id: task_id.clone(),
            target: target.clone(),
            payload: payload.clone(),
            status: "claimed".to_string(),
            agent_id: agent_id.to_string(),
            attempts: (attempts + 1).min(u8::MAX),
            error: String::new(),
            assigned_at: Some(now()),
            finished_at: None,
            lease_until: Some(lease_until),
        };
        let mut inserter = match client.insert::<TaskUpdateRow>("task_queue").await {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!("claim insert failed for id={id}: {e}");
                continue;
            }
        };
        match inserter.write(&row).await {
            Ok(()) => match inserter.end().await {
                Ok(()) => out.push(ClaimedTask {
                    id,
                    task_id,
                    target,
                    payload,
                }),
                Err(e) => tracing::warn!("claim end failed for id={id}: {e}"),
            },
            Err(e) => tracing::warn!("claim write failed for id={id}: {e}"),
        }
    }

    Ok(out)
}

pub async fn finish(client: &Client, id: u64, agent_id: &str, ok: bool, error: &str) -> Result<()> {
    let bytes = client
        .query("SELECT task_id, target, payload, attempts, toString(assigned_at) AS assigned_at FROM task_queue FINAL WHERE id = ?")
        .bind(id)
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;

    let line = bytes.split(|&b| b == b'\n').find(|l| !l.is_empty());
    let Some(v) = line.and_then(|l| serde_json::from_slice::<serde_json::Value>(l).ok()) else {
        tracing::warn!("finish: task {id} not found, ignoring");
        return Ok(());
    };

    let task_id = v["task_id"].as_str().unwrap_or_default().to_string();
    let target = v["target"].as_str().unwrap_or_default().to_string();
    let payload = v["payload"].as_str().unwrap_or_default().to_string();
    let attempts = v["attempts"].as_u64().unwrap_or(1) as u8;
    let assigned_at = v["assigned_at"]
        .as_str()
        .and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok())
        .map(|ndt| ndt.and_utc())
        .or_else(|| Some(now()));

    let (status, lease_until) = if ok {
        ("done", None)
    } else if attempts >= MAX_ATTEMPTS {
        ("failed", None)
    } else {
        ("queued", None)
    };

    let row = TaskUpdateRow {
        id,
        task_id,
        target: target.clone(),
        payload,
        status: status.to_string(),
        agent_id: agent_id.to_string(),
        attempts,
        error: if ok { String::new() } else { error.to_string() },
        assigned_at,
        finished_at: Some(now()),
        lease_until,
    };
    let mut inserter = client.insert::<TaskUpdateRow>("task_queue").await?;
    inserter.write(&row).await?;
    inserter.end().await?;

    if !ok {
        tracing::warn!("task {id} ({target}): attempt {attempts} failed: {error}");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskSummary {
    pub task_id: String,
    pub total: u64,
    pub queued: u64,
    pub claimed: u64,
    pub done: u64,
    pub failed: u64,
    pub created_at: String,
}

fn summarize(v: &serde_json::Value) -> TaskSummary {
    TaskSummary {
        task_id: v["task_id"].as_str().unwrap_or_default().to_string(),
        total: v["total"].as_u64().unwrap_or(0),
        queued: v["queued"].as_u64().unwrap_or(0),
        claimed: v["claimed"].as_u64().unwrap_or(0),
        done: v["done"].as_u64().unwrap_or(0),
        failed: v["failed"].as_u64().unwrap_or(0),
        created_at: v["created_at"].as_str().unwrap_or_default().to_string(),
    }
}

const SUMMARY_SQL: &str =
    "SELECT task_id, \
        count(*) AS total, \
        countIf(status = 'queued') AS queued, \
        countIf(status = 'claimed') AS claimed, \
        countIf(status = 'done') AS done, \
        countIf(status = 'failed') AS failed, \
        toString(min(created_at)) AS created_at \
     FROM task_queue FINAL \
     {where} \
     GROUP BY task_id \
     ORDER BY created_at DESC \
     LIMIT ?";

pub async fn task_list(client: &Client, limit: u32) -> Result<Vec<TaskSummary>> {
    let bytes = client
        .query(&SUMMARY_SQL.replace("{where}", ""))
        .bind(limit)
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;

    let mut out = Vec::new();
    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) {
            out.push(summarize(&v));
        }
    }
    Ok(out)
}

pub async fn task_progress(client: &Client, task_id: &str) -> Result<TaskSummary> {
    let bytes = client
        .query(&SUMMARY_SQL.replace("{where}", "WHERE task_id = ?"))
        .bind(task_id)
        .bind(1u32)
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;

    let line = bytes.split(|&b| b == b'\n').find(|l| !l.is_empty());
    let v = line
        .and_then(|l| serde_json::from_slice::<serde_json::Value>(l).ok())
        .ok_or_else(|| anyhow::anyhow!("task {task_id} not found"))?;
    Ok(summarize(&v))
}
