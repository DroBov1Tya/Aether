use std::sync::OnceLock;

use clickhouse::Client as ChClient;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::app::databases::clickhouse::queries::agents;

static TARGET_TX: OnceLock<mpsc::UnboundedSender<Vec<String>>> = OnceLock::new();

pub fn get_target_tx() -> Option<mpsc::UnboundedSender<Vec<String>>> {
    TARGET_TX.get().cloned()
}

pub async fn run(ch: ChClient, api_key: String) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<String>>();
    let _ = TARGET_TX.set(tx);

    while let Some(targets) = rx.recv().await {
        let agent = match pick_agent(&ch).await {
            Some(a) => a,
            None => {
                tracing::warn!("no agent available for {} targets, skipping", targets.len());
                continue;
            }
        };

        tracing::info!("distributor: {} targets -> agent {}:{}", targets.len(), agent.ip, agent.port);

        push_targets(&targets, &agent.ip, agent.port, &api_key).await;
    }
}

struct AgentSelection {
    pub id: Uuid,
    pub ip: String,
    pub port: i32,
}

async fn pick_agent(ch: &ChClient) -> Option<AgentSelection> {
    let agents_list = match agents::list_active(ch).await {
        Ok(a) if !a.is_empty() => a,
        _ => return None,
    };

    agents_list.into_iter().next().map(|a| {
        let id = Uuid::parse_str(&a.id).unwrap_or_default();
        AgentSelection { id, ip: a.ip, port: a.port }
    })
}

async fn push_targets(targets: &[String], agent_ip: &str, agent_port: i32, api_key: &str) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(10));
    let api_key = std::sync::Arc::new(api_key.to_string());
    let agent_url = std::sync::Arc::new(format!("http://{}:{}/api/scan", agent_ip, agent_port));
    let mut handles = Vec::new();

    for ip in targets {
        let permit = sem.clone().acquire_owned().await.expect("semaphore");
        let client = client.clone();
        let api_key = std::sync::Arc::clone(&api_key);
        let msg = serde_json::json!({"target": ip, "task_uid": ""});
        let url = agent_url.to_string();
        let ip = ip.clone();

        handles.push(tokio::spawn(async move {
            let result = client
                .post(&url)
                .header("X-API-KEY", api_key.as_str())
                .json(&msg)
                .send()
                .await;
            match result {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("pushed {} to agent", ip);
                }
                Ok(resp) => {
                    tracing::warn!("agent {} rejected {}: {}", url, ip, resp.status());
                }
                Err(e) => {
                    tracing::error!("failed to push {}: {}", ip, e);
                }
            }
            drop(permit);
        }));
    }

    for h in handles {
        let _ = h.await;
    }
}
