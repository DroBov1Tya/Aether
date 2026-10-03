use crate::app::{AppState, server::handlers::scan};
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{json, Value};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tracing::info;

mod metadata;
use metadata::AgentMetadata;

struct BusyGuard(Arc<AtomicU8>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn busy(state: &AppState) -> u8 {
    state.busy.load(Ordering::SeqCst)
}

pub async fn start(state: Arc<AppState>) -> Result<()> {
    let mut agent_id = state.cfg.agent_id.clone();
    let mut agent_token = state.cfg.agent_token.clone();

    if agent_id.is_empty() || agent_token.is_empty() {
        if let Some(creds) = load_credentials(&state.cfg.credentials_path) {
            if agent_id.is_empty() {
                agent_id = creds.agent_id;
            }
            if agent_token.is_empty() {
                agent_token = creds.agent_token;
            }
        }
    }

    if agent_id.is_empty() || agent_token.is_empty() {
        let (id, token) = register(&state).await?;
        agent_id = id;
        agent_token = token;
        if let Err(e) = save_credentials(&state.cfg.credentials_path, &agent_id, &agent_token) {
            tracing::warn!("saving agent credentials failed: {e}");
        }
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build http client")?;

    let base = state.cfg.external_server_path.trim_end_matches('/');
    let mut heartbeat_url = format!("{base}/api/agents/{agent_id}/heartbeat");
    let mut claim_url = format!("{base}/api/agents/{agent_id}/tasks/claim");
    let mut finish_url = format!("{base}/api/agents/{agent_id}/tasks");

    let mut heartbeat_tick = tokio::time::interval(Duration::from_secs(15));
    let mut claim_tick = tokio::time::interval(Duration::from_millis(500));
    let mut shutdown = state.shutdown.subscribe();
    heartbeat_tick.tick().await;
    claim_tick.tick().await;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = shutdown.recv() => break,

            _ = heartbeat_tick.tick() => {
                let r = client
                    .post(&heartbeat_url)
                    .header("X-API-KEY", &agent_token)
                    .json(&json!({ "busy": busy(&state) }))
                    .send()
                    .await;
                match r {
                    Ok(r) if r.status().is_success() => {
                        if let Ok(body) = r.json::<Value>().await {
                            if let Some(cap) = body["max_concurrent_tasks"].as_u64() {
                                let cap = cap.clamp(1, 100) as u8;
                                if state.capacity.swap(cap, Ordering::SeqCst) != cap {
                                    tracing::info!("capacity updated to {cap} via heartbeat");
                                }
                            }
                        }
                    }
                    Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                        tracing::warn!("backend rejected our token; re-registering");
                        let (id, token) = match register(&state).await {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!("re-register failed: {e}; retrying in 30s");
                                tokio::time::sleep(Duration::from_secs(30)).await;
                                continue;
                            }
                        };
                        agent_id = id;
                        agent_token = token;
                        heartbeat_url = format!("{base}/api/agents/{agent_id}/heartbeat");
                        claim_url = format!("{base}/api/agents/{agent_id}/tasks/claim");
                        finish_url = format!("{base}/api/agents/{agent_id}/tasks");
                        if let Err(e) = save_credentials(&state.cfg.credentials_path, &agent_id, &agent_token) {
                            tracing::warn!("saving new credentials failed: {e}");
                        }
                    }
                    Ok(r) => tracing::warn!("heartbeat: {}", r.status()),
                    Err(e) => tracing::warn!("heartbeat failed: {e}"),
                }
            }

            _ = claim_tick.tick() => {
                let capacity = (state.capacity.load(Ordering::SeqCst) as usize)
                    .saturating_sub(busy(&state) as usize);
                if capacity == 0 {
                    continue;
                }
                let r = client
                    .post(&format!("{claim_url}?limit={capacity}"))
                    .header("X-API-KEY", &agent_token)
                    .send()
                    .await;
                let Ok(r) = r else { continue };
                if !r.status().is_success() {
                    tracing::warn!("claim: {}", r.status());
                    continue;
                }
                let Ok(body) = r.json::<Value>().await else { continue };
                let Some(items) = body["data"].as_array() else { continue };

                for item in items {
                    let Some(queue_id) = item["id"].as_u64() else { continue };
                    let Some(target) = item["target"].as_str() else {
                        continue;
                    };
                    let target = target.to_string();
                    let task_id = item["task_id"].as_str().unwrap_or("").to_string();
                    let settings = parse_settings(item.get("payload"));

                    state.busy.fetch_add(1, Ordering::SeqCst);
                    let state = Arc::clone(&state);
                    let finish_url = finish_url.clone();
                    let token = agent_token.clone();
                    let task_id = task_id.clone();
                    tokio::spawn(async move {
                        let _guard = BusyGuard(state.busy.clone());
                        let ok = scan::run_pipeline(&state, &target, Some(&task_id), &settings).await;

                        let url = format!("{finish_url}/{queue_id}/finish");
                        let r = reqwest::Client::new()
                            .post(&url)
                            .header("X-API-KEY", &token)
                            .json(&json!({ "task_id": queue_id.to_string(), "success": ok }))
                            .send()
                            .await;
                        match r {
                            Ok(r) if r.status().is_success() => {}
                            Ok(r) => tracing::warn!("finish {queue_id}: {}", r.status()),
                            Err(e) => tracing::warn!("finish {queue_id} failed: {e}"),
                        }
                    });
                }
            }
        }
    }

    Ok(())
}

fn parse_settings(payload: Option<&Value>) -> scan::ScanSettings {
    let Some(payload) = payload else {
        return scan::ScanSettings::default();
    };
    let Ok(v) = serde_json::from_str::<Value>(payload.as_str().unwrap_or("")) else {
        return scan::ScanSettings::default();
    };
    scan::ScanSettings {
        port_range: v["settings"]["port_range"].as_str().map(String::from),
        threads: v["settings"]["threads"].as_u64().map(|t| t as u32),
        timeout_ms: v["settings"]["timeout_ms"].as_u64(),
        proxy: v["settings"]["proxy"].as_str().map(String::from),
    }
}

async fn register(state: &AppState) -> Result<(String, String)> {
    let meta = AgentMetadata::collect(env!("CARGO_PKG_VERSION"));

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build http client")?;

    let base = state.cfg.external_server_path.trim_end_matches('/');
    let url = format!("{base}/api/register/agent");

    let json = json!({
        "hostname": &meta.hostname,
        "version": &meta.version,
        "os": &meta.os,
        "arch": &meta.arch,
        "ip": &meta.ip,
        "kernel": &meta.kernel,
        "port": state.cfg.port,
        "max_concurrent_tasks": state.cfg.max_concurrent_tasks,
        "name": if state.cfg.agent_name.is_empty() { meta.hostname.clone() } else { state.cfg.agent_name.clone() },
        "agent_id": load_credentials(&state.cfg.credentials_path).map(|c| c.agent_id).unwrap_or_default(),
    });

    let mut req = client.post(&url).json(&json);
    // Enrollment token authorizes first-time join; API key kept for legacy fallback.
    if !state.cfg.enroll_token.is_empty() {
        req = req.header("X-ENROLL-TOKEN", &state.cfg.enroll_token);
    }
    if !state.cfg.api_key.is_empty() {
        req = req.header("X-API-KEY", &state.cfg.api_key);
    }

    let response = req
        .send()
        .await
        .context("register request failed")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("register failed: status={status} body={body}");
    }

    let v: Value = response.json().await.context("parsing register response")?;
    let agent_id = v["agent_id"].as_str().context("no agent_id in response")?;
    let agent_token = v["token"].as_str().context("no token in response")?;

    info!(
        hostname = %meta.hostname,
        os = %meta.os,
        arch = %meta.arch,
        version = %meta.version,
        "agent registered"
    );

    Ok((agent_id.to_string(), agent_token.to_string()))
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Credentials {
    agent_id: String,
    agent_token: String,
}

fn load_credentials(path: &str) -> Option<Credentials> {
    let s = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&s).ok()
}

fn save_credentials(path: &str, agent_id: &str, agent_token: &str) -> std::io::Result<()> {
    let c = Credentials {
        agent_id: agent_id.to_string(),
        agent_token: agent_token.to_string(),
    };
    std::fs::write(path, serde_json::to_string_pretty(&c)?)
}
