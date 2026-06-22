use crate::app::AppState;
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::json;
use std::{process::exit, sync::Arc, time::Duration};
use tracing::info;

mod metadata;
use metadata::AgentMetadata;

pub async fn start(state: Arc<AppState>) -> Result<()> {
    register(&state).await?;

    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let client = Client::new();
        let backend_url = state.cfg.external_server_path.as_str();

        let response = client
            .get(backend_url)
            .header("X-API-KEY", state.cfg.api_key.clone())
            .send()
            .await;

        match response {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Backend check failed: {}", e);
                exit(1)
            }
        }
    }
}

async fn register(state: &AppState) -> Result<()> {
    let meta = AgentMetadata::collect(env!("CARGO_PKG_VERSION"));

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build http client")?;

    let base = state.cfg.external_server_path.trim_end_matches('/');
    let url = format!("{}/api/register/agent", base);

    let json = json!({
        "hostname": &meta.hostname,
        "version": &meta.version,
        "os": &meta.os,
        "arch": &meta.arch,
        "ip": &meta.ip,
        "kernel": &meta.kernel,
        "port": state.cfg.port
    });

    let response = client
        .post(&url)
        .header("X-API-KEY", &state.cfg.api_key)
        .json(&json)
        .send()
        .await
        .context("register request failed")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("register failed: status={status} body={body}");
    }

    info!(
        hostname = %meta.hostname,
        os = %meta.os,
        arch = %meta.arch,
        version = %meta.version,
        "agent registered"
    );

    Ok(())
}
