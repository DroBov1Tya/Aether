use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct ExternalReq {
    pub status: String,
    pub target: String,
    pub body: String,
    pub version: &'static str,
}

pub fn pick_random(items: &[String]) -> Option<&String> {
    if items.is_empty() {
        return None;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let idx = nanos as usize % items.len();
    Some(&items[idx])
}

pub fn apply_proxy(cmd: &mut Command) {
    let cfg = crate::config::cfg();
    if let Some(proxy) = pick_random(&cfg.proxies) {
        cmd.env("ALL_PROXY", proxy);
        cmd.env("HTTP_PROXY", proxy);
        cmd.env("HTTPS_PROXY", proxy);
    }
}

pub async fn post_json<T: Serialize + std::fmt::Debug>(
    url: &str,
    body: &T,
    api_key: &str,
) -> anyhow::Result<reqwest::Response> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let response = client
        .post(url)
        .header("X-API-KEY", api_key)
        .json(body)
        .send()
        .await?;

    Ok(response)
}
