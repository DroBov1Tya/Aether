use reqwest::Client;
use std::time::Duration;

pub async fn fetch_pool(external_server_path: &str, api_key: &str) -> Vec<String> {
    let base = external_server_path.trim_end_matches('/');
    let url = format!("{base}/api/proxies");

    let client = match Client::builder().timeout(Duration::from_secs(10)).build() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let resp = match client.get(&url).header("X-API-KEY", api_key).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("proxy pool fetch failed: {e}");
            return Vec::new();
        }
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    body.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|row| row.get("url").and_then(|u| u.as_str()).map(String::from))
                .filter(|s| !s.trim().is_empty())
                .collect()
        })
        .unwrap_or_default()
}

pub fn local_pool(cfg: &crate::config::Config, cli_proxies: &[String]) -> Vec<String> {
    let cli: Vec<String> = cli_proxies
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !cli.is_empty() {
        cli
    } else {
        cfg.proxies.clone()
    }
}

pub fn attempts(pool: &[String]) -> Vec<Option<String>> {
    let mut v: Vec<Option<String>> = Vec::with_capacity(pool.len() + 1);
    v.push(None);
    for p in pool {
        let t = p.trim();
        if !t.is_empty() {
            v.push(Some(t.to_string()));
        }
    }
    v
}
