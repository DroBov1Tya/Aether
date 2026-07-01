use reqwest::Client;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;

static COUNTRY_CACHE: Mutex<Option<HashMap<String, Option<String>>>> = Mutex::new(None);

pub const CENSYS_UA: &str =
    "Mozilla/5.0 (compatible; Censys Inspect/1.1; +https://about.censys.io/)";
pub const CENSYS_NMAP_ARGS: &[&str] = &["--osscan-guess", "--version-intensity=9"];

#[derive(Debug, Clone, Serialize)]
pub struct ExternalReq {
    pub status: String,
    pub target: String,
    pub body: String,
    pub version: &'static str,
    pub scan_uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
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

pub async fn lookup_country(target: &str) -> Option<String> {
    {
        let cache = COUNTRY_CACHE.lock().unwrap();
        if let Some(ref map) = *cache {
            if let Some(cached) = map.get(target) {
                return cached.clone();
            }
        }
    }

    let url = format!("http://ip-api.com/json/{}?fields=country", target);
    let result = match Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(client) => match client.get(&url).send().await {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(body) => body
                    .get("country")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                Err(_) => None,
            },
            Err(_) => None,
        },
        Err(_) => None,
    };

    {
        let mut cache = COUNTRY_CACHE.lock().unwrap();
        cache
            .get_or_insert_with(HashMap::new)
            .insert(target.to_string(), result.clone());
    }

    result
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
