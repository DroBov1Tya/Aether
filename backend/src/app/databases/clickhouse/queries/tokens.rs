use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use anyhow::Result;
use chrono::{NaiveDateTime, Utc};
use clickhouse::{Client, Row};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Row, Serialize)]
struct AgentRow {
    agent_id: String,
    token_hash: String,
    name: String,
    ip: String,
    port: u16,
    version: String,
    os: String,
    arch: String,
    kernel: String,
    max_concurrent_tasks: u8,
    busy_tasks: u8,
    status: String,
}

pub fn sha256_hex(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let digest = h.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

const TOKEN_CACHE_TTL_SECS: u64 = 60;
const NEG_CACHE_TTL_SECS: u64 = 15;

struct TokenCache {
    positive: HashMap<String, (String, Instant)>,
    negative: HashMap<String, Instant>,
}

fn token_cache() -> &'static Mutex<TokenCache> {
    static CACHE: OnceLock<Mutex<TokenCache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(TokenCache {
            positive: HashMap::new(),
            negative: HashMap::new(),
        })
    })
}

pub async fn resolve_token(client: &Client, token: &str) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    let hash = sha256_hex(token);

    {
        let cache = token_cache().lock().unwrap();
        if let Some((id, at)) = cache.positive.get(&hash) {
            if at.elapsed().as_secs() < TOKEN_CACHE_TTL_SECS {
                return Some(id.clone());
            }
        }
        if let Some(at) = cache.negative.get(&hash) {
            if at.elapsed().as_secs() < NEG_CACHE_TTL_SECS {
                return None;
            }
        }
    }

    let mut cursor = match client
        .query("SELECT agent_id FROM agent_tokens FINAL WHERE token_hash = ? LIMIT 1")
        .bind(&hash)
        .fetch_bytes("JSONEachRow")
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("resolve_token: query failed: {e}");
            return None;
        }
    };
    let bytes = match cursor.collect().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("resolve_token: collect failed: {e}");
            return None;
        }
    };

    let id = bytes
        .split(|&b| b == b'\n')
        .find(|l| !l.is_empty())
        .and_then(|l| {
            serde_json::from_slice::<serde_json::Value>(l)
                .ok()
                .and_then(|v| v["agent_id"].as_str().map(String::from))
        });

    {
        let mut cache = token_cache().lock().unwrap();
        match &id {
            Some(id) => {
                cache.positive.insert(hash, (id.clone(), Instant::now()));
            }
            None => {
                cache.negative.insert(hash, Instant::now());
            }
        }
    }

    id
}

pub async fn is_valid(client: &Client, token: &str) -> bool {
    let Some(id) = resolve_token(client, token).await else {
        return false;
    };
    let mut cursor = match client
        .query("SELECT status FROM agent_tokens FINAL WHERE agent_id = ? LIMIT 1")
        .bind(&id)
        .fetch_bytes("JSONEachRow")
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("is_valid: query failed: {e}");
            return false;
        }
    };
    let bytes = match cursor.collect().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("is_valid: collect failed: {e}");
            return false;
        }
    };
    bytes
        .split(|&c| c == b'\n')
        .find(|l| !l.is_empty())
        .and_then(|l| {
            serde_json::from_slice::<serde_json::Value>(l)
                .ok()
                .and_then(|v| v["status"].as_str().map(String::from))
        })
        .map(|s| s == "active")
        .unwrap_or(false)
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentView {
    pub agent_id: String,
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub kernel: String,
    pub max_concurrent_tasks: u8,
    pub busy_tasks: u8,
    pub status: String,
    pub last_seen_at: String,
    pub created_at: String,
}

pub async fn list(client: &Client) -> Result<Vec<AgentView>> {
    let bytes = client
        .query(
            "SELECT agent_id, name, ip, port, version, os, arch, kernel, \
             max_concurrent_tasks, busy_tasks, status, \
             toString(last_seen_at) AS last_seen_at, toString(created_at) AS created_at \
             FROM agent_tokens FINAL \
             ORDER BY agent_id, last_seen_at",
        )
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;

    let mut latest: HashMap<String, AgentView> = HashMap::new();
    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        let agent_id = v["agent_id"].as_str().unwrap_or_default().to_string();
        let last_seen = v["last_seen_at"].as_str().unwrap_or_default();
        if let Some(existing) = latest.get(&agent_id) {
            if existing.last_seen_at.as_str() >= last_seen {
                continue;
            }
        }
        latest.insert(
            agent_id.clone(),
            AgentView {
                agent_id,
                name: v["name"].as_str().unwrap_or_default().to_string(),
                ip: v["ip"].as_str().unwrap_or_default().to_string(),
                port: v["port"].as_u64().unwrap_or(0) as u16,
                version: v["version"].as_str().unwrap_or_default().to_string(),
                os: v["os"].as_str().unwrap_or_default().to_string(),
                arch: v["arch"].as_str().unwrap_or_default().to_string(),
                kernel: v["kernel"].as_str().unwrap_or_default().to_string(),
                max_concurrent_tasks: v["max_concurrent_tasks"].as_u64().unwrap_or(10) as u8,
                busy_tasks: v["busy_tasks"].as_u64().unwrap_or(0) as u8,
                status: v["status"].as_str().unwrap_or_default().to_string(),
                last_seen_at: last_seen.to_string(),
                created_at: v["created_at"].as_str().unwrap_or_default().to_string(),
            },
        );
    }

    let mut agents: Vec<AgentView> = latest.into_values().collect();
    agents.sort_by(|a, b| b.last_seen_at.cmp(&a.last_seen_at));
    Ok(agents)
}

pub async fn upsert(
    client: &Client,
    agent_id: &str,
    token: &str,
    name: &str,
    ip: &str,
    port: u16,
    version: &str,
    os: &str,
    arch: &str,
    kernel: &str,
    max_concurrent_tasks: u8,
) -> Result<()> {
    let row = AgentRow {
        agent_id: agent_id.to_string(),
        token_hash: sha256_hex(token),
        name: name.to_string(),
        ip: ip.to_string(),
        port,
        version: version.to_string(),
        os: os.to_string(),
        arch: arch.to_string(),
        kernel: kernel.to_string(),
        max_concurrent_tasks,
        busy_tasks: 0,
        status: "active".to_string(),
    };
    let mut inserter = client.insert::<AgentRow>("agent_tokens").await?;
    inserter.write(&row).await?;
    inserter.end().await?;

    if let Ok(mut cache) = token_cache().lock() {
        cache.positive.insert(sha256_hex(token), (agent_id.to_string(), Instant::now()));
        cache.negative.remove(&sha256_hex(token));
    }

    Ok(())
}

pub async fn heartbeat(client: &Client, agent_id: &str, busy: u8) -> Result<()> {
    let meta = current_meta(client, agent_id).await;
    let row = AgentRow {
        agent_id: agent_id.to_string(),
        token_hash: meta.token_hash,
        name: meta.name,
        ip: meta.ip,
        port: meta.port,
        version: meta.version,
        os: meta.os,
        arch: meta.arch,
        kernel: meta.kernel,
        max_concurrent_tasks: meta.max_concurrent_tasks,
        busy_tasks: busy,
        status: "active".to_string(),
    };
    let mut inserter = client.insert::<AgentRow>("agent_tokens").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

struct Meta {
    token_hash: String,
    name: String,
    ip: String,
    port: u16,
    version: String,
    os: String,
    arch: String,
    kernel: String,
    max_concurrent_tasks: u8,
}

fn default_meta() -> Meta {
    Meta {
        token_hash: String::new(),
        name: String::new(),
        ip: String::new(),
        port: 0,
        version: String::new(),
        os: String::new(),
        arch: String::new(),
        kernel: String::new(),
        max_concurrent_tasks: 10,
    }
}

async fn current_meta(client: &Client, agent_id: &str) -> Meta {
    let mut cursor = match client
        .query("SELECT token_hash, name, ip, port, version, os, arch, kernel, max_concurrent_tasks \
                FROM agent_tokens FINAL WHERE agent_id = ? ORDER BY last_seen_at DESC LIMIT 1")
        .bind(agent_id)
        .fetch_bytes("JSONEachRow")
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("current_meta: query failed: {e}");
            return default_meta();
        }
    };
    let bytes = match cursor.collect().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("current_meta: collect failed: {e}");
            return default_meta();
        }
    };
    let Some(line) = bytes.split(|&c| c == b'\n').find(|l| !l.is_empty()) else {
        return default_meta();
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
        return default_meta();
    };
    Meta {
        token_hash: v["token_hash"].as_str().unwrap_or_default().to_string(),
        name: v["name"].as_str().unwrap_or_default().to_string(),
        ip: v["ip"].as_str().unwrap_or_default().to_string(),
        port: v["port"].as_u64().unwrap_or(0) as u16,
        version: v["version"].as_str().unwrap_or_default().to_string(),
        os: v["os"].as_str().unwrap_or_default().to_string(),
        arch: v["arch"].as_str().unwrap_or_default().to_string(),
        kernel: v["kernel"].as_str().unwrap_or_default().to_string(),
        max_concurrent_tasks: v["max_concurrent_tasks"].as_u64().unwrap_or(10) as u8,
    }
}

pub async fn set_status(client: &Client, agent_id: &str, status: &str) -> Result<()> {
    let meta = current_meta(client, agent_id).await;
    let row = AgentRow {
        agent_id: agent_id.to_string(),
        token_hash: meta.token_hash,
        name: meta.name,
        ip: meta.ip,
        port: meta.port,
        version: meta.version,
        os: meta.os,
        arch: meta.arch,
        kernel: meta.kernel,
        max_concurrent_tasks: meta.max_concurrent_tasks,
        busy_tasks: 0,
        status: status.to_string(),
    };
    let mut inserter = client.insert::<AgentRow>("agent_tokens").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

fn parse_ch_datetime(s: &str) -> Option<i64> {
    NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc().timestamp())
}

pub async fn stale_active(client: &Client, stale_secs: u64) -> Result<Vec<String>> {
    let agents = list(client).await?;
    let now = Utc::now().timestamp();
    let mut out = Vec::new();
    for a in agents {
        if a.status != "active" {
            continue;
        }
        if let Some(ts) = parse_ch_datetime(&a.last_seen_at) {
            if now - ts > stale_secs as i64 {
                out.push(a.agent_id);
            }
        }
    }
    Ok(out)
}
