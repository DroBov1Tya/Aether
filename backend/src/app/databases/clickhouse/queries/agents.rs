use anyhow::Result;
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Row, Serialize)]
pub struct AgentRow {
    pub id: String,
    pub ip: String,
    pub name: String,
    pub version: String,
    pub port: u16,
    pub os: String,
    pub arch: String,
    pub kernel: String,
    pub max_concurrent_tasks: u8,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub ip: String,
    pub port: i32,
    pub max_concurrent_tasks: i32,
}

pub async fn insert(client: &Client, id: Uuid, ip: &str, hostname: &str, version: &str, port: i32, os: &str, arch: &str, kernel: &str) -> Result<()> {
    let row = AgentRow {
        id: id.to_string(),
        ip: ip.to_string(),
        name: hostname.to_string(),
        version: version.to_string(),
        port: port as u16,
        os: os.to_string(),
        arch: arch.to_string(),
        kernel: kernel.to_string(),
        max_concurrent_tasks: 10,
        status: "active".to_string(),
    };
    let mut inserter = client.insert::<AgentRow>("agents").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub async fn list_active(client: &Client) -> Result<Vec<AgentInfo>> {
    let bytes = client
        .query("SELECT id, ip, port, max_concurrent_tasks FROM agents WHERE status = 'active'")
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;

    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    use std::collections::HashMap;
    let mut seen: HashMap<String, AgentInfo> = HashMap::new();
    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_slice::<AgentInfo>(line) {
            seen.entry(v.id.clone()).or_insert(v);
        }
    }
    Ok(seen.into_values().collect())
}

pub async fn find_by_ip_port(client: &Client, ip: &str, port: i32) -> Result<Option<String>> {
    let bytes = client
        .query("SELECT id FROM agents WHERE ip = ? AND port = ? LIMIT 1")
        .bind(ip)
        .bind(port)
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;

    if bytes.is_empty() {
        return Ok(None);
    }

    #[derive(Deserialize)]
    struct IdRow {
        id: String,
    }

    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(row) = serde_json::from_slice::<IdRow>(line) {
            return Ok(Some(row.id));
        }
    }
    Ok(None)
}
