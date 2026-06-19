use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;

#[derive(Debug, Row, Serialize)]
pub struct SslRow {
    pub host: String,
    pub port: u16,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub san: Vec<String>,
    pub ssl_version: String,
    pub cipher: String,
    pub chain_length: u8,
}

pub async fn insert(client: &Client, row: SslRow) -> Result<()> {
    let mut inserter = client.insert::<SslRow>("scan_results_ssl").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub fn from_json(item: &serde_json::Value) -> Option<SslRow> {
    Some(SslRow {
        host: item.get("host")?.as_str()?.to_string(),
        port: item.get("port")?.as_u64()? as u16,
        subject: item
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        issuer: item
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        not_before: item
            .get("not_before")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        not_after: item
            .get("not_after")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        serial: item
            .get("serial")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        san: item
            .get("san")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        ssl_version: item
            .get("ssl_version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        cipher: item
            .get("cipher")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        chain_length: item
            .get("chain_length")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8,
    })
}
