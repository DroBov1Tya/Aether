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
    pub jarm: String,
    pub chain_length: u8,
    pub country: Option<String>,
    pub project: String,
    pub scan_uid: String,
}

pub async fn insert(client: &Client, row: SslRow) -> Result<()> {
    let mut inserter = client.insert::<SslRow>("scan_results_ssl").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub fn from_json(
    scan_uid: &str,
    country: Option<String>,
    item: &serde_json::Value,
) -> Option<SslRow> {
    from_json_with_project(scan_uid, "global", country, item)
}

pub fn from_json_with_project(
    scan_uid: &str,
    project: &str,
    country: Option<String>,
    item: &serde_json::Value,
) -> Option<SslRow> {
    Some(SslRow {
        host: item.get("host")?.as_str()?.to_string(),
        scan_uid: scan_uid.to_string(),
        project: project.to_string(),
        country,
        port: item.get("port")?.as_u64()? as u16,
        subject: str_field(item, "subject"),
        issuer: str_field(item, "issuer"),
        not_before: str_field(item, "not_before"),
        not_after: str_field(item, "not_after"),
        serial: str_field(item, "serial"),
        san: item
            .get("san")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        ssl_version: str_field(item, "ssl_version"),
        cipher: str_field(item, "cipher"),
        jarm: str_field(item, "jarm"),
        chain_length: item
            .get("chain_length")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8,
    })
}

fn str_field(item: &serde_json::Value, key: &str) -> String {
    item.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}
