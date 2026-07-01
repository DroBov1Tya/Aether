use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;

#[derive(Debug, Row, Serialize)]
pub struct FuzzingRow {
    pub target: String,
    pub port: u16,
    pub path: String,
    pub url: String,
    pub http_status: u16,
    pub scan_uid: String,
}

pub async fn insert(client: &Client, row: FuzzingRow) -> Result<()> {
    let mut inserter = client.insert::<FuzzingRow>("scan_results_fuzzing").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub fn from_json(target: &str, scan_uid: &str, body: &serde_json::Value) -> Option<FuzzingRow> {
    Some(FuzzingRow {
        target: target.to_string(),
        scan_uid: scan_uid.to_string(),
        port: body.get("port")?.as_str()?.parse().ok()?,
        path: body.get("path")?.as_str()?.to_string(),
        url: body.get("url")?.as_str()?.to_string(),
        http_status: body.get("http_status")?.as_u64()? as u16,
    })
}
