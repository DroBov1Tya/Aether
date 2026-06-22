use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;

#[derive(Debug, Row, Serialize)]
pub struct NmapRow {
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub state_reason: Option<String>,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub country: Option<String>,
    pub os_type: Option<String>,
    pub detection_method: Option<String>,
    pub confidence: Option<u8>,
    pub banner: Option<String>,
    pub cpe: Option<String>,
    pub scripts: Option<String>,
    pub os_name: Option<String>,
    pub os_accuracy: Option<u8>,
    pub ttl: Option<u8>,
    pub scan_uid: String,
}

pub async fn insert(client: &Client, row: NmapRow) -> Result<()> {
    let mut inserter = client.insert::<NmapRow>("scan_results_nmap").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub fn from_json(target: &str, scan_uid: &str, country: Option<String>, body: &serde_json::Value) -> Option<NmapRow> {
    Some(NmapRow {
        target: target.to_string(),
        scan_uid: scan_uid.to_string(),
        port: body.get("port")?.as_str()?.parse().ok()?,
        protocol: body.get("protocol")?.as_str()?.to_string(),
        state: body.get("state")?.as_str()?.to_string(),
        state_reason: body
            .get("state_reason")
            .and_then(|v| v.as_str())
            .map(String::from),
        service: body
            .get("service")
            .and_then(|v| v.as_str())
            .map(String::from),
        product: body
            .get("product")
            .and_then(|v| v.as_str())
            .map(String::from),
        version: body
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from),
        extra_info: body
            .get("extra_info")
            .and_then(|v| v.as_str())
            .map(String::from),
        country,
        os_type: body
            .get("os_type")
            .and_then(|v| v.as_str())
            .map(String::from),
        detection_method: body
            .get("detection_method")
            .and_then(|v| v.as_str())
            .map(String::from),
        confidence: body
            .get("confidence")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok()),
        banner: body
            .get("banner")
            .and_then(|v| v.as_str())
            .map(String::from),
        cpe: body.get("cpe").and_then(|v| v.as_str()).map(String::from),
        scripts: body
            .get("scripts")
            .and_then(|v| v.as_str())
            .map(String::from),
        os_name: body
            .get("os_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        os_accuracy: body
            .get("os_accuracy")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok()),
        ttl: body
            .get("ttl")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok()),
    })
}
