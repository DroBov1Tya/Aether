use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;

#[derive(Debug, Row, Serialize)]
pub struct NucleiRow {
    pub target: String,
    pub port: u16,
    pub url: String,
    pub template_id: String,
    pub name: String,
    pub severity: String,
    pub protocol_type: String,
    pub matched_at: String,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub reference: Vec<String>,
    pub extracted: Vec<String>,
    pub country: Option<String>,
    pub project: String,
    pub scan_uid: String,
}

pub async fn insert(client: &Client, row: NucleiRow) -> Result<()> {
    let mut inserter = client.insert::<NucleiRow>("scan_results_nuclei").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub fn from_json(
    target: &str,
    scan_uid: &str,
    project: &str,
    country: Option<String>,
    item: &serde_json::Value,
) -> Option<NucleiRow> {
    let template_id = item.get("template_id")?.as_str()?.to_string();
    if template_id.is_empty() {
        return None;
    }
    Some(NucleiRow {
        target: target.to_string(),
        scan_uid: scan_uid.to_string(),
        project: project.to_string(),
        port: item
            .get("port")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        url: item.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        template_id,
        name: item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        severity: item
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        protocol_type: item
            .get("protocol_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        matched_at: item
            .get("matched_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        tags: str_array(item, "tags"),
        description: item
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from)
            .filter(|s| !s.is_empty()),
        reference: str_array(item, "reference"),
        extracted: str_array(item, "extracted"),
        country,
    })
}

fn str_array(item: &serde_json::Value, key: &str) -> Vec<String> {
    item.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
