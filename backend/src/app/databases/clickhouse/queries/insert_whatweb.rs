use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;

#[derive(Debug, Row, Serialize)]
pub struct WhatwebRow {
    pub target: String,
    pub port: u16,
    pub url: String,
    pub http_status: Option<u16>,
    pub title: Option<String>,
    pub technologies: Vec<String>,
}

pub async fn insert(client: &Client, row: WhatwebRow) -> Result<()> {
    let mut inserter = client.insert::<WhatwebRow>("scan_results_whatweb").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub fn from_json(target: &str, item: &serde_json::Value) -> Option<WhatwebRow> {
    Some(WhatwebRow {
        target: target.to_string(),
        port: item.get("port")?.as_str()?.parse().ok()?,
        url: item.get("url")?.as_str()?.to_string(),
        http_status: item.get("http_status").and_then(|v| {
            if v.is_null() { None } else { v.as_str().and_then(|s| s.parse().ok()) }
        }),
        title: item.get("title").and_then(|v| {
            if v.is_null() { None } else { v.as_str().map(String::from) }
        }),
        technologies: item
            .get("technologies")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
    })
}
