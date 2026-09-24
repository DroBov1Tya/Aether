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
    pub webserver: Option<String>,
    pub cdn: Option<String>,
    pub favicon_hash: Option<String>,
    pub content_length: Option<u32>,
    pub headers: String,
    pub country: Option<String>,
    pub project: String,
    pub scan_uid: String,
}

pub async fn insert(client: &Client, row: WhatwebRow) -> Result<()> {
    let mut inserter = client.insert::<WhatwebRow>("scan_results_whatweb").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub fn from_json(
    target: &str,
    scan_uid: &str,
    country: Option<String>,
    item: &serde_json::Value,
) -> Option<WhatwebRow> {
    Some(WhatwebRow {
        target: target.to_string(),
        scan_uid: scan_uid.to_string(),
        project: "global".to_string(),
        port: item.get("port")?.as_str()?.parse().ok()?,
        url: item.get("url")?.as_str()?.to_string(),
        http_status: item.get("http_status").and_then(str_num),
        title: item.get("title").and_then(opt_str),
        technologies: tech_array(item),
        webserver: None,
        cdn: None,
        favicon_hash: None,
        content_length: None,
        headers: String::new(),
        country,
    })
}

pub fn from_json_httpx(
    target: &str,
    scan_uid: &str,
    project: &str,
    country: Option<String>,
    item: &serde_json::Value,
) -> Option<WhatwebRow> {
    Some(WhatwebRow {
        target: target.to_string(),
        scan_uid: scan_uid.to_string(),
        project: project.to_string(),
        port: item.get("port")?.as_str()?.parse().ok()?,
        url: item.get("url")?.as_str()?.to_string(),
        http_status: item.get("http_status").and_then(str_num),
        title: item.get("title").and_then(opt_str),
        technologies: tech_array(item),
        webserver: item.get("webserver").and_then(opt_str),
        cdn: item.get("cdn").and_then(opt_str),
        favicon_hash: item.get("favicon_hash").and_then(opt_str),
        content_length: item
            .get("content_length")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        headers: item
            .get("headers")
            .filter(|v| v.is_object() && v.as_object().map(|o| !o.is_empty()).unwrap_or(false))
            .map(|v| v.to_string())
            .unwrap_or_default(),
        country,
    })
}

fn tech_array(item: &serde_json::Value) -> Vec<String> {
    item.get("technologies")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn opt_str(v: &serde_json::Value) -> Option<String> {
    if v.is_null() {
        None
    } else {
        v.as_str().map(String::from).filter(|s| !s.is_empty())
    }
}

fn str_num(v: &serde_json::Value) -> Option<u16> {
    if v.is_null() {
        None
    } else {
        v.as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| v.as_u64().map(|n| n as u16))
    }
}
