use anyhow::Result;
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};

#[derive(Debug, Row, Serialize, Deserialize)]
pub struct WhoisRow {
    pub target: String,
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub name_servers: Vec<String>,
    pub organization: Option<String>,
    pub country: Option<String>,
    pub emails: Vec<String>,
    pub raw: String,
    pub scan_uid: String,
}

impl WhoisRow {
    pub fn from_json(target: &str, scan_uid: &str, body: &serde_json::Value) -> Option<Self> {
        Some(Self {
            target: target.to_string(),
            scan_uid: scan_uid.to_string(),
            registrar: body
                .get("registrar")
                .and_then(|v| v.as_str())
                .map(String::from),
            creation_date: body
                .get("creation_date")
                .and_then(|v| v.as_str())
                .map(String::from),
            expiration_date: body
                .get("expiration_date")
                .and_then(|v| v.as_str())
                .map(String::from),
            name_servers: body
                .get("name_servers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            organization: body
                .get("organization")
                .and_then(|v| v.as_str())
                .map(String::from),
            country: body
                .get("country")
                .and_then(|v| v.as_str())
                .map(String::from),
            emails: body
                .get("emails")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            raw: body
                .get("raw")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_default(),
        })
    }
}

pub async fn insert(client: &Client, row: WhoisRow) -> Result<()> {
    let mut inserter = client.insert::<WhoisRow>("scan_results_whois").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}
