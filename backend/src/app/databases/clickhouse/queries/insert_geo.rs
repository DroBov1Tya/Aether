use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Row, Serialize)]
pub struct GeoRow {
    pub target: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub lat: f64,
    pub lon: f64,
    pub asn: String,
    pub org: String,
    pub isp: String,
}

pub async fn insert(client: &Client, row: GeoRow) -> Result<()> {
    let mut inserter = client.insert::<GeoRow>("host_geo").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub fn from_json(target: &str, item: &Value) -> GeoRow {
    GeoRow {
        target: target.to_string(),
        country: str_field(item, "country"),
        country_code: str_field(item, "country_code"),
        city: str_field(item, "city"),
        lat: item.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0),
        lon: item.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0),
        asn: str_field(item, "asn"),
        org: str_field(item, "org"),
        isp: str_field(item, "isp"),
    }
}

fn str_field(item: &Value, key: &str) -> String {
    item.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}
