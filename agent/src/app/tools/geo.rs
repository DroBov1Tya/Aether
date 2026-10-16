use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::common::ExternalReq;
use super::sink::{Sink, Stage};

#[derive(Debug, Serialize, Deserialize)]
pub struct GeoResp {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub country: String,
    #[serde(default, rename = "countryCode")]
    pub country_code: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub lat: f64,
    #[serde(default)]
    pub lon: f64,
    #[serde(default, rename = "as")]
    pub asn: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub isp: String,
}

pub async fn enrich_hosts(
    sink: &Sink,
    hosts: &[String],
    scan_uid: &str,
    task_uid: Option<&str>,
) -> Result<usize> {
    let mut done = 0;
    for host in hosts {
        if host.trim().is_empty() {
            continue;
        }
        if let Some(geo) = lookup(host).await {
            if hosts.len() > 1 {
                tokio::time::sleep(Duration::from_millis(1400)).await;
            }
            if geo.status != "success" {
                continue;
            }
            let body = serde_json::json!({
                "country": geo.country,
                "country_code": geo.country_code,
                "city": geo.city,
                "lat": geo.lat,
                "lon": geo.lon,
                "asn": geo.asn,
                "org": geo.org,
                "isp": geo.isp,
            });
            let req = ExternalReq {
                status: "complete".to_string(),
                target: host.to_string(),
                body: body.to_string(),
                version: crate::config::VERSION,
                scan_uid: scan_uid.to_string(),
                task_uid: task_uid.map(String::from),
                country: Some(geo.country.clone()),
                port: None,
            };
            if sink.emit(Stage::Geo, req).await.is_ok() {
                done += 1;
            }
        }
    }
    tracing::info!(hosts = hosts.len(), enriched = done, "geo batch complete");
    Ok(done)
}

async fn lookup(ip: &str) -> Option<GeoResp> {
    let url = format!(
        "http://ip-api.com/json/{}?fields=status,country,countryCode,city,lat,lon,as,org,isp",
        ip
    );
    let client = Client::builder().timeout(Duration::from_secs(6)).build().ok()?;
    let resp = client.get(&url).send().await.ok()?;
    resp.json::<GeoResp>().await.ok()
}
