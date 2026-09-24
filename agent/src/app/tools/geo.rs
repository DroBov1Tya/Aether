use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

use super::common::ExternalReq;

#[derive(Debug, Deserialize)]
struct GeoResp {
    #[serde(default)]
    status: String,
    #[serde(default)]
    country: String,
    #[serde(default, rename = "countryCode")]
    country_code: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    lat: f64,
    #[serde(default)]
    lon: f64,
    #[serde(default, rename = "as")]
    asn: String,
    #[serde(default)]
    org: String,
    #[serde(default)]
    isp: String,
}

pub async fn enrich_hosts(
    external_server_path: &str,
    hosts: &[String],
    scan_uid: &str,
    task_uid: Option<&str>,
    api_key: &str,
) -> Result<usize> {
    let mut done = 0;
    for host in hosts {
        // ip-api.com resolves hostnames too; the target key matches other tables.
        if host.trim().is_empty() {
            continue;
        }
        if let Some(geo) = lookup(host).await {
            // ip-api.com free tier: 45 req/min. Space calls out (~1.4s).
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
            let url = format!("{}/api/checkout/geo", external_server_path);
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
            if let Ok(resp) = super::common::post_json(&url, &req, api_key).await {
                if resp.status().is_success() {
                    done += 1;
                }
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
