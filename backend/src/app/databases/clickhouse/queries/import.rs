use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;

use super::insert_geo;

#[derive(Debug, Row, Serialize)]
struct ImpRustscan {
    target: String,
    ports: Vec<u16>,
    country: Option<String>,
    project: String,
    scan_uid: String,
}

#[derive(Debug, Row, Serialize)]
struct ImpNmap {
    target: String,
    port: u16,
    protocol: String,
    state: String,
    state_reason: Option<String>,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
    extra_info: Option<String>,
    country: Option<String>,
    os_type: Option<String>,
    detection_method: Option<String>,
    confidence: Option<u8>,
    banner: Option<String>,
    cpe: Option<String>,
    scripts: Option<String>,
    os_name: Option<String>,
    os_accuracy: Option<u8>,
    ttl: Option<u8>,
    project: String,
    scan_uid: String,
}

#[derive(Debug, Row, Serialize)]
struct ImpWhatweb {
    target: String,
    port: u16,
    url: String,
    http_status: Option<u16>,
    title: Option<String>,
    technologies: Vec<String>,
    webserver: Option<String>,
    cdn: Option<String>,
    favicon_hash: Option<String>,
    content_length: Option<u32>,
    country: Option<String>,
    project: String,
    scan_uid: String,
}

#[derive(Debug, Row, Serialize)]
struct ImpSsl {
    host: String,
    port: u16,
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    serial: String,
    san: Vec<String>,
    ssl_version: String,
    cipher: String,
    jarm: String,
    chain_length: u8,
    country: Option<String>,
    project: String,
    scan_uid: String,
}

#[derive(Debug, Row, Serialize)]
struct ImpDns {
    target: String,
    a: Vec<String>,
    aaaa: Vec<String>,
    cname: Vec<String>,
    mx: Vec<String>,
    ns: Vec<String>,
    txt: Vec<String>,
    ptr: Vec<String>,
    country: Option<String>,
    project: String,
    scan_uid: String,
}

#[derive(Debug, Default, Serialize)]
pub struct ImportCounts {
    pub hosts: usize,
    pub ports: usize,
    pub http: usize,
    pub tls: usize,
    pub dns: usize,
    pub geo: usize,
}

fn s(v: &serde_json::Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(String::from).filter(|s| !s.is_empty())
}
fn arr(v: &serde_json::Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

pub async fn import_payload(
    client: &Client,
    project: &str,
    scan_uid: &str,
    hosts: &[serde_json::Value],
) -> Result<ImportCounts> {
    let mut counts = ImportCounts::default();

    for host in hosts {
        let target = match host.get("target").and_then(|v| v.as_str()) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => continue,
        };
        counts.hosts += 1;
        let country = s(host, "country");

        if let Some(geo) = host.get("geo") {
            if geo.is_object() {
                let row = insert_geo::from_json(&target, geo);
                if !row.country.is_empty() || !row.asn.is_empty() || !row.org.is_empty() {
                    if insert_geo::insert(client, row).await.is_ok() {
                        counts.geo += 1;
                    }
                }
            }
        }

        let ports_val = host.get("ports").and_then(|v| v.as_array());
        if let Some(ports) = ports_val {
            let mut port_nums: Vec<u16> = Vec::new();
            for p in ports {
                let port = p
                    .get("port")
                    .and_then(|v| v.as_u64())
                    .or_else(|| p.as_u64())
                    .map(|n| n as u16);
                let Some(port) = port else { continue };
                port_nums.push(port);
                counts.ports += 1;

                let mut ins = client.insert::<ImpNmap>("scan_results_nmap").await?;
                ins.write(&ImpNmap {
                    target: target.clone(),
                    port,
                    protocol: p.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp").to_string(),
                    state: "open".to_string(),
                    state_reason: None,
                    service: s(p, "service"),
                    product: s(p, "product"),
                    version: s(p, "version"),
                    extra_info: None,
                    country: country.clone(),
                    os_type: None,
                    detection_method: None,
                    confidence: None,
                    banner: None,
                    cpe: None,
                    scripts: None,
                    os_name: None,
                    os_accuracy: None,
                    ttl: None,
                    project: project.to_string(),
                    scan_uid: scan_uid.to_string(),
                })
                .await?;
                ins.end().await?;
            }
            if !port_nums.is_empty() {
                let mut ins = client.insert::<ImpRustscan>("scan_results_rustscan").await?;
                ins.write(&ImpRustscan {
                    target: target.clone(),
                    ports: port_nums,
                    country: country.clone(),
                    project: project.to_string(),
                    scan_uid: scan_uid.to_string(),
                })
                .await?;
                ins.end().await?;
            }
        }

        let http = host.get("http");
        let technologies = arr(host, "technologies");
        if http.is_some() || !technologies.is_empty() {
            let h = http.cloned().unwrap_or(serde_json::json!({}));
            let port = h.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let mut ins = client.insert::<ImpWhatweb>("scan_results_whatweb").await?;
            ins.write(&ImpWhatweb {
                target: target.clone(),
                port,
                url: h.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                http_status: h.get("status").and_then(|v| v.as_u64()).map(|n| n as u16),
                title: s(&h, "title"),
                technologies,
                webserver: s(&h, "webserver"),
                cdn: s(&h, "cdn"),
                favicon_hash: s(&h, "favicon_hash"),
                content_length: h.get("content_length").and_then(|v| v.as_u64()).map(|n| n as u32),
                country: country.clone(),
                project: project.to_string(),
                scan_uid: scan_uid.to_string(),
            })
            .await?;
            ins.end().await?;
            counts.http += 1;
        }

        if let Some(tls) = host.get("tls") {
            if tls.is_object() {
                let mut ins = client.insert::<ImpSsl>("scan_results_ssl").await?;
                ins.write(&ImpSsl {
                    host: target.clone(),
                    port: tls.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16,
                    subject: tls.get("subject").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    issuer: tls.get("issuer").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    not_before: tls.get("not_before").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    not_after: tls.get("not_after").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    serial: tls.get("serial").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    san: arr(tls, "san"),
                    ssl_version: tls.get("ssl_version").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    cipher: tls.get("cipher").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    jarm: tls.get("jarm").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    chain_length: 1,
                    country: country.clone(),
                    project: project.to_string(),
                    scan_uid: scan_uid.to_string(),
                })
                .await?;
                ins.end().await?;
                counts.tls += 1;
            }
        }

        if let Some(dns) = host.get("dns") {
            if dns.is_object() {
                let mut ins = client.insert::<ImpDns>("scan_results_dns").await?;
                ins.write(&ImpDns {
                    target: target.clone(),
                    a: arr(dns, "a"),
                    aaaa: arr(dns, "aaaa"),
                    cname: arr(dns, "cname"),
                    mx: arr(dns, "mx"),
                    ns: arr(dns, "ns"),
                    txt: arr(dns, "txt"),
                    ptr: arr(dns, "ptr"),
                    country: country.clone(),
                    project: project.to_string(),
                    scan_uid: scan_uid.to_string(),
                })
                .await?;
                ins.end().await?;
                counts.dns += 1;
            }
        }
    }

    Ok(counts)
}
