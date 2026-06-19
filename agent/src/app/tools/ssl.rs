use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct SslCertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SslResult {
    pub host: String,
    pub port: u16,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub san: Vec<String>,
    pub ssl_version: String,
    pub cipher: String,
    pub chain_length: usize,
    pub chain: Vec<SslCertInfo>,
}

pub async fn run_ssl(
    external_server_path: &str,
    target: &str,
    http_ports: &[String],
    api_key: &str,
) -> Result<()> {
    for port in http_ports {
        let p: u16 = match port.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let result = match scan_ssl(target, p).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("ssl  {}:{}  err={}", target, port, e);
                continue;
            }
        };

        if let Err(e) = send_to_server(external_server_path, target, &result, api_key).await {
            tracing::warn!("ssl  {}:{}  send error: {}", target, port, e);
        }

        tracing::info!(
            "ssl  {}:{}  subject={}  issuer={}  chain={}",
            target,
            port,
            result.subject,
            result.issuer,
            result.chain_length,
        );
    }

    Ok(())
}

async fn scan_ssl(host: &str, port: u16) -> Result<SslResult> {
    let addr = format!("{}:{}", host, port);
    let output = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &addr,
            "-servername",
            host,
            "-showcerts",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let full = format!("{}\n{}", stdout, stderr);

    let mut subject = String::new();
    let mut issuer = String::new();
    let mut not_before = String::new();
    let mut not_after = String::new();
    let mut serial = String::new();
    let mut san = Vec::new();
    let mut ssl_version = String::new();
    let mut cipher = String::new();

    for line in full.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("subject=") {
            subject = val.to_string();
        } else if let Some(val) = line.strip_prefix("issuer=") {
            issuer = val.to_string();
        } else if let Some(val) = line.strip_prefix("notBefore=") {
            not_before = val.to_string();
        } else if let Some(val) = line.strip_prefix("notAfter=") {
            not_after = val.to_string();
        } else if let Some(val) = line.strip_prefix("Serial Number:") {
            serial = val.trim().to_string();
        } else if line.starts_with("Protocol") && line.contains(':') {
            if let Some(val) = line.split(':').nth(1) {
                ssl_version = val.trim().to_string();
            }
        } else if line.starts_with("Cipher") && line.contains(':') {
            if let Some(val) = line.split(':').nth(1) {
                cipher = val.trim().to_string();
            }
        }
    }

    let mut in_san = false;
    for line in full.lines() {
        let line = line.trim();
        if line.contains("X509v3 Subject Alternative Name") {
            in_san = true;
            continue;
        }
        if in_san {
            if line.starts_with("X509v3") || line.starts_with("Signature") || line.is_empty() {
                in_san = false;
                continue;
            }
            for part in line.split(',') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("DNS:") {
                    san.push(val.to_string());
                }
            }
        }
    }

    let chain_certs = parse_chain(&full);

    Ok(SslResult {
        host: host.to_string(),
        port,
        subject,
        issuer,
        not_before,
        not_after,
        serial,
        san,
        ssl_version,
        cipher,
        chain_length: chain_certs.len(),
        chain: chain_certs,
    })
}

fn parse_chain(full: &str) -> Vec<SslCertInfo> {
    let mut certs = Vec::new();
    let mut current_subject = String::new();
    let mut current_issuer = String::new();
    let mut current_not_before = String::new();
    let mut current_not_after = String::new();
    let mut current_serial = String::new();
    let mut in_cert = false;

    for line in full.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current_subject.clear();
            current_issuer.clear();
            current_not_before.clear();
            current_not_after.clear();
            current_serial.clear();
            continue;
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            in_cert = false;
            certs.push(SslCertInfo {
                subject: current_subject.clone(),
                issuer: current_issuer.clone(),
                not_before: current_not_before.clone(),
                not_after: current_not_after.clone(),
                serial: current_serial.clone(),
            });
            continue;
        }
        if !in_cert {
            continue;
        }
        if let Some(val) = line.strip_prefix("subject=") {
            current_subject = val.to_string();
        } else if let Some(val) = line.strip_prefix("issuer=") {
            current_issuer = val.to_string();
        } else if let Some(val) = line.strip_prefix("notBefore=") {
            current_not_before = val.to_string();
        } else if let Some(val) = line.strip_prefix("notAfter=") {
            current_not_after = val.to_string();
        } else if let Some(val) = line.strip_prefix("Serial Number:") {
            current_serial = val.trim().to_string();
        }
    }

    certs
}

async fn send_to_server(
    external_server_path: &str,
    target: &str,
    result: &SslResult,
    api_key: &str,
) -> Result<()> {
    let url = format!("{}/api/checkout/ssl", external_server_path);
    let body = serde_json::to_string(result)?;

    let req = super::common::ExternalReq {
        status: "complete".to_string(),
        target: target.to_string(),
        body,
        version: crate::config::VERSION,
    };

    super::common::post_json(&url, &req, api_key).await?;
    Ok(())
}
