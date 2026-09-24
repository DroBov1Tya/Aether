use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::common::ExternalReq;

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsxRow {
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
    pub jarm: String,
    pub chain_length: u8,
}

#[derive(Debug, Deserialize)]
struct TlsxLine {
    host: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    port: Option<String>,
    #[serde(default)]
    subject_dn: Option<String>,
    #[serde(default)]
    subject_cn: Option<String>,
    #[serde(default)]
    issuer_dn: Option<String>,
    #[serde(rename = "not_before", default)]
    not_before: Option<String>,
    #[serde(rename = "not_after", default)]
    not_after: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    subject_an: Vec<String>,
    #[serde(default)]
    tls_version: Option<String>,
    #[serde(default)]
    cipher: Option<String>,
    #[serde(default)]
    jarm_hash: Option<String>,
}

pub async fn run_tlsx(
    external_server_path: &str,
    targets: &[String],
    scan_uid: &str,
    task_uid: Option<&str>,
    pool: &[String],
    api_key: &str,
) -> Result<usize> {
    if targets.is_empty() {
        return Ok(0);
    }

    // Ladder: direct first, then each pool proxy in order until we get certs.
    let mut rows: Vec<TlsxRow> = Vec::new();
    for attempt in super::proxy::attempts(pool) {
        match run_once(targets, attempt.as_deref()).await {
            Ok(r) if !r.is_empty() => {
                rows = r;
                break;
            }
            Ok(_) => {
                tracing::debug!(proxy = ?attempt, "tlsx: no certs, trying next proxy");
            }
            Err(e) => {
                tracing::debug!(proxy = ?attempt, err = %e, "tlsx: attempt failed, trying next proxy");
            }
        }
    }

    let count = rows.len();
    let url = format!("{}/api/checkout/ssl", external_server_path);
    for row in &rows {
        let country = super::common::lookup_country(&row.host).await;
        let req = ExternalReq {
            status: "complete".to_string(),
            target: row.host.clone(),
            body: serde_json::to_string(row).unwrap_or_else(|_| "{}".to_string()),
            version: crate::config::VERSION,
            scan_uid: scan_uid.to_string(),
            task_uid: task_uid.map(String::from),
            country,
            port: None,
        };
        if let Ok(resp) = super::common::post_json(&url, &req, api_key).await {
            if !resp.status().is_success() {
                tracing::warn!(host = %row.host, status = %resp.status(), "tlsx checkout non-200");
            }
        }
    }

    tracing::info!(targets = targets.len(), certs = count, "tlsx batch complete");
    Ok(count)
}

/// One tlsx invocation over the host:port batch, with an optional proxy.
async fn run_once(targets: &[String], proxy: Option<&str>) -> Result<Vec<TlsxRow>> {
    let cfg = crate::config::cfg();

    let mut args: Vec<String> = vec![
        "-json".into(),
        "-silent".into(),
        "-nc".into(),
        "-jarm".into(),
        "-c".into(),
        cfg.tlsx_concurrency.to_string(),
        "-timeout".into(),
        cfg.tlsx_timeout.to_string(),
    ];

    if let Some(proxy) = proxy {
        args.push("-proxy".into());
        args.push(proxy.to_string());
    }

    let mut child = Command::new("tlsx")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        let payload = targets.join("\n");
        stdin.write_all(payload.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.shutdown().await.ok();
    }

    let output = child.wait_with_output().await?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            tracing::warn!(stderr = %stderr.trim(), "tlsx produced no output");
        }
    }

    let mut rows: Vec<TlsxRow> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed: TlsxLine = match serde_json::from_str(line) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(err = %e, "tlsx: unparseable line");
                continue;
            }
        };

        let host = parsed
            .host
            .clone()
            .or_else(|| parsed.ip.clone())
            .unwrap_or_default();
        let port: u16 = parsed
            .port
            .as_deref()
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);

        if host.is_empty() {
            continue;
        }

        let subject = parsed
            .subject_dn
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| parsed.subject_cn.clone())
            .unwrap_or_default();

        rows.push(TlsxRow {
            host,
            port,
            subject,
            issuer: parsed.issuer_dn.clone().unwrap_or_default(),
            not_before: parsed.not_before.clone().unwrap_or_default(),
            not_after: parsed.not_after.clone().unwrap_or_default(),
            serial: parsed.serial.clone().unwrap_or_default(),
            san: parsed.subject_an.clone(),
            ssl_version: parsed.tls_version.clone().unwrap_or_default(),
            cipher: parsed.cipher.clone().unwrap_or_default(),
            jarm: parsed.jarm_hash.clone().unwrap_or_default(),
            chain_length: 1,
        });
    }

    Ok(rows)
}
