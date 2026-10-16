use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::common::ExternalReq;
use super::sink::{Sink, Stage};

#[derive(Debug, Serialize, Deserialize)]
pub struct NucleiRow {
    pub host: String,
    pub port: String,
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
}

#[derive(Debug, Deserialize)]
struct NucleiLine {
    #[serde(rename = "template-id", default)]
    template_id: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(rename = "matched-at", default)]
    matched_at: Option<String>,
    #[serde(rename = "type", default)]
    protocol_type: Option<String>,
    #[serde(default)]
    info: NucleiInfo,
    #[serde(rename = "extracted-results", default)]
    extracted_results: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NucleiInfo {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    reference: Vec<String>,
}

pub async fn run_nuclei(
    sink: &Sink,
    urls: &[String],
    scan_uid: &str,
    task_uid: Option<&str>,
    pool: &[String],
) -> Result<usize> {
    if urls.is_empty() {
        return Ok(0);
    }

    let mut rows: Vec<NucleiRow> = Vec::new();
    for attempt in super::proxy::attempts(pool) {
        match run_once(urls, attempt.as_deref()).await {
            Ok(r) => {
                rows = r;
                break;
            }
            Err(e) => {
                tracing::debug!(proxy = ?attempt, err = %e, "nuclei: attempt failed, trying next proxy");
            }
        }
    }

    let count = rows.len();
    send_findings(sink, scan_uid, task_uid, &rows).await?;
    tracing::info!(urls = urls.len(), findings = count, "nuclei batch complete");
    Ok(count)
}

async fn run_once(urls: &[String], proxy: Option<&str>) -> Result<Vec<NucleiRow>> {
    let cfg = crate::config::cfg();

    let mut args: Vec<String> = vec![
        "-jsonl".into(),
        "-silent".into(),
        "-nc".into(),
        "-duc".into(),
        "-severity".into(),
        cfg.nuclei_severity.clone(),
        "-rate-limit".into(),
        cfg.nuclei_rate_limit.to_string(),
        "-concurrency".into(),
        cfg.nuclei_concurrency.to_string(),
        "-timeout".into(),
        cfg.nuclei_timeout.to_string(),
    ];

    if !cfg.nuclei_tags.trim().is_empty() {
        args.push("-tags".into());
        args.push(cfg.nuclei_tags.clone());
    }

    if let Some(proxy) = proxy {
        args.push("-proxy".into());
        args.push(proxy.to_string());
    }

    let mut child = Command::new("nuclei")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        let payload = urls.join("\n");
        stdin.write_all(payload.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.shutdown().await.ok();
    }

    let output = child.wait_with_output().await?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut rows: Vec<NucleiRow> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed: NucleiLine = match serde_json::from_str(line) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(err = %e, "nuclei: unparseable line");
                continue;
            }
        };

        let raw_host = parsed.host.clone().unwrap_or_default();
        let matched_at = parsed.matched_at.clone().unwrap_or_else(|| raw_host.clone());
        let (host, port) = split_host_port(&raw_host, &matched_at);

        if parsed.template_id.is_empty() {
            continue;
        }

        rows.push(NucleiRow {
            host,
            port,
            url: matched_at,
            template_id: parsed.template_id.clone(),
            name: parsed.info.name.clone().unwrap_or_default(),
            severity: parsed.info.severity.clone().unwrap_or_else(|| "unknown".into()),
            protocol_type: parsed.protocol_type.clone().unwrap_or_default(),
            matched_at: parsed.matched_at.clone().unwrap_or_default(),
            tags: parsed.info.tags.clone(),
            description: parsed.info.description.clone().filter(|s| !s.is_empty()),
            reference: parsed.info.reference.clone(),
            extracted: parsed.extracted_results.clone(),
        });
    }

    Ok(rows)
}

fn split_host_port(raw_host: &str, matched_at: &str) -> (String, String) {
    if let Some((h, p)) = raw_host.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() {
            return (h.to_string(), p.to_string());
        }
    }
    let cleaned = matched_at
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let authority = cleaned.split('/').next().unwrap_or(cleaned);
    if let Some((h, p)) = authority.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() {
            return (h.to_string(), p.to_string());
        }
    }
    let default_port = if matched_at.starts_with("https://") {
        "443"
    } else {
        "80"
    };
    let host = if raw_host.is_empty() {
        authority.to_string()
    } else {
        raw_host.to_string()
    };
    (host, default_port.to_string())
}

async fn send_findings(
    sink: &Sink,
    scan_uid: &str,
    task_uid: Option<&str>,
    rows: &[NucleiRow],
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut by_host: std::collections::HashMap<&str, Vec<&NucleiRow>> = std::collections::HashMap::new();
    for r in rows {
        by_host.entry(r.host.as_str()).or_default().push(r);
    }

    for (host, host_rows) in by_host {
        let country = super::common::lookup_country(host).await;
        let req = ExternalReq {
            status: "complete".to_string(),
            target: host.to_string(),
            body: serde_json::to_string(&host_rows).unwrap_or_else(|_| "[]".to_string()),
            version: crate::config::VERSION,
            scan_uid: scan_uid.to_string(),
            task_uid: task_uid.map(String::from),
            country,
            port: None,
        };
        if let Err(e) = sink.emit(Stage::Nuclei, req).await {
            tracing::warn!(host, err = %e, "nuclei checkout failed");
        }
    }
    Ok(())
}
