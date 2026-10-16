use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::common::ExternalReq;
use super::sink::{Sink, Stage};

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpxRow {
    pub host: String,
    pub port: String,
    pub url: String,
    pub http_status: Option<String>,
    pub title: Option<String>,
    pub technologies: Vec<String>,
    pub webserver: Option<String>,
    pub cdn: Option<String>,
    pub favicon_hash: Option<String>,
    pub content_length: Option<u32>,
    pub headers: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct HttpxLine {
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    host: Option<String>,
    url: Option<String>,
    #[serde(default)]
    port: Option<String>,
    #[serde(default)]
    scheme: Option<String>,
    #[serde(default)]
    status_code: Option<i64>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    webserver: Option<String>,
    #[serde(default)]
    tech: Vec<String>,
    #[serde(default)]
    cdn_name: Option<String>,
    #[serde(default)]
    favicon: Option<String>,
    #[serde(default)]
    content_length: Option<u32>,
    #[serde(default)]
    header: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    screenshot_path: Option<String>,
}

pub async fn run_httpx(
    sink: &Sink,
    targets: &[String],
    scan_uid: &str,
    task_uid: Option<&str>,
    screenshots: bool,
    pool: &[String],
    screenshot_dir: &str,
) -> Result<Vec<String>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let mut rows: Vec<HttpxRow> = Vec::new();
    let mut shots: Vec<(String, String, String)> = Vec::new();
    for attempt in super::proxy::attempts(pool) {
        match run_once(targets, screenshots, attempt.as_deref(), screenshot_dir).await {
            Ok((r, s)) if !r.is_empty() => {
                rows = r;
                shots = s;
                break;
            }
            Ok(_) => {
                tracing::debug!(proxy = ?attempt, "httpx: no rows, trying next proxy");
            }
            Err(e) => {
                tracing::debug!(proxy = ?attempt, err = %e, "httpx: attempt failed, trying next proxy");
            }
        }
    }

    let count = rows.len();
    let urls: Vec<String> = rows.iter().map(|r| r.url.clone()).collect();
    send_probe_rows(sink, scan_uid, task_uid, &rows).await?;

    if screenshots {
        for (host, port, path) in shots {
            if let Err(e) =
                send_screenshot_file(sink, &host, &port, scan_uid, task_uid, &path).await
            {
                tracing::warn!(host, port, err = %e, "httpx: screenshot upload failed");
            }
        }
    }

    tracing::info!(targets = targets.len(), rows = count, "httpx batch complete");
    Ok(urls)
}

async fn run_once(
    targets: &[String],
    screenshots: bool,
    proxy: Option<&str>,
    screenshot_dir: &str,
) -> Result<(Vec<HttpxRow>, Vec<(String, String, String)>)> {
    let cfg = crate::config::cfg();
    tokio::fs::create_dir_all(screenshot_dir).await.ok();

    let mut args: Vec<String> = vec![
        "-json".into(),
        "-silent".into(),
        "-no-color".into(),
        "-td".into(),
        "-favicon".into(),
        "-irh".into(),
        "-timeout".into(),
        cfg.httpx_timeout.to_string(),
        "-retries".into(),
        "1".into(),
        "-rate-limit".into(),
        cfg.httpx_rate_limit.to_string(),
        "-threads".into(),
        cfg.httpx_threads.to_string(),
    ];

    if screenshots {
        args.push("-screenshot".into());
        args.push("-system-chrome".into());
        args.push("-srd".into());
        args.push(screenshot_dir.into());
        args.push("-exclude-screenshot-bytes".into());
    }

    if let Some(proxy) = proxy {
        args.push("-http-proxy".into());
        args.push(proxy.to_string());
    }

    let mut child = Command::new("httpx")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        let payload = targets.join("\n");
        stdin.write_all(payload.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.shutdown().await.ok();
    }

    let output = child.wait_with_output().await?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut rows: Vec<HttpxRow> = Vec::new();
    let mut shots: Vec<(String, String, String)> = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed: HttpxLine = match serde_json::from_str(line) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(err = %e, "httpx: unparseable line");
                continue;
            }
        };

        let host = parsed
            .input
            .as_deref()
            .and_then(|s| s.rsplit_once(':').map(|(h, _)| h.to_string()))
            .or_else(|| parsed.host.clone())
            .unwrap_or_default();
        let port = parsed
            .port
            .clone()
            .or_else(|| {
                parsed
                    .input
                    .as_deref()
                    .and_then(|s| s.rsplit_once(':').map(|(_, p)| p.to_string()))
            })
            .unwrap_or_default();

        if host.is_empty() || port.is_empty() {
            continue;
        }

        if let Some(path) = parsed.screenshot_path.clone() {
            if !path.is_empty() {
                shots.push((host.clone(), port.clone(), path));
            }
        }

        rows.push(HttpxRow {
            host: host.clone(),
            port: port.clone(),
            url: parsed
                .url
                .clone()
                .unwrap_or_else(|| format!("{}://{}:{}", parsed.scheme.as_deref().unwrap_or("http"), host, port)),
            http_status: parsed.status_code.map(|s| s.to_string()),
            title: parsed.title.clone().filter(|s| !s.is_empty()),
            technologies: parsed.tech.clone(),
            webserver: parsed.webserver.clone().filter(|s| !s.is_empty()),
            cdn: parsed.cdn_name.clone().filter(|s| !s.is_empty()),
            favicon_hash: parsed.favicon.clone().filter(|s| !s.is_empty()),
            content_length: parsed.content_length,
            headers: parsed
                .header
                .iter()
                .map(|(k, v)| (k.clone(), header_value_to_string(v)))
                .collect(),
        });
    }

    Ok((rows, shots))
}

async fn send_probe_rows(
    sink: &Sink,
    scan_uid: &str,
    task_uid: Option<&str>,
    rows: &[HttpxRow],
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut by_host: std::collections::HashMap<&str, Vec<&HttpxRow>> = std::collections::HashMap::new();
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
        if let Err(e) = sink.emit(Stage::Httpx, req).await {
            tracing::warn!(host, err = %e, "httpx checkout failed");
        }
    }
    Ok(())
}

async fn send_screenshot_file(
    sink: &Sink,
    host: &str,
    port: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    path: &str,
) -> Result<()> {
    if sink.is_local() {
        if let Ok(meta) = tokio::fs::metadata(path).await {
            if meta.len() >= 1000 {
                sink.note_screenshot(path).await;
            }
        }
        return Ok(());
    }
    let bytes = tokio::fs::read(path).await?;
    if bytes.len() < 1000 {
        return Ok(());
    }
    let encoded = STANDARD.encode(&bytes);
    let country = super::common::lookup_country(host).await;
    let req = ExternalReq {
        status: "success".to_string(),
        target: host.to_string(),
        body: encoded,
        version: crate::config::VERSION,
        scan_uid: scan_uid.to_string(),
        task_uid: task_uid.map(String::from),
        country,
        port: Some(port.to_string()),
    };
    sink.emit(Stage::Hxn, req).await
}

fn header_value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}
