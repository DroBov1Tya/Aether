use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::common::ExternalReq;

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsxResult {
    pub target: String,
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub cname: Vec<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
    pub ptr: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DnsxLine {
    host: Option<String>,
    #[serde(default)]
    a: Vec<String>,
    #[serde(default)]
    aaaa: Vec<String>,
    #[serde(default)]
    cname: Vec<String>,
    #[serde(default)]
    mx: Vec<String>,
    #[serde(default)]
    ns: Vec<String>,
    #[serde(default)]
    txt: Vec<String>,
    #[serde(default)]
    ptr: Vec<String>,
}

pub async fn run_dnsx(
    external_server_path: &str,
    targets: &[String],
    scan_uid: &str,
    task_uid: Option<&str>,
    _pool: &[String],
    api_key: &str,
) -> Result<usize> {
    if targets.is_empty() {
        return Ok(0);
    }

    // DNS resolves over UDP/TCP, not HTTP, so the HTTP proxy pool does not
    // apply here; dnsx always runs direct. `_pool` is accepted only to keep
    // the pipeline call shape uniform with the other tools.
    let cfg = crate::config::cfg();

    let args: Vec<String> = vec![
        "-json".into(),
        "-silent".into(),
        "-nc".into(),
        "-a".into(),
        "-aaaa".into(),
        "-cname".into(),
        "-mx".into(),
        "-ns".into(),
        "-txt".into(),
        "-ptr".into(),
        "-resp".into(),
        "-t".into(),
        cfg.dnsx_threads.to_string(),
    ];

    let mut child = Command::new("dnsx")
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

    let url = format!("{}/api/checkout/dns", external_server_path);
    let mut count = 0usize;

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed: DnsxLine = match serde_json::from_str(line) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(err = %e, "dnsx: unparseable line");
                continue;
            }
        };
        let target = match parsed.host.clone() {
            Some(h) if !h.is_empty() => h,
            _ => continue,
        };

        let result = DnsxResult {
            target: target.clone(),
            a: parsed.a,
            aaaa: parsed.aaaa,
            cname: strip_trailing_dots(parsed.cname),
            mx: parsed.mx,
            ns: strip_trailing_dots(parsed.ns),
            txt: parsed.txt,
            ptr: strip_trailing_dots(parsed.ptr),
        };

        let country = super::common::lookup_country(&target).await;
        let req = ExternalReq {
            status: "complete".to_string(),
            target: target.clone(),
            body: serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string()),
            version: crate::config::VERSION,
            scan_uid: scan_uid.to_string(),
            task_uid: task_uid.map(String::from),
            country,
            port: None,
        };
        if let Ok(resp) = super::common::post_json(&url, &req, api_key).await {
            if resp.status().is_success() {
                count += 1;
            } else {
                tracing::warn!(target = %target, status = %resp.status(), "dnsx checkout non-200");
            }
        }
    }

    tracing::info!(targets = targets.len(), resolved = count, "dnsx batch complete");
    Ok(count)
}

fn strip_trailing_dots(v: Vec<String>) -> Vec<String> {
    v.into_iter()
        .map(|s| s.trim_end_matches('.').to_string())
        .collect()
}
