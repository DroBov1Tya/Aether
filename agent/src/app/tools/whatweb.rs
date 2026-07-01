use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use super::common::ExternalReq;

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatWebResult {
    pub host: String,
    pub port: String,
    pub url: String,
    pub http_status: Option<String>,
    pub title: Option<String>,
    pub technologies: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_scheme: Option<String>,
}

pub async fn run_whatweb(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    http_ports: &[String],
    api_key: &str,
) -> Result<()> {
    if http_ports.is_empty() {
        tracing::warn!(target, "whatweb: no HTTP ports provided, skipping");
        return Ok(());
    }

    let mut all_results = Vec::new();

    for port in http_ports {
        let result = match try_whatweb(target, port, false).await {
            Ok(r) if !r.technologies.is_empty() || r.http_status.is_some() => Some(r),
            _ => match try_whatweb(target, port, true).await {
                Ok(r) if !r.technologies.is_empty() || r.http_status.is_some() => Some(r),
                Ok(_) => None,
                Err(e) => {
                    tracing::debug!(target, port, error = %e, "Both schemes failed for whatweb");
                    None
                }
            },
        };

        if let Some(ww_result) = result {
            all_results.push(ww_result);
        }
    }

    tracing::info!(
        target,
        total_ports = http_ports.len(),
        successful = all_results.len(),
        "whatweb completed"
    );

    send_to_server(
        external_server_path,
        target,
        scan_uid,
        task_uid,
        &all_results,
        api_key,
    )
    .await?;

    Ok(())
}

async fn try_whatweb(target: &str, port: &str, use_https: bool) -> Result<WhatWebResult> {
    let scheme = if use_https { "https" } else { "http" };
    let url = format!("{}://{}:{}", scheme, target, port);
    let out_file = format!(
        "/tmp/whatweb_{}_{}_{}.json",
        target.replace([':', '/'], "_"),
        port,
        scheme
    );

    let mut cmd = Command::new("whatweb");
    super::common::apply_proxy(&mut cmd);

    let args = vec![
        "--log-json",
        &out_file,
        "--open-timeout=15",
        "--read-timeout=30",
        &url,
    ];

    cmd.args(&args).output().await?;

    let content = match std::fs::read_to_string(&out_file) {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&out_file);
            anyhow::bail!("Failed to read whatweb output for {}: {}", url, e);
        }
    };

    let _ = std::fs::remove_file(&out_file);

    let mut json_results: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    if json_results.is_empty() {
        json_results = serde_json::from_str(&content).unwrap_or_default();
    }

    let result = json_results
        .pop()
        .ok_or_else(|| anyhow::anyhow!("whatweb returned empty results for {}", url))?;

    let mut technologies = Vec::new();
    if let Some(plugins) = result.get("plugins").and_then(|v| v.as_object()) {
        for (name, info) in plugins {
            if matches!(
                name.as_str(),
                "HTTPServer" | "Cookies" | "HttpOnly" | "X-Frame-Options"
            ) {
                continue;
            }

            let version = info
                .get("version")
                .and_then(|v| {
                    v.as_str().map(String::from).or_else(|| {
                        v.as_array()
                            .and_then(|a| a.first())
                            .and_then(|f| f.as_str())
                            .map(String::from)
                    })
                })
                .unwrap_or_default();

            technologies.push(if version.is_empty() {
                name.clone()
            } else {
                format!("{} {}", name, version)
            });
        }
    }

    let title = result.get("title").and_then(|v| {
        v.as_str().map(String::from).or_else(|| {
            v.as_array()
                .and_then(|a| a.first())
                .and_then(|f| f.as_str())
                .map(String::from)
        })
    });

    Ok(WhatWebResult {
        host: target.to_string(),
        port: port.to_string(),
        url,
        http_status: result
            .get("http_status")
            .and_then(|v| v.as_i64())
            .map(|s| s.to_string()),
        title,
        technologies,
        detected_scheme: Some(scheme.to_string()),
    })
}

async fn send_to_server(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    results: &[WhatWebResult],
    api_key: &str,
) -> Result<()> {
    let url = format!("{}/api/checkout/whatweb", external_server_path);

    let country = super::common::lookup_country(target).await;
    let json = ExternalReq {
        status: "complete".to_string(),
        target: target.to_string(),
        body: serde_json::to_string(results).unwrap_or_else(|_| "[]".to_string()),
        version: crate::config::VERSION,
        scan_uid: scan_uid.to_string(),
        task_uid: task_uid.map(String::from),
        country,
        port: None,
    };

    let response = super::common::post_json(&url, &json, api_key).await?;
    if !response.status().is_success() {
        anyhow::bail!("server returned {}", response.status());
    }

    tracing::info!(
        target,
        count = results.len(),
        "whatweb results sent to server"
    );
    Ok(())
}
