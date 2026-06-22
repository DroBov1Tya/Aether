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
}

pub async fn run_whatweb(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    http_ports: &[String],
    api_key: &str,
) -> Result<()> {
    let mut all_results = Vec::new();

    for port in http_ports {
        let scheme = if port == "443" || port == "8443" || port == "993" {
            "https"
        } else {
            "http"
        };
        let url = format!("{}://{}:{}", scheme, target, port);
        let output_file = format!("/tmp/whatweb_{}_{}.json", target.replace(':', "_"), port);

        let mut cmd = Command::new("whatweb");
        super::common::apply_proxy(&mut cmd);
        let output = cmd
            .args([
                "--user-agent",
                super::common::CENSYS_UA,
                "--log-json",
                &output_file,
                &url,
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("[{:>15}] {}  err={}", "whatweb", url, stderr.trim());
            continue;
        }

        let content = match std::fs::read_to_string(&output_file) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("[{:>15}] read {}: {}", "whatweb", output_file, e);
                let _ = std::fs::remove_file(&output_file);
                continue;
            }
        };

        let json_results: Vec<serde_json::Value> = match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("[{:>15}] parse {}: {}", "whatweb", output_file, e);
                let _ = std::fs::remove_file(&output_file);
                continue;
            }
        };

        for result in json_results {
            let mut technologies = Vec::new();
            if let Some(plugins) = result.get("plugins").and_then(|v| v.as_object()) {
                for (name, info) in plugins {
                    let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
                    technologies.push(if version.is_empty() {
                        name.clone()
                    } else {
                        format!("{} {}", name, version)
                    });
                }
            }

            all_results.push(WhatWebResult {
                host: target.to_string(),
                port: port.clone(),
                url: url.clone(),
                http_status: result
                    .get("http_status")
                    .and_then(|v| v.as_i64())
                    .map(|s| s.to_string()),
                title: result
                    .get("title")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                technologies,
            });
        }

        let _ = std::fs::remove_file(&output_file);
    }

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
        body: serde_json::to_string(results).unwrap_or_default(),
        version: crate::config::VERSION,
        scan_uid: scan_uid.to_string(),
        task_uid: task_uid.map(String::from),
        country,
    };

    let response = super::common::post_json(&url, &json, api_key).await?;
    if !response.status().is_success() {
        anyhow::bail!("server returned {}", response.status());
    }
    Ok(())
}
