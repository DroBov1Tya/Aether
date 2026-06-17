use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

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
    external_server_path: &String,
    target: &str,
    http_ports: &[String],
) -> Result<()> {
    let mut all_results = Vec::new();

    for port in http_ports {
        let url = format!("http://{}:{}", target, port);
        let output_file = format!("/tmp/whatweb_{}_{}.json", target.replace(':', "_"), port);

        let output = Command::new("whatweb")
            .args(["--log-json", &output_file, &url])
            .output()
            .await?;

        if !output.status.success() {
            tracing::error!(
                target = "whatweb",
                url = %url,
                stderr = %String::from_utf8_lossy(&output.stderr),
                "Whatweb failed"
            );
            continue;
        }

        let content = match std::fs::read_to_string(&output_file) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(target = "whatweb", error = %e, "Failed to read output");
                let _ = std::fs::remove_file(&output_file);
                continue;
            }
        };

        let json_results: Vec<serde_json::Value> = match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(target = "whatweb", error = %e, "Failed to parse JSON");
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

    let _ = send_to_server(&external_server_path, &all_results).await?;

    Ok(())
}

async fn send_to_server(external_server_path: &String, results: &Vec<WhatWebResult>) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("http://localhost:{}/", external_server_path);
    let _ = client.post(&url).json(results).send().await?;
    Ok(())
}
