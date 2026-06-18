use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::{fs, process::Command};

mod parser;

#[tracing::instrument(name = "nmap", skip_all, fields(target = target))]
pub async fn run_nmap(
    external_server_path: &str,
    target: &str,
    ports: &str,
    scans_output_path: &str,
    api_key: &str,
) -> Result<Vec<String>> {
    let out_dir = Path::new(scans_output_path);
    fs::create_dir_all(out_dir).await?;

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let xml_path = format!("{}/scan_{}.xml", scans_output_path, timestamp);
    let mut http_services: Vec<String> = Vec::new();

    let output = Command::new("nmap")
        .args(&[
            "-sV",
            "-sC",
            "-sT",
            &format!("-p{}", ports),
            target,
            "-oX",
            &xml_path,
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nmap failed: {stderr}");
    }

    match parser::parse_nmap_xml(&xml_path) {
        Ok(map) => {
            for result_port in map.iter() {
                if let Err(e) =
                    send_result(external_server_path, result_port, target, api_key).await
                {
                    tracing::warn!(error = %e, "Failed to report port result");
                }
                if let Some(port) = result_port.get("port") {
                    if matches!(
                        result_port.get("service").map(String::as_str),
                        Some("http") | Some("https")
                    ) {
                        http_services.push(port.clone());
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse nmap XML");
        }
    }

    let cooldown = crate::config::cfg().scan_cooldown;
    if cooldown > 0 {
        tracing::info!("Cooldown {}s", cooldown);
        tokio::time::sleep(Duration::from_secs(cooldown)).await;
    }

    Ok(http_services)
}

async fn send_result(
    external_server_path: &str,
    result_port: &HashMap<String, String>,
    target: &str,
    api_key: &str,
) -> Result<()> {
    let url = format!("{}/api/checkout/nmap", external_server_path);
    let json = super::common::ExternalReq {
        status: "complete".to_string(),
        target: target.to_string(),
        body: serde_json::to_string(result_port)?,
        version: crate::config::VERSION,
    };

    let response = super::common::post_json(&url, &json, api_key).await?;
    if !response.status().is_success() {
        anyhow::bail!("server returned {}", response.status());
    }
    Ok(())
}
