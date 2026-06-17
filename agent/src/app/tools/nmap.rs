use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tokio::process::Command;

mod parser;

pub async fn run_nmap(
    external_server_path: &String,
    target: &str,
    ports: &str,
    scans_output_path: &str,
) -> Result<(Vec<String>)> {
    let out_dir = Path::new(scans_output_path);
    fs::create_dir_all(out_dir).await?;

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let xml_path = format!("{}/scan_{}.xml", scans_output_path, timestamp);
    let mut http_services: Vec<String> = Vec::new();

    let mut cmd = Command::new("nmap");
    cmd.arg("-sV")
        .arg("-sC")
        .arg("-O")
        .arg(format!("-p{}", ports))
        .arg(target)
        .arg("-oX")
        .arg(&xml_path);

    tracing::info!(
        target = "nmap",
        host = %target,
        ports = %ports,
        output = %xml_path,
        "Running nmap scan"
    );

    let output = cmd.output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(target = "nmap", stderr = %stderr, "Nmap scan failed");
        anyhow::bail!("nmap failed: {stderr}");
    }

    tracing::info!(
        target = "nmap",
        host = %target,
        ports = %ports,
        xml = %xml_path,
        "Nmap scan completed successfully"
    );

    match parser::parse_nmap_xml(&xml_path) {
        Ok(map) => {
            for result_port in map.iter() {
                if let Err(e) =
                    send_result_to_server(external_server_path, result_port, target).await
                {
                    tracing::warn!(target = "nmap", error = %e, port = ?result_port, "Failed to report port result");
                }
                if let Some(port) = result_port.get("port") {
                    if result_port.get("service").map(String::as_str) == Some("http") {
                        http_services.push(port.clone());
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                target = "nmap_parser",
                error = %e,
                "Failed to parse nmap XML"
            );
        }
    }

    Ok(http_services)
}

async fn send_result_to_server(
    external_server_path: &str,
    result_port: &HashMap<String, String>,
    target: &str,
) -> Result<()> {
    let url = format!("http://{}/api/checkout/nmap", external_server_path);

    let body = json!({
        "host": target,
        "scan_result": result_port,
        "status": "complete"
    });

    tracing::debug!(target = "nmap", url = %url, body = %body, "Sending result to server");

    let response = reqwest::Client::new().post(&url).json(&body).send().await?;

    let status = response.status();
    let text = response.text().await.unwrap_or_default();

    if !status.is_success() {
        anyhow::bail!("server returned {status}: {text}");
    }

    tracing::info!(target = "nmap", status = %status, body = %text, "Result accepted by server");
    Ok(())
}
