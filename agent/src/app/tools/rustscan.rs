use anyhow::Result;
use serde_json::json;
use tokio::process::Command;

pub async fn run_rustscan(external_server_path: &str, target: &str) -> Result<Vec<i64>> {
    tracing::info!(target = "rustscan", host = %target, "Running rustscan scan");

    let output = Command::new("rustscan")
        .arg("-a")
        .arg(target)
        .arg("--greppable")
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(target = "rustscan", stderr = %stderr, "Rustscan failed");
        anyhow::bail!("rustscan failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::info!(target = "rustscan", stdout = %stdout, "Rustscan output");

    let ports = parse_ports(&stdout)?;

    if let Err(e) = send_result_to_server(external_server_path, target, &ports).await {
        tracing::warn!(target = "rustscan", error = %e, "Failed to report scan results, continuing");
    }

    tracing::info!(target = "rustscan", host = %target, ports = ?ports, "Rustscan completed");
    Ok(ports)
}

fn parse_ports(stdout: &str) -> Result<Vec<i64>> {
    let mut ports = Vec::new();

    for line in stdout.lines() {
        if !line.contains("->") {
            continue;
        }
        if let Some(raw) = line.split('>').nth(1) {
            let raw = raw.trim().trim_start_matches('[').trim_end_matches(']');
            for part in raw.split(',') {
                let port: i64 = part.trim().parse()?;
                ports.push(port);
            }
        }
    }

    Ok(ports)
}

async fn send_result_to_server(
    external_server_path: &str,
    target: &str,
    ports: &[i64],
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("http://{}/api/checkout/rustscan", external_server_path);

    let json = json!({
        "target": target,
        "ports": ports,
        "status": "completed"
    });
    
    let response = client
        .post(&url)
        .json(&json)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("server returned {}", response.status());
    }

    Ok(())
}
