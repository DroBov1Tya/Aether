use anyhow::Result;
use std::time::Duration;
use tokio::process::Command;

#[tracing::instrument(name = "rustscan", skip_all, fields(target = target))]
pub async fn run_rustscan(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    api_key: &str,
) -> Result<Vec<i64>> {
    let mut cmd = Command::new("rustscan");
    super::common::apply_proxy(&mut cmd);

    let output = cmd.args(["-a", target, "--greppable"]).output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("rustscan failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let ports = parse_ports(&stdout)?;

    if let Err(e) = send_result(
        external_server_path,
        target,
        scan_uid,
        task_uid,
        &ports,
        api_key,
    )
    .await
    {
        tracing::warn!(error = %e, "Failed to report scan results");
    }

    let cooldown = crate::config::cfg().scan_cooldown;
    if cooldown > 0 {
        tracing::info!("Cooldown {}s", cooldown);
        tokio::time::sleep(Duration::from_secs(cooldown)).await;
    }

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
                if let Ok(port) = part.trim().parse::<i64>() {
                    ports.push(port);
                }
            }
        }
    }
    Ok(ports)
}

async fn send_result(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    ports: &[i64],
    api_key: &str,
) -> Result<()> {
    let url = format!("{}/api/checkout/rustscan", external_server_path);
    let country = super::common::lookup_country(target).await;
    let json = super::common::ExternalReq {
        status: "complete".to_string(),
        target: target.to_string(),
        body: serde_json::to_string(ports)?,
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
    Ok(())
}
