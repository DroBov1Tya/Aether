use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::path::PathBuf;
use tokio::{fs, process::Command};

pub async fn run_hxn(
    external_server_path: &str,
    target: &str,
    delay: &u64,
    http_ports: &[String],
) -> Result<()> {
    for port in http_ports {
        let url = format!("{}:{}", target, port);

        tracing::info!(target = "hxn", url = %url, "Running hxn screenshot");

        let output = Command::new("hxn")
            .arg("-u")
            .arg(&url)
            .arg("--fullpage")
            .arg("--delay")
            .arg(delay.to_string())
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!(target = "hxn", stderr = %stderr, "hxn failed");
            anyhow::bail!("hxn failed: {stderr}");
        }

        tracing::info!(target = "hxn", url = %url, "hxn completed successfully");

        let screenshot_path = screenshot_path_for(&url);
        send_screenshot(external_server_path, port, &screenshot_path).await?;
    }

    Ok(())
}

fn screenshot_path_for(url: &str) -> PathBuf {
    let stem: String = url.chars().filter(|c| c.is_alphanumeric()).collect();
    PathBuf::from("./hxnshots/").join(format!("{stem}.png"))
}

async fn send_screenshot(external_server_path: &str, port: &str, path: &PathBuf) -> Result<()> {
    let image_bytes = fs::read(path).await?;
    let encoded = STANDARD.encode(&image_bytes);

    let client = reqwest::Client::new();
    let url = format!("http://{external_server_path}/api/checkout/hxn");

    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "port": port,
            "screenshot": encoded,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("failed to send screenshot to {url}: {}", response.status());
    }

    Ok(())
}
