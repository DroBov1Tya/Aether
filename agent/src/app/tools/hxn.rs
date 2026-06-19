use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::path::PathBuf;
use std::time::Duration;
use tokio::{fs, process::Command, time::sleep};

#[tracing::instrument(name = "hxn", skip_all, fields(target = target))]
pub async fn run_screenshot(
    external_server_path: &str,
    target: &str,
    _delay: &u64,
    http_ports: &[String],
    api_key: &str,
) -> Result<()> {
    if http_ports.is_empty() {
        tracing::warn!(target, "hxn: no HTTP ports, skipping");
        return Ok(());
    }

    let screenshot_dir = PathBuf::from("/app/screenshots");
    fs::create_dir_all(&screenshot_dir).await.ok();

    let cfg = crate::config::cfg();

    for raw_port in http_ports {
        let port = raw_port.trim().to_string();
        let scheme = if port == "443" || port == "8443" || port == "993" {
            "https"
        } else {
            "http"
        };
        let url = if port == "80" || port == "443" {
            format!("{}://{}", scheme, target)
        } else {
            format!("{}://{}:{}", scheme, target, port)
        };

        tracing::info!(target, port = &port, scheme, url = &url, "hxn: screenshot");

        let filename = format!("{}_{}.png", target.replace(['.', ':'], "_"), port);
        let out_path = screenshot_dir.join(&filename);

        let mut args = vec![
            "--headless=new".to_string(),
            "--no-sandbox".to_string(),
            "--disable-gpu".to_string(),
            "--disable-software-rasterizer".to_string(),
            format!("--screenshot={}", out_path.to_string_lossy()),
            "--window-size=1920,1080".to_string(),
            "--disable-features=NetworkServiceInProcess2".to_string(),
            "--ignore-certificate-errors".to_string(),
            "--disable-web-security".to_string(),
        ];

        if let Some(proxy) = super::common::pick_random(&cfg.proxies) {
            args.push(format!("--proxy-server={}", proxy));
        }

        args.push(url.clone());

        let output = Command::new("chromium")
            .args(&args)
            .env("TERM", "xterm")
            .env("HOME", "/tmp")
            .env("XDG_RUNTIME_DIR", "/tmp")
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            tracing::warn!(target, port = &port, err = %stderr, "chromium failed");
            continue;
        }

        sleep(Duration::from_millis(800)).await;

        if fs::metadata(&out_path).await.is_ok() {
            if let Err(e) =
                send_screenshot(external_server_path, target, &port, &out_path, api_key).await
            {
                tracing::error!(target, port = &port, err = %e, "Failed to send screenshot");
            }
        } else {
            tracing::warn!(target, port = &port, path = %out_path.display(), "chromium did not create file");
        }
    }

    Ok(())
}

async fn send_screenshot(
    external_server_path: &str,
    target: &str,
    port: &str,
    path: &PathBuf,
    api_key: &str,
) -> Result<()> {
    let image_bytes = fs::read(path).await?;
    if image_bytes.len() < 1000 {
        tracing::warn!(target, port = %port, size = image_bytes.len(), "screenshot too small, skipping");
        return Ok(());
    }

    let encoded = STANDARD.encode(&image_bytes);
    let url = format!("{}/api/checkout/hxn", external_server_path);
    let json = super::common::ExternalReq {
        status: "success".to_string(),
        target: target.to_string(),
        body: encoded,
        version: crate::config::VERSION,
    };

    let response = super::common::post_json(&url, &json, api_key).await?;
    if !response.status().is_success() {
        anyhow::bail!("API returned {}", response.status());
    }
    Ok(())
}
