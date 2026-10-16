use anyhow::Result;
use tokio::process::Command;

use super::common::ExternalReq;
use super::sink::{Sink, Stage};

const PATHS: &[&str] = &[
    "/admin",
    "/login",
    "/wp-admin",
    "/administrator",
    "/phpmyadmin",
    "/.git/config",
    "/.gitignore",
    "/.env",
    "/.htaccess",
    "/.htpasswd",
    "/backup",
    "/config",
    "/api",
    "/api/v1",
    "/graphql",
    "/swagger",
    "/swagger-ui",
    "/api-docs",
    "/console",
    "/debug",
    "/test",
    "/dev",
    "/uploads",
    "/downloads",
    "/assets",
    "/css",
    "/js",
    "/images",
    "/includes",
    "/modules",
    "/plugins",
    "/themes",
    "/cgi-bin",
    "/tmp",
    "/private",
    "/restricted",
    "/setup",
    "/install",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/.well-known/security.txt",
    "/server-status",
    "/manager",
    "/error.log",
    "/CHANGELOG.txt",
    "/readme.html",
    "/license.txt",
    "/wp-config.php",
    "/.DS_Store",
];

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FuzzFinding {
    pub target: String,
    pub port: String,
    pub path: String,
    pub url: String,
    pub http_status: u16,
}

#[tracing::instrument(name = "fuzzing", skip_all, fields(target = target))]
pub async fn run_fuzzing(
    sink: &Sink,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    http_ports: &[String],
    screenshots: bool,
    screenshot_dir: &str,
) -> Result<Vec<FuzzFinding>> {
    if http_ports.is_empty() {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();

    for raw_port in http_ports {
        let port = raw_port.trim();

        for path in PATHS {
            let url = format!("http://{}:{}{}", target, port, path);

            match probe_url(&url).await {
                Ok(status) if is_interesting_status(status) => {
                    tracing::info!(target, port, path, status, "fuzzing: found");
                    findings.push(FuzzFinding {
                        target: target.to_string(),
                        port: port.to_string(),
                        path: path.to_string(),
                        url: url.clone(),
                        http_status: status,
                    });
                }
                Ok(status) => {
                    tracing::debug!(target, port, path, status, "fuzzing: skip");
                }
                Err(e) => {
                    tracing::debug!(target, port, path, error = %e, "fuzzing: probe failed");
                }
            }
        }
    }

    if !findings.is_empty() {
        send_findings(sink, target, scan_uid, task_uid, &findings).await?;
        if screenshots {
            take_screenshots(sink, target, scan_uid, task_uid, &findings, screenshot_dir).await?;
        }
    }

    Ok(findings)
}

fn is_interesting_status(status: u16) -> bool {
    status == 200
        || status == 301
        || status == 302
        || status == 401
        || status == 403
        || (500..600).contains(&status)
}

async fn probe_url(url: &str) -> Result<u16> {
    let output = Command::new("curl")
        .args([
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-m",
            "8",
            "-L",
            "-A",
            super::common::CENSYS_UA,
            &url,
        ])
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let status: u16 = stdout.trim().parse().unwrap_or(0);
    Ok(status)
}

async fn send_findings(
    sink: &Sink,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    findings: &[FuzzFinding],
) -> Result<()> {
    let country = super::common::lookup_country(target).await;
    let req = ExternalReq {
        status: "complete".to_string(),
        target: target.to_string(),
        body: serde_json::to_string(findings)?,
        version: crate::config::VERSION,
        scan_uid: scan_uid.to_string(),
        task_uid: task_uid.map(String::from),
        country,
        port: None,
    };

    sink.emit(Stage::Fuzzing, req).await
}

async fn take_screenshots(
    sink: &Sink,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    findings: &[FuzzFinding],
    screenshot_dir: &str,
) -> Result<()> {
    let screenshot_dir = std::path::PathBuf::from(screenshot_dir);
    tokio::fs::create_dir_all(&screenshot_dir).await.ok();

    for finding in findings {
        let safe_name = format!(
            "{}_{}_{}",
            target.replace(['.', ':'], "_"),
            finding.port,
            finding.path.replace('/', "_")
        );
        let out_path = screenshot_dir.join(format!("{}.png", safe_name));

        let args: Vec<String> = vec![
            "--headless=new".to_string(),
            "--no-sandbox".to_string(),
            "--disable-gpu".to_string(),
            "--disable-software-rasterizer".to_string(),
            format!("--screenshot={}", out_path.to_string_lossy()),
            "--window-size=1920,1080".to_string(),
            "--ignore-certificate-errors".to_string(),
            "--disable-web-security".to_string(),
            format!("--user-agent={}", super::common::CENSYS_UA),
            finding.url.clone(),
        ];

        let output = Command::new("chromium")
            .args(&args)
            .env("TERM", "xterm")
            .env("HOME", "/tmp")
            .env("XDG_RUNTIME_DIR", "/tmp")
            .output()
            .await;

        if let Ok(out) = output {
            if out.status.success() && tokio::fs::metadata(&out_path).await.is_ok() {
                send_screenshot_file(
                    sink,
                    target,
                    scan_uid,
                    task_uid,
                    &finding.port,
                    &finding.path,
                    &out_path,
                )
                .await
                .ok();
            }
        }
    }

    Ok(())
}

async fn send_screenshot_file(
    sink: &Sink,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    port: &str,
    _path: &str,
    file_path: &std::path::PathBuf,
) -> Result<()> {
    if sink.is_local() {
        if let Ok(meta) = tokio::fs::metadata(file_path).await {
            if meta.len() >= 1000 {
                sink.note_screenshot(&file_path.to_string_lossy()).await;
            }
        }
        return Ok(());
    }

    let image_bytes = tokio::fs::read(file_path).await?;
    if image_bytes.len() < 1000 {
        return Ok(());
    }

    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &image_bytes);
    let country = super::common::lookup_country(target).await;

    let payload = serde_json::json!({
        "port": port,
        "path": format!("/fuzzing/{}", port),
        "image_base64": encoded,
    });

    let req = ExternalReq {
        status: "success".to_string(),
        target: target.to_string(),
        body: serde_json::to_string(&payload)?,
        version: crate::config::VERSION,
        scan_uid: scan_uid.to_string(),
        task_uid: task_uid.map(String::from),
        country,
        port: None,
    };

    sink.emit(Stage::Hxn, req).await
}
