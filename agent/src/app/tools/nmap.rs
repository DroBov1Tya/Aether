use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::{fs, process::Command};

use super::common::{CENSYS_NMAP_ARGS, CENSYS_UA};

mod parser;

#[tracing::instrument(name = "nmap", skip_all, fields(target = target))]
pub async fn run_nmap(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    ports: &str,
    scans_output_path: &str,
    api_key: &str,
) -> Result<Vec<String>> {
    let out_dir = Path::new(scans_output_path);
    fs::create_dir_all(out_dir).await?;

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let xml_path = format!("{}/scan_{}.xml", scans_output_path, timestamp);
    let mut http_services: Vec<String> = Vec::new();

    let mut cmd = Command::new("nmap");
    super::common::apply_proxy(&mut cmd);

    let port_arg = format!("-p{}", ports);
    let mut args: Vec<&str> = vec![
        "-Pn",
        "-sV",
        "-sC",
        "-sT",
        "-O",
        "-T3",
        "--max-rate=50",
        "--min-rtt-timeout=200ms",
        "--max-retries=2",
        "-f",
        "--data-length=24",
        "--script=banner,ssl-cert,http-title,http-server-header",
    ];
    args.extend_from_slice(CENSYS_NMAP_ARGS);
    args.push(&port_arg);

    let proxies = &crate::config::cfg().proxies;
    if let Some(proxy) = super::common::pick_random(proxies) {
        args.push("--proxies");
        args.push(proxy);
    }
    args.push(target);
    args.push("-oX");
    args.push(&xml_path);

    let output = cmd.args(&args).output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nmap failed: {stderr}");
    }

    match parser::parse_nmap_xml(&xml_path) {
        Ok(map) => {
            for mut result_port in map {
                if let Some(port) = result_port.get("port").cloned() {
                    let is_http = matches!(
                        result_port.get("service").map(String::as_str),
                        Some("http") | Some("https")
                    );

                    match probe_http_via_curl(target, &port).await {
                        Ok(curl_data) => {
                            let product = result_port.get("product").map(|p| p.to_lowercase());
                            let server_header = curl_data.get("server").map(|s| s.to_lowercase());

                            let is_nginx = product.as_ref().is_some_and(|p| p.contains("nginx"))
                                || server_header.as_ref().is_some_and(|s| s.contains("nginx"));

                            if !is_http && is_nginx {
                                tracing::info!(
                                    target,
                                    port = &*port,
                                    "f: nginx detected → treating as http"
                                );
                                result_port.insert("service".to_string(), "http".to_string());
                            }

                            if is_http || is_nginx {
                                http_services.push(port.clone());
                            }

                            let is_cloudflare =
                                product.as_ref().is_some_and(|p| p.contains("cloudflare"))
                                    || server_header
                                        .as_ref()
                                        .is_some_and(|s| s.contains("cloudflare"));

                            if server_header.is_some() && !is_cloudflare {
                                result_port
                                    .insert("banner".to_string(), curl_data["server"].clone());
                            }
                            if let Some(cf_ray) = curl_data.get("cloudflare_ray") {
                                result_port.insert("cloudflare_ray".to_string(), cf_ray.clone());
                            }
                            if let Some(powered_by) = curl_data.get("powered_by") {
                                result_port.insert("extra_info".to_string(), powered_by.clone());
                            }
                            if let Some(title) = curl_data.get("title") {
                                result_port.insert("http_title".to_string(), title.clone());
                            }
                            if let Some(status) = curl_data.get("http_status") {
                                result_port.insert("http_status".to_string(), status.clone());
                            }
                            if curl_data.contains_key("cloudflare_ray")
                                && !result_port.contains_key("product")
                            {
                                result_port.insert("product".to_string(), "Cloudflare".to_string());
                                result_port.insert("service".to_string(), "http".to_string());
                            }
                        }
                        Err(e) => {
                            tracing::debug!(target, port, error = %e, "curl probe failed");
                        }
                    }
                }

                if let Err(e) = send_result(
                    external_server_path,
                    &result_port,
                    target,
                    scan_uid,
                    task_uid,
                    api_key,
                )
                .await
                {
                    tracing::warn!(error = %e, "Failed to report port result");
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

async fn probe_http_via_curl(target: &str, port: &str) -> Result<HashMap<String, String>> {
    let url = if port == "443" || port == "8443" {
        format!("https://{}:{}", target, port)
    } else {
        format!("http://{}:{}", target, port)
    };

    let output = Command::new("curl")
        .args([
            "-sS",
            "-D",
            "-",
            "-o",
            "/dev/null",
            "-m",
            "10",
            "-L",
            "-A",
            CENSYS_UA,
            "-H",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "-H",
            "Accept-Language: en-US,en;q=0.9",
            "-H",
            "Accept-Encoding: gzip, deflate, br",
            "-H",
            "Connection: keep-alive",
            "-H",
            "Upgrade-Insecure-Requests: 1",
            "-H",
            "Sec-Fetch-Dest: document",
            "-H",
            "Sec-Fetch-Mode: navigate",
            "-H",
            "Sec-Fetch-Site: none",
            "-H",
            "Sec-Fetch-User: ?1",
            "--compressed",
            &url,
        ])
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut result = HashMap::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        if lower.starts_with("http/") {
            let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                result.insert("http_status".to_string(), parts[1].to_string());
            }
            continue;
        }

        if let Some(val) = extract_header(trimmed, "server:") {
            result.insert("server".to_string(), val);
        } else if let Some(val) = extract_header(trimmed, "cf-ray:") {
            result.insert("cloudflare_ray".to_string(), val);
        } else if let Some(val) = extract_header(trimmed, "x-powered-by:") {
            result.insert("powered_by".to_string(), val);
        } else if let Some(val) = extract_header(trimmed, "x-frame-options:") {
            result.insert("x_frame_options".to_string(), val);
        } else if let Some(val) = extract_header(trimmed, "strict-transport-security:") {
            result.insert("hsts".to_string(), val);
        } else if let Some(val) = extract_header(trimmed, "content-security-policy:") {
            result.insert("csp".to_string(), val);
        } else if let Some(val) = extract_header(trimmed, "set-cookie:") {
            result.entry("cookie".to_string()).or_insert(val);
        }
    }

    Ok(result)
}

fn extract_header(line: &str, prefix: &str) -> Option<String> {
    if line.to_lowercase().starts_with(prefix) {
        let val = line[prefix.len()..].trim().to_string();
        if !val.is_empty() {
            return Some(val);
        }
    }
    None
}

async fn send_result(
    external_server_path: &str,
    result_port: &HashMap<String, String>,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    api_key: &str,
) -> Result<()> {
    let url = format!("{}/api/checkout/nmap", external_server_path);
    let country = super::common::lookup_country(target).await;
    let json = super::common::ExternalReq {
        status: "complete".to_string(),
        target: target.to_string(),
        body: serde_json::to_string(result_port)?,
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
