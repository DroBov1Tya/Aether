use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::{fs, process::Command};

use super::common::{CENSYS_NMAP_ARGS, CENSYS_UA};

mod parser;

const CLEAN_CENSYS_NMAP_ARGS: &[&str] = &[
    "-Pn",
    "-sV",
    "-sC",
    "-sT",
    "-T3",
    "--max-rate=25",
    "--min-rtt-timeout=400ms",
    "--max-rtt-timeout=3000ms",
    "--initial-rtt-timeout=1000ms",
    "--max-retries=3",
    "--version-intensity=8",
    "--reason",
    "--host-timeout=5m",
    "--script-timeout=30s",
];

const CENSYS_HTTP_SCRIPTS: &str = "banner,ssl-cert,http-title,http-server-header,\
     http-headers,http-methods,http-enum,http-robots.txt,\
     ssl-enum-ciphers";

#[tracing::instrument(name = "nmap", skip_all, fields(target = target))]
pub async fn run_nmap(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    ports: &str,
    scans_output_path: &str,
    proxy: Option<&str>,
    api_key: &str,
) -> Result<Vec<String>> {
    let out_dir = Path::new(scans_output_path);
    fs::create_dir_all(out_dir).await?;

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let xml_path = format!("{}/scan_{}.xml", scans_output_path, timestamp);
    let mut http_services: Vec<String> = Vec::new();

    let mut cmd = Command::new("nmap");
    super::common::apply_proxy_with(&mut cmd, proxy);

    let port_arg = format!("-p{}", ports);

    let mut args: Vec<&str> = Vec::new();
    args.extend_from_slice(CLEAN_CENSYS_NMAP_ARGS);
    args.extend_from_slice(CENSYS_NMAP_ARGS);
    args.push("--script");
    args.push(CENSYS_HTTP_SCRIPTS);
    args.push(&port_arg);

    if let Some(proxy) = proxy.filter(|p| !p.trim().is_empty()) {
        args.push("--proxies");
        args.push(proxy);
    }

    args.push(target);
    args.push("-oX");
    args.push(&xml_path);

    tracing::debug!(target, args = ?args, "Starting nmap scan");

    let output = cmd.args(&args).output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(target, stderr = %stderr, "nmap returned non-zero status");
    }

    match parser::parse_nmap_xml(&xml_path) {
        Ok(map) if map.is_empty() => {
            tracing::warn!(target, "nmap returned 0 open ports");
        }
        Ok(map) => {
            for mut result_port in map {
                if let Some(port) = result_port.get("port").cloned() {
                    let nmap_is_http = matches!(
                        result_port.get("service").map(String::as_str),
                        Some("http") | Some("https") | Some("http-proxy") | Some("http-alt")
                    );

                    match probe_http_via_curl_dual_scheme(target, &port).await {
                        Ok(curl_data) if !curl_data.is_empty() => {
                            enrich_port_data(
                                &mut result_port,
                                &curl_data,
                                nmap_is_http,
                                target,
                                &port,
                            );

                            let service = result_port.get("service").map(String::as_str);
                            if !matches!(service, Some("http") | Some("https") | Some("http-alt")) {
                                tracing::info!(
                                    target,
                                    port,
                                    "curl succeeded but nmap missed HTTP — adding as http"
                                );
                                result_port.insert("service".to_string(), "http".to_string());
                            }

                            http_services.push(port.clone());
                        }
                        Ok(_) => {
                            if nmap_is_http {
                                http_services.push(port.clone());
                            }
                        }
                        Err(e) => {
                            tracing::debug!(target, port, error = %e, "curl probe failed both schemes");
                            if nmap_is_http {
                                http_services.push(port.clone());
                            }
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
            if let Ok(meta) = fs::metadata(&xml_path).await {
                if meta.len() > 0 {
                    if let Ok(first_bytes) = fs::read(&xml_path).await {
                        let preview =
                            String::from_utf8_lossy(&first_bytes[..first_bytes.len().min(500)]);
                        tracing::debug!(xml_preview = %preview, "nmap XML beginning");
                    }
                } else {
                    tracing::warn!("nmap XML file is empty");
                }
            }
        }
    }

    let cooldown = crate::config::cfg().scan_cooldown;
    if cooldown > 0 {
        tracing::info!("Cooldown {}s", cooldown);
        tokio::time::sleep(Duration::from_secs(cooldown)).await;
    }

    Ok(http_services)
}

fn enrich_port_data(
    result_port: &mut HashMap<String, String>,
    curl_data: &HashMap<String, String>,
    nmap_is_http: bool,
    target: &str,
    port: &str,
) {
    let product = result_port.get("product").map(|p| p.to_lowercase());
    let server_header = curl_data.get("server").map(|s| s.to_lowercase());

    let is_cloudflare = server_header
        .as_ref()
        .is_some_and(|s| s.contains("cloudflare"));

    if curl_data.contains_key("cloudflare_ray") && !result_port.contains_key("product") {
        result_port.insert("product".to_string(), "Cloudflare".to_string());
        result_port.insert("service".to_string(), "http".to_string());
    }

    let is_nginx = !is_cloudflare
        && (product.as_ref().is_some_and(|p| p.contains("nginx"))
            || server_header.as_ref().is_some_and(|s| s.contains("nginx")));

    if !nmap_is_http && is_nginx {
        tracing::info!(target, port, "nginx detected via header → treating as http");
        result_port.insert("service".to_string(), "http".to_string());
    }

    if let Some(server) = curl_data.get("server") {
        if !is_cloudflare {
            result_port.insert("banner".to_string(), server.clone());
        }
    }

    let mappings = [
        ("cloudflare_ray", "cloudflare_ray"),
        ("powered_by", "extra_info"),
        ("title", "http_title"),
        ("http_status", "http_status"),
        ("x_frame_options", "x_frame_options"),
        ("hsts", "strict_transport_security"),
        ("csp", "content_security_policy"),
        ("cookie", "set_cookie"),
        ("location", "redirect_location"),
    ];

    for (curl_key, result_key) in mappings {
        if let Some(val) = curl_data.get(curl_key) {
            result_port.insert(result_key.to_string(), val.clone());
        }
    }

    if let Some(status) = curl_data.get("http_status") {
        let health = match status.chars().next() {
            Some('2') => "ok",
            Some('3') => "redirect",
            Some('4') => "client_error",
            Some('5') => "server_error",
            _ => "unknown",
        };
        result_port.insert("http_health".to_string(), health.to_string());
    }
}

async fn probe_http_via_curl_dual_scheme(
    target: &str,
    port: &str,
) -> Result<HashMap<String, String>> {
    let https_result = try_curl_with_scheme(target, port, true).await;
    if let Ok(data) = &https_result {
        if !data.is_empty() {
            let mut enriched = data.clone();
            enriched.insert("detected_scheme".to_string(), "https".to_string());
            return Ok(enriched);
        }
    }

    let http_result = try_curl_with_scheme(target, port, false).await;
    if let Ok(data) = &http_result {
        if !data.is_empty() {
            let mut enriched = data.clone();
            enriched.insert("detected_scheme".to_string(), "http".to_string());
            return Ok(enriched);
        }
    }

    https_result
}

async fn try_curl_with_scheme(
    target: &str,
    port: &str,
    use_https: bool,
) -> Result<HashMap<String, String>> {
    let scheme = if use_https { "https" } else { "http" };
    let url = format!("{}://{}:{}", scheme, target, port);

    let mut curl_cmd = Command::new("curl");
    super::common::apply_proxy(&mut curl_cmd);

    let mut curl_args: Vec<&str> = vec![
        "-sS",
        "-D",
        "-",
        "-o",
        "/dev/null",
        "-m",
        "12",
        "--max-time",
        "15",
        "-L",
        "--location-trusted",
        "-k",
        "--connect-timeout",
        "8",
        "-A",
        CENSYS_UA,
        "-H",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
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
        "-H",
        "Cache-Control: no-cache",
        "--compressed",
    ];

    if use_https {
        curl_args.extend_from_slice(&[
            "--tlsv1.2",
            "--ciphers", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256",
        ]);
    }

    curl_args.push(&url);

    let output = curl_cmd.args(&curl_args).output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("curl failed ({}): {}", scheme, stderr);
    }

    parse_curl_output(&output.stdout)
}

fn parse_curl_output(stdout: &[u8]) -> Result<HashMap<String, String>> {
    let stdout_str = String::from_utf8_lossy(stdout);
    let mut result = HashMap::new();
    let mut in_headers = true;

    for line in stdout_str.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            if in_headers {
                in_headers = false;
            }
            continue;
        }

        let lower = trimmed.to_lowercase();

        if lower.starts_with("http/") {
            let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                result.insert("http_status".to_string(), parts[1].to_string());
            }
            in_headers = true;
            continue;
        }

        if !in_headers {
            if lower.contains("<title>") && !result.contains_key("title") {
                if let Some(title) = extract_html_title(trimmed) {
                    result.insert("title".to_string(), title);
                }
            }
            continue;
        }

        let header_mappings = [
            ("server:", "server"),
            ("cf-ray:", "cloudflare_ray"),
            ("x-powered-by:", "powered_by"),
            ("x-frame-options:", "x_frame_options"),
            ("strict-transport-security:", "hsts"),
            ("content-security-policy:", "csp"),
            ("set-cookie:", "cookie"),
            ("location:", "location"),
            ("x-content-type-options:", "x_content_type_options"),
            ("referrer-policy:", "referrer_policy"),
            ("permissions-policy:", "permissions_policy"),
            ("alt-svc:", "alt_svc"),
        ];

        for (prefix, key) in header_mappings {
            if let Some(val) = extract_header(trimmed, prefix) {
                result.entry(key.to_string()).or_insert(val);
            }
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

fn extract_html_title(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    if let Some(start) = lower.find("<title>") {
        let rest = &line[start + 7..];
        if let Some(end) = rest.to_lowercase().find("</title>") {
            let title = rest[..end].trim();
            if !title.is_empty() {
                return Some(title.to_string());
            }
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
        port: None,
    };

    let response = super::common::post_json(&url, &json, api_key).await?;
    if !response.status().is_success() {
        anyhow::bail!("server returned {}", response.status());
    }
    Ok(())
}
