use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsResult {
    pub target: String,
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub cname: Vec<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
    pub ptr: Vec<String>,
}

pub async fn run_dns(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    api_key: &str,
) -> Result<()> {
    let mut result = DnsResult {
        target: target.to_string(),
        a: Vec::new(),
        aaaa: Vec::new(),
        cname: Vec::new(),
        mx: Vec::new(),
        ns: Vec::new(),
        txt: Vec::new(),
        ptr: Vec::new(),
    };

    let forward_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"];
    for rtype in &forward_types {
        let output = Command::new("dig")
            .args(["+short", &format!("-t{}", rtype), target])
            .output()
            .await;

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with(';') {
                    continue;
                }
                match *rtype {
                    "A" => result.a.push(line.to_string()),
                    "AAAA" => result.aaaa.push(line.to_string()),
                    "CNAME" => result.cname.push(line.trim_end_matches('.').to_string()),
                    "MX" => result.mx.push(line.to_string()),
                    "NS" => result.ns.push(line.trim_end_matches('.').to_string()),
                    "TXT" => result.txt.push(line.to_string()),
                    _ => {}
                }
            }
        }
    }

    if target.contains('.') && !target.chars().any(|c| c.is_alphabetic()) {
        let output = Command::new("dig")
            .args(["+short", "-x", target])
            .output()
            .await;

        if let Ok(out) = output {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let line = line.trim().trim_end_matches('.');
                if !line.is_empty() && !line.starts_with(';') {
                    result.ptr.push(line.to_string());
                }
            }
        }
    }

    tracing::info!(
        "dns   {}  a={} aaaa={} cname={} mx={} ns={} txt={} ptr={}",
        target,
        result.a.len(),
        result.aaaa.len(),
        result.cname.len(),
        result.mx.len(),
        result.ns.len(),
        result.txt.len(),
        result.ptr.len(),
    );

    send_to_server(
        external_server_path,
        target,
        scan_uid,
        task_uid,
        &result,
        api_key,
    )
    .await?;

    Ok(())
}

async fn send_to_server(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    result: &DnsResult,
    api_key: &str,
) -> Result<()> {
    let url = format!("{}/api/checkout/dns", external_server_path);
    let body = serde_json::to_string(result)?;

    let country = super::common::lookup_country(target).await;
    let req = super::common::ExternalReq {
        status: "complete".to_string(),
        target: target.to_string(),
        body,
        version: crate::config::VERSION,
        scan_uid: scan_uid.to_string(),
        task_uid: task_uid.map(String::from),
        country,
        port: None,
    };

    super::common::post_json(&url, &req, api_key).await?;
    Ok(())
}
