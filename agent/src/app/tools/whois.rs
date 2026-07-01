use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct WhoisResult {
    pub target: String,
    pub raw: String,
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub name_servers: Vec<String>,
    pub organization: Option<String>,
    pub country: Option<String>,
    pub emails: Vec<String>,
}

pub async fn run_whois(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    api_key: &str,
) -> Result<()> {
    let output = Command::new("whois").arg(target).output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("whois failed: {stderr}");
    }

    let raw = String::from_utf8_lossy(&output.stdout).to_string();

    let result = WhoisResult {
        target: target.to_string(),
        registrar: extract_field(&raw, "Registrar:"),
        creation_date: extract_field(&raw, "Creation Date:")
            .or_else(|| extract_field(&raw, "created:"))
            .or_else(|| extract_field(&raw, "Domain Registration Date:")),
        expiration_date: extract_field(&raw, "Registry Expiry Date:")
            .or_else(|| extract_field(&raw, "Expiration Date:"))
            .or_else(|| extract_field(&raw, "expire:")),
        name_servers: extract_lines(&raw, &["Name Server:", "nserver:"], 10),
        organization: extract_field(&raw, "Organization:")
            .or_else(|| extract_field(&raw, "org-name:"))
            .or_else(|| extract_field(&raw, "descr:")),
        country: extract_field(&raw, "Country:")
            .or_else(|| extract_field(&raw, "country:"))
            .or_else(|| extract_field(&raw, "Registrant Country:")),
        emails: extract_lines(&raw, &["Registrant Email:", "e-mail:", "Email:"], 5),
        raw,
    };

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

fn extract_field(raw: &str, prefix: &str) -> Option<String> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix(prefix) {
            let val = val.trim().trim_matches('"').to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

fn extract_lines(raw: &str, prefixes: &[&str], max: usize) -> Vec<String> {
    let mut results = Vec::new();
    for line in raw.lines() {
        if results.len() >= max {
            break;
        }
        let trimmed = line.trim();
        for prefix in prefixes {
            if let Some(val) = trimmed.strip_prefix(prefix) {
                let val = val.trim().trim_matches('"').to_string();
                if !val.is_empty() && !results.contains(&val) {
                    results.push(val);
                }
                break;
            }
        }
    }
    results
}

async fn send_to_server(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    result: &WhoisResult,
    api_key: &str,
) -> Result<()> {
    let url = format!("{}/api/checkout/whois", external_server_path);
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
