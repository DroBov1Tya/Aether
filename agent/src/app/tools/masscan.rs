use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;
use tokio::{fs, process::Command};

#[tracing::instrument(name = "masscan", skip_all, fields(target = target))]
pub async fn run_masscan(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    ports: &str,
    max_rate: u32,
    scans_output_path: &str,
    api_key: &str,
) -> Result<BTreeMap<String, Vec<i64>>> {
    let out_dir = Path::new(scans_output_path);
    fs::create_dir_all(out_dir).await?;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let safe_target: String = target
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let out_path = format!("{}/masscan_{}_{}_{}.json", scans_output_path, scan_uid, safe_target, nanos);

    let port_arg = format!("-p{}", ports);
    let rate_arg = format!("--rate={}", max_rate.max(1));

    let mut cmd = Command::new("masscan");
    cmd.arg(target)
        .arg(&port_arg)
        .arg(&rate_arg)
        .arg("--wait")
        .arg("0")
        .arg("-oJ")
        .arg(&out_path);

    let extra = crate::config::cfg().masscan_extra_args.clone();
    for a in extra.split_whitespace() {
        cmd.arg(a);
    }

    tracing::debug!(target, ports, max_rate, "starting masscan");

    let output = cmd.output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let _ = fs::remove_file(&out_path).await;
        anyhow::bail!("masscan failed: {stderr}");
    }

    let raw = fs::read_to_string(&out_path).await.unwrap_or_default();
    let _ = fs::remove_file(&out_path).await;

    let host_ports = parse_masscan_json(&raw);

    for (host, plist) in &host_ports {
        if let Err(e) = send_result(external_server_path, host, scan_uid, task_uid, plist, api_key).await {
            tracing::warn!(host, error = %e, "failed to report masscan result");
        }
    }

    Ok(host_ports)
}

fn parse_masscan_json(raw: &str) -> BTreeMap<String, Vec<i64>> {
    let mut map: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for line in raw.lines() {
        let t = line.trim().trim_end_matches(',');
        if !t.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(t) else {
            continue;
        };
        let Some(ip) = v["ip"].as_str() else { continue };
        let Some(ports) = v["ports"].as_array() else { continue };
        for p in ports {
            let is_open = p["status"].as_str().map(|s| s == "open").unwrap_or(true);
            if !is_open {
                continue;
            }
            if let Some(port) = p["port"].as_i64() {
                map.entry(ip.to_string()).or_default().push(port);
            }
        }
    }
    for plist in map.values_mut() {
        plist.sort_unstable();
        plist.dedup();
    }
    map
}

async fn send_result(
    external_server_path: &str,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    ports: &[i64],
    api_key: &str,
) -> Result<()> {
    let url = format!("{}/api/checkout/masscan", external_server_path);
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
