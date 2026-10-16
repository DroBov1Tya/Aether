use anyhow::Result;
use std::time::Duration;
use tokio::process::Command;

use super::sink::{Sink, Stage};

#[tracing::instrument(name = "rustscan", skip_all, fields(target = target))]
pub async fn run_rustscan(
    sink: &Sink,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    port_range: Option<&str>,
    threads: Option<u32>,
    timeout_ms: Option<u64>,
    proxy: Option<&str>,
    cooldown_secs: u64,
) -> Result<Vec<i64>> {
    let mut cmd = Command::new("rustscan");
    super::common::apply_proxy_with(&mut cmd, proxy);

    let mut args: Vec<String> = vec!["--greppable".to_string()];
    if let Some((s, e)) = target.split_once('-') {
        if let (Ok(a), Ok(b)) = (s.parse::<std::net::Ipv4Addr>(), e.parse::<std::net::Ipv4Addr>()) {
            let [o1, o2, o3, o4] = a.octets();
            let [p1, p2, p3, p4] = b.octets();
            let (start, end) = (
                ((o1 as u32) << 24) | ((o2 as u32) << 16) | ((o3 as u32) << 8) | o4 as u32,
                ((p1 as u32) << 24) | ((p2 as u32) << 16) | ((p3 as u32) << 8) | p4 as u32,
            );
            for n in start..=end {
                args.push("-a".to_string());
                args.push(std::net::Ipv4Addr::from(n).to_string());
            }
        } else {
            args.push("-a".to_string());
            args.push(target.to_string());
        }
    } else {
        args.push("-a".to_string());
        args.push(target.to_string());
    }
    if let Some(range) = port_range.filter(|r| !r.trim().is_empty()) {
        let r = range.trim();
        if r.contains('-') && !r.contains(',') {
            args.push("-r".to_string());
            args.push(r.to_string());
        } else {
            args.push("-p".to_string());
            args.push(r.to_string());
        }
    }
    let max_batch = crate::config::cfg().rustscan_max_batch.max(1);
    let batch = threads.unwrap_or(max_batch).min(max_batch);
    args.push("-b".to_string());
    args.push(batch.to_string());
    if let Some(ms) = timeout_ms {
        args.push("-t".to_string());
        args.push(ms.to_string());
    }
    cmd.args(args);

    let output = cmd.output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("rustscan failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let ports = parse_ports(&stdout)?;

    if let Err(e) = send_result(sink, target, scan_uid, task_uid, &ports).await {
        tracing::warn!(error = %e, "Failed to report scan results");
    }

    if cooldown_secs > 0 {
        tracing::info!("Cooldown {}s", cooldown_secs);
        tokio::time::sleep(Duration::from_secs(cooldown_secs)).await;
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
    sink: &Sink,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    ports: &[i64],
) -> Result<()> {
    let country = super::common::lookup_country(target).await;
    let req = super::common::ExternalReq {
        status: "complete".to_string(),
        target: target.to_string(),
        body: serde_json::to_string(ports)?,
        version: crate::config::VERSION,
        scan_uid: scan_uid.to_string(),
        task_uid: task_uid.map(String::from),
        country,
        port: None,
    };
    sink.emit(Stage::Rustscan, req).await
}
