use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, Default, Clone, Serialize)]
pub struct DeepTlsRow {
    pub host: String,
    pub port: String,
    pub versions: Vec<String>,
    pub ciphers: Vec<String>,
    pub weak_ciphers: Vec<String>,
    pub fingerprint_sha256: Option<String>,
    pub serial: Option<String>,
    pub chain_subjects: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FingerprintHash {
    #[serde(default)]
    sha256: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CipherTypes {
    #[serde(default)]
    weak: Vec<String>,
    #[serde(default)]
    insecure: Vec<String>,
    #[serde(default)]
    secure: Vec<String>,
    #[serde(default)]
    unknown: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CipherEnum {
    #[serde(default)]
    ciphers: CipherTypes,
}

#[derive(Debug, Deserialize)]
struct ChainCert {
    #[serde(default)]
    subject_dn: Option<String>,
    #[serde(default)]
    subject_cn: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TlsxLine {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    port: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    subject_dn: Option<String>,
    #[serde(default)]
    subject_cn: Option<String>,
    #[serde(default)]
    tls_version: Option<String>,
    #[serde(default)]
    cipher: Option<String>,
    #[serde(default)]
    version_enum: Vec<String>,
    #[serde(default)]
    cipher_enum: Vec<CipherEnum>,
    #[serde(default)]
    fingerprint_hash: FingerprintHash,
    #[serde(default)]
    chain: Vec<ChainCert>,
}

pub async fn deep_scan(
    targets: &[String],
    timeout_secs: u64,
    proxy: Option<&str>,
) -> Vec<DeepTlsRow> {
    if targets.is_empty() {
        return Vec::new();
    }

    let enum_args = ["-ve", "-ce", "-ct", "all", "-json", "-silent", "-nc"];
    let cert_args = ["-json", "-silent", "-nc", "-tc"];

    let (enum_lines, cert_lines) = tokio::join!(
        run_tlsx(targets, &enum_args, timeout_secs, proxy),
        run_tlsx(targets, &cert_args, timeout_secs, proxy),
    );

    let mut rows: BTreeMap<String, DeepTlsRow> = BTreeMap::new();

    for line in enum_lines {
        let key = match line_key(&line) {
            Some(k) => k,
            None => continue,
        };
        let entry = rows.entry(key.clone()).or_default();
        if entry.host.is_empty() {
            let (host, port) = split_key(&key);
            entry.host = host;
            entry.port = port;
        }
        if !line.version_enum.is_empty() {
            for v in &line.version_enum {
                push_unique(&mut entry.versions, v);
            }
        } else if let Some(v) = line.tls_version.as_deref() {
            if !v.is_empty() {
                push_unique(&mut entry.versions, v);
            }
        }
        if line.cipher_enum.is_empty() {
            if let Some(c) = line.cipher.as_deref() {
                if !c.is_empty() {
                    push_unique(&mut entry.ciphers, c);
                }
            }
        } else {
            for ce in &line.cipher_enum {
                for c in &ce.ciphers.weak {
                    push_unique(&mut entry.ciphers, c);
                    push_unique(&mut entry.weak_ciphers, c);
                }
                for c in &ce.ciphers.insecure {
                    push_unique(&mut entry.ciphers, c);
                    push_unique(&mut entry.weak_ciphers, c);
                }
                for c in &ce.ciphers.secure {
                    push_unique(&mut entry.ciphers, c);
                }
                for c in &ce.ciphers.unknown {
                    push_unique(&mut entry.ciphers, c);
                }
            }
        }
    }

    for line in cert_lines {
        let key = match line_key(&line) {
            Some(k) => k,
            None => continue,
        };
        let entry = rows.entry(key.clone()).or_default();
        if entry.host.is_empty() {
            let (host, port) = split_key(&key);
            entry.host = host;
            entry.port = port;
        }
        if entry.fingerprint_sha256.is_none() {
            if let Some(h) = line.fingerprint_hash.sha256.as_deref() {
                if !h.is_empty() {
                    entry.fingerprint_sha256 = Some(h.to_string());
                }
            }
        }
        if entry.serial.is_none() {
            if let Some(s) = line.serial.as_deref() {
                if !s.is_empty() {
                    entry.serial = Some(s.to_string());
                }
            }
        }
        if entry.chain_subjects.is_empty() {
            for c in &line.chain {
                let subj = c
                    .subject_dn
                    .clone()
                    .filter(|s| !s.is_empty())
                    .or_else(|| c.subject_cn.clone())
                    .unwrap_or_default();
                if !subj.is_empty() {
                    push_unique(&mut entry.chain_subjects, &subj);
                }
            }
            if entry.chain_subjects.is_empty() {
                let subj = line
                    .subject_dn
                    .clone()
                    .filter(|s| !s.is_empty())
                    .or_else(|| line.subject_cn.clone())
                    .unwrap_or_default();
                if !subj.is_empty() {
                    push_unique(&mut entry.chain_subjects, &subj);
                }
            }
        }
    }

    rows.into_values().collect()
}

fn line_key(line: &TlsxLine) -> Option<String> {
    let host = line
        .host
        .clone()
        .filter(|h| !h.is_empty())
        .or_else(|| line.ip.clone())
        .filter(|h| !h.is_empty())?;
    let port = line
        .port
        .clone()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "443".to_string());
    Some(format!("{}:{}", host, port))
}

fn split_key(key: &str) -> (String, String) {
    match key.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.to_string()),
        None => (key.to_string(), "443".to_string()),
    }
}

fn push_unique(list: &mut Vec<String>, item: &str) {
    if !list.iter().any(|x| x == item) {
        list.push(item.to_string());
    }
}

async fn run_tlsx(
    targets: &[String],
    extra_args: &[&str],
    timeout_secs: u64,
    proxy: Option<&str>,
) -> Vec<TlsxLine> {
    let cfg = crate::config::cfg();

    let mut args: Vec<String> = extra_args.iter().map(|s| s.to_string()).collect();
    args.push("-c".into());
    args.push(cfg.tlsx_concurrency.to_string());
    args.push("-timeout".into());
    args.push(cfg.tlsx_timeout.to_string());
    if let Some(proxy) = proxy {
        if !proxy.trim().is_empty() {
            args.push("-proxy".into());
            args.push(proxy.to_string());
        }
    }

    let mut child = match Command::new("tlsx")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                tracing::warn!("deep_tls: tlsx binary not found; skipping deep TLS pass");
            } else {
                tracing::warn!(err = %e, "deep_tls: failed to spawn tlsx");
            }
            return Vec::new();
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let payload = targets.join("\n");
        let _ = stdin.write_all(payload.as_bytes()).await;
        let _ = stdin.write_all(b"\n").await;
        let _ = stdin.shutdown().await;
    }

    let wait = child.wait_with_output();
    let output = match tokio::time::timeout(Duration::from_secs(timeout_secs.max(1)), wait).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            tracing::warn!(err = %e, "deep_tls: tlsx execution failed");
            return Vec::new();
        }
        Err(_) => {
            tracing::warn!(timeout = timeout_secs, "deep_tls: tlsx timed out");
            return Vec::new();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            tracing::warn!(stderr = %stderr.trim(), "deep_tls: tlsx produced no output");
        }
        return Vec::new();
    }

    let mut lines = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<TlsxLine>(line) {
            Ok(parsed) => lines.push(parsed),
            Err(e) => {
                tracing::debug!(err = %e, "deep_tls: unparseable tlsx line");
            }
        }
    }
    lines
}
