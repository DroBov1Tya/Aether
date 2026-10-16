use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const UA: &str = "Mozilla/5.0 (compatible; Aether-Recon/0.2; +https://github.com/)";
const MAX_CONCURRENCY: usize = 5;

#[derive(Debug, Default, Clone)]
pub struct PassiveKeys {
    pub otx: Option<String>,
    pub certspotter: Option<String>,
    pub virustotal: Option<String>,
    pub securitytrails: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SourceHit {
    pub source: String,
    pub count: usize,
    pub error: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct PassiveResult {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub sources: Vec<SourceHit>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct InternetDbResult {
    pub ip: String,
    pub ports: Vec<i64>,
    pub hostnames: Vec<String>,
    pub cpes: Vec<String>,
    pub vulns: Vec<String>,
    pub tags: Vec<String>,
}

pub async fn enumerate(
    domain: &str,
    keys: &PassiveKeys,
    timeout_secs: u64,
    client: &reqwest::Client,
) -> PassiveResult {
    let domain = domain.trim().trim_matches('.').to_lowercase();
    if domain.is_empty() {
        return PassiveResult {
            domain,
            ..Default::default()
        };
    }

    let dur = Duration::from_secs(timeout_secs.max(1));
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENCY));
    let mut set: JoinSet<(SourceHit, Vec<String>)> = JoinSet::new();

    {
        let c = client.clone();
        let d = domain.clone();
        let s = sem.clone();
        set.spawn(async move {
            let _permit = s.acquire().await;
            let r = tokio::time::timeout(dur, fetch_crtsh(&c, &d)).await;
            finish("crtsh", &d, r)
        });
    }
    {
        let c = client.clone();
        let d = domain.clone();
        let s = sem.clone();
        let k = keys.certspotter.clone();
        set.spawn(async move {
            let _permit = s.acquire().await;
            let r = tokio::time::timeout(dur, fetch_certspotter(&c, &d, k)).await;
            finish("certspotter", &d, r)
        });
    }
    {
        let c = client.clone();
        let d = domain.clone();
        let s = sem.clone();
        let k = keys.otx.clone();
        set.spawn(async move {
            let _permit = s.acquire().await;
            let r = tokio::time::timeout(dur, fetch_otx(&c, &d, k)).await;
            finish("alienvault", &d, r)
        });
    }
    {
        let c = client.clone();
        let d = domain.clone();
        let s = sem.clone();
        set.spawn(async move {
            let _permit = s.acquire().await;
            let r = tokio::time::timeout(dur, fetch_anubis(&c, &d)).await;
            finish("anubisdb", &d, r)
        });
    }
    {
        let c = client.clone();
        let d = domain.clone();
        let s = sem.clone();
        set.spawn(async move {
            let _permit = s.acquire().await;
            let r = tokio::time::timeout(dur, fetch_hackertarget(&c, &d)).await;
            finish("hackertarget", &d, r)
        });
    }
    {
        let c = client.clone();
        let d = domain.clone();
        let s = sem.clone();
        set.spawn(async move {
            let _permit = s.acquire().await;
            let r = tokio::time::timeout(dur, fetch_rapiddns(&c, &d)).await;
            finish("rapiddns", &d, r)
        });
    }
    {
        let c = client.clone();
        let d = domain.clone();
        let s = sem.clone();
        set.spawn(async move {
            let _permit = s.acquire().await;
            let r = tokio::time::timeout(dur, fetch_wayback(&c, &d)).await;
            finish("wayback", &d, r)
        });
    }

    if let Some(k) = keys.virustotal.clone() {
        let c = client.clone();
        let d = domain.clone();
        let s = sem.clone();
        set.spawn(async move {
            let _permit = s.acquire().await;
            let r = tokio::time::timeout(dur, fetch_virustotal(&c, &d, &k)).await;
            finish("virustotal", &d, r)
        });
    }
    if let Some(k) = keys.securitytrails.clone() {
        let c = client.clone();
        let d = domain.clone();
        let s = sem.clone();
        set.spawn(async move {
            let _permit = s.acquire().await;
            let r = tokio::time::timeout(dur, fetch_securitytrails(&c, &d, &k)).await;
            finish("securitytrails", &d, r)
        });
    }

    let mut sources: Vec<SourceHit> = Vec::new();
    let mut merged: BTreeSet<String> = BTreeSet::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((hit, names)) = joined {
            for n in names {
                merged.insert(n);
            }
            sources.push(hit);
        }
    }
    sources.sort_by(|a, b| a.source.cmp(&b.source));

    let subdomains: Vec<String> = merged.into_iter().collect();
    tracing::info!(
        domain = %domain,
        subdomains = subdomains.len(),
        sources = sources.len(),
        "passive subdomain enumeration complete"
    );
    PassiveResult {
        domain,
        subdomains,
        sources,
    }
}

pub async fn internetdb(ip: &str, client: &reqwest::Client) -> Option<InternetDbResult> {
    let ip = ip.trim();
    if ip.is_empty() {
        return None;
    }
    let url = format!("https://internetdb.shodan.io/{}", ip);
    let resp = client.get(&url).header("User-Agent", UA).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: serde_json::Value = resp.json().await.ok()?;
    Some(InternetDbResult {
        ip: ip.to_string(),
        ports: json_i64_array(&v, "ports"),
        hostnames: json_str_array(&v, "hostnames"),
        cpes: json_str_array(&v, "cpes"),
        vulns: json_str_array(&v, "vulns"),
        tags: json_str_array(&v, "tags"),
    })
}

fn finish(
    name: &str,
    domain: &str,
    res: Result<Result<Vec<String>>, tokio::time::error::Elapsed>,
) -> (SourceHit, Vec<String>) {
    match res {
        Ok(Ok(raws)) => {
            let unique: BTreeSet<String> =
                raws.iter().filter_map(|r| normalize(r, domain)).collect();
            let names: Vec<String> = unique.into_iter().collect();
            let hit = SourceHit {
                source: name.to_string(),
                count: names.len(),
                error: None,
            };
            (hit, names)
        }
        Ok(Err(e)) => (
            SourceHit {
                source: name.to_string(),
                count: 0,
                error: Some(e.to_string()),
            },
            Vec::new(),
        ),
        Err(_) => (
            SourceHit {
                source: name.to_string(),
                count: 0,
                error: Some("timeout".to_string()),
            },
            Vec::new(),
        ),
    }
}

fn normalize(raw: &str, domain: &str) -> Option<String> {
    let mut s = raw.trim().to_lowercase();
    if let Some(rest) = s.strip_prefix("*.") {
        s = rest.to_string();
    }
    let s = s.trim_matches('.').to_string();
    if s.is_empty() {
        return None;
    }
    let valid = s.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_'
    });
    if !valid {
        return None;
    }
    let suffix = format!(".{}", domain);
    if s == domain || s.ends_with(&suffix) {
        Some(s)
    } else {
        None
    }
}

fn is_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'*'
}

fn is_continue_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'.'
}

fn extract_hostnames(body: &str, domain: &str) -> Vec<String> {
    let lower = body.to_lowercase();
    let lbytes = lower.as_bytes();
    let dlen = domain.len();
    let mut out: Vec<String> = Vec::new();
    let mut search = 0usize;
    while search <= lower.len() {
        let rel = match lower[search..].find(domain) {
            Some(r) => r,
            None => break,
        };
        let pos = search + rel;
        let end = pos + dlen;
        let next_is_continue = end < lbytes.len() && is_continue_byte(lbytes[end]);
        if !next_is_continue {
            let mut start = pos;
            while start > 0 && is_label_byte(lbytes[start - 1]) {
                start -= 1;
            }
            out.push(lower[start..end].to_string());
        }
        search = pos + 1;
    }
    out
}

fn json_str_array(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn json_i64_array(v: &serde_json::Value, key: &str) -> Vec<i64> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_i64()).collect())
        .unwrap_or_default()
}

async fn fetch_crtsh(client: &Client, domain: &str) -> Result<Vec<String>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let resp = client.get(&url).header("User-Agent", UA).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("http {}", status);
    }
    let arr: Vec<serde_json::Value> = serde_json::from_str(&text)?;
    let mut out: Vec<String> = Vec::new();
    for item in &arr {
        if let Some(nv) = item.get("name_value").and_then(|v| v.as_str()) {
            for line in nv.split('\n') {
                out.push(line.to_string());
            }
        }
        if let Some(cn) = item.get("common_name").and_then(|v| v.as_str()) {
            out.push(cn.to_string());
        }
    }
    Ok(out)
}

async fn fetch_certspotter(
    client: &Client,
    domain: &str,
    key: Option<String>,
) -> Result<Vec<String>> {
    let url = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        domain
    );
    let mut req = client.get(&url).header("User-Agent", UA);
    if let Some(k) = key {
        if !k.trim().is_empty() {
            req = req.header("Authorization", format!("Bearer {}", k));
        }
    }
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("http {}", status);
    }
    let arr: Vec<serde_json::Value> = serde_json::from_str(&text)?;
    let mut out: Vec<String> = Vec::new();
    for item in &arr {
        if let Some(names) = item.get("dns_names").and_then(|v| v.as_array()) {
            for n in names {
                if let Some(s) = n.as_str() {
                    out.push(s.to_string());
                }
            }
        }
    }
    Ok(out)
}

async fn fetch_otx(client: &Client, domain: &str, key: Option<String>) -> Result<Vec<String>> {
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
        domain
    );
    let mut req = client.get(&url).header("User-Agent", UA);
    if let Some(k) = key {
        if !k.trim().is_empty() {
            req = req.header("X-OTX-API-KEY", k);
        }
    }
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("http {}", status);
    }
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let mut out: Vec<String> = Vec::new();
    if let Some(arr) = v.get("passive_dns").and_then(|x| x.as_array()) {
        for e in arr {
            if let Some(h) = e.get("hostname").and_then(|x| x.as_str()) {
                out.push(h.to_string());
            }
        }
    }
    Ok(out)
}

async fn fetch_anubis(client: &Client, domain: &str) -> Result<Vec<String>> {
    let url = format!("https://anubisdb.com/anubis/subdomains/{}", domain);
    let resp = client.get(&url).header("User-Agent", UA).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("http {}", status);
    }
    let arr: Vec<String> = serde_json::from_str(&text)?;
    Ok(arr)
}

async fn fetch_hackertarget(client: &Client, domain: &str) -> Result<Vec<String>> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    let resp = client.get(&url).header("User-Agent", UA).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("http {}", status);
    }
    let lower = text.to_lowercase();
    if lower.contains("api count exceeded")
        || lower.contains("increase quota")
        || lower.starts_with("error")
    {
        anyhow::bail!("rate limited");
    }
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some((host, _ip)) = line.split_once(',') {
            let host = host.trim();
            if !host.is_empty() {
                out.push(host.to_string());
            }
        }
    }
    Ok(out)
}

async fn fetch_rapiddns(client: &Client, domain: &str) -> Result<Vec<String>> {
    let url = format!("https://rapiddns.io/subdomain/{}?full=1", domain);
    let resp = client.get(&url).header("User-Agent", UA).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("http {}", status);
    }
    Ok(extract_hostnames(&text, domain))
}

async fn fetch_wayback(client: &Client, domain: &str) -> Result<Vec<String>> {
    let url = format!(
        "http://web.archive.org/cdx/search/cdx?url=*.{}&output=txt&fl=original&collapse=urlkey&matchType=domain",
        domain
    );
    let resp = client.get(&url).header("User-Agent", UA).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("http {}", status);
    }
    Ok(extract_hostnames(&text, domain))
}

async fn fetch_virustotal(client: &Client, domain: &str, key: &str) -> Result<Vec<String>> {
    let url = format!(
        "https://www.virustotal.com/api/v3/domains/{}/subdomains?limit=40",
        domain
    );
    let resp = client
        .get(&url)
        .header("User-Agent", UA)
        .header("x-apikey", key)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("http {}", status);
    }
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let mut out: Vec<String> = Vec::new();
    if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
        for e in arr {
            if let Some(id) = e.get("id").and_then(|x| x.as_str()) {
                out.push(id.to_string());
            }
        }
    }
    Ok(out)
}

async fn fetch_securitytrails(client: &Client, domain: &str, key: &str) -> Result<Vec<String>> {
    let url = format!(
        "https://api.securitytrails.com/v1/domain/{}/subdomains?children_only=false",
        domain
    );
    let resp = client
        .get(&url)
        .header("User-Agent", UA)
        .header("APIKEY", key)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("http {}", status);
    }
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let mut out: Vec<String> = Vec::new();
    if let Some(arr) = v.get("subdomains").and_then(|x| x.as_array()) {
        for e in arr {
            if let Some(pre) = e.as_str() {
                out.push(format!("{}.{}", pre, domain));
            }
        }
    }
    Ok(out)
}
