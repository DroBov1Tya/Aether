use reqwest::Client;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

const DEFAULT_TESTS: usize = 3;
const LABEL_LEN: usize = 16;
const MAX_CONCURRENCY: usize = 16;
const DOH_TIMEOUT_SECS: u64 = 8;

static RAND_CTR: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default, Clone, Serialize)]
pub struct WildcardRoot {
    pub root: String,
    pub ips: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct WildcardResult {
    pub domain: String,
    pub kept: Vec<String>,
    pub wildcard_roots: Vec<String>,
    pub dropped: usize,
    pub dropped_names: Vec<String>,
    pub candidates: usize,
    pub tests: usize,
    pub roots_detail: Vec<WildcardRoot>,
}

pub async fn filter(
    domain: &str,
    candidates: &[String],
    client: &reqwest::Client,
    tests: usize,
) -> WildcardResult {
    let tests = if tests == 0 { DEFAULT_TESTS } else { tests };
    let domain_norm = match normalize_host(domain) {
        Some(d) => d,
        None => {
            return WildcardResult {
                domain: domain.to_string(),
                tests,
                ..Default::default()
            };
        }
    };
    let dom_suffix = format!(".{}", domain_norm);

    let mut cand_set: BTreeSet<String> = BTreeSet::new();
    for c in candidates {
        if let Some(n) = normalize_host(c) {
            if n == domain_norm || n.ends_with(&dom_suffix) {
                cand_set.insert(n);
            }
        }
    }
    let cands: Vec<String> = cand_set.into_iter().collect();

    if cands.is_empty() {
        return WildcardResult {
            domain: domain_norm,
            tests,
            ..Default::default()
        };
    }

    let mut parents: BTreeSet<String> = BTreeSet::new();
    for c in &cands {
        if let Some(p) = parent_of(c) {
            if p == domain_norm || p.ends_with(&dom_suffix) {
                parents.insert(p);
            }
        }
    }

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENCY));
    let cache: Arc<Mutex<HashMap<String, BTreeSet<String>>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut roots_js: JoinSet<Option<(String, BTreeSet<String>)>> = JoinSet::new();
    for p in parents {
        let client = client.clone();
        let sem = sem.clone();
        let cache = cache.clone();
        let domain_c = domain_norm.clone();
        roots_js.spawn(async move {
            find_wildcard_root(&p, &domain_c, tests, &client, &sem, &cache).await
        });
    }
    let mut roots_map: HashMap<String, BTreeSet<String>> = HashMap::new();
    while let Some(res) = roots_js.join_next().await {
        if let Ok(Some((root, ips))) = res {
            roots_map.entry(root).or_default().extend(ips);
        }
    }

    let mut cand_js: JoinSet<(String, BTreeSet<String>)> = JoinSet::new();
    for c in &cands {
        let name = c.clone();
        let client = client.clone();
        let sem = sem.clone();
        cand_js.spawn(async move {
            let ips = resolve_ips(&name, &client, &sem).await;
            (name, ips)
        });
    }
    let mut cand_ips: HashMap<String, BTreeSet<String>> = HashMap::new();
    while let Some(res) = cand_js.join_next().await {
        if let Ok((name, ips)) = res {
            cand_ips.insert(name, ips);
        }
    }

    let mut roots_sorted: Vec<(String, BTreeSet<String>)> = roots_map.into_iter().collect();
    roots_sorted.sort_by(|a, b| label_count(&b.0).cmp(&label_count(&a.0)).then(a.0.cmp(&b.0)));

    let mut kept = Vec::new();
    let mut dropped_names = Vec::new();
    for c in &cands {
        let ips = cand_ips.get(c).cloned().unwrap_or_default();
        if ips.is_empty() {
            kept.push(c.clone());
            continue;
        }
        let mut is_wild = false;
        for (root, rips) in &roots_sorted {
            let suffix = format!(".{}", root);
            if c.ends_with(&suffix) && !rips.is_empty() && ips.is_subset(rips) {
                dropped_names.push(c.clone());
                is_wild = true;
                break;
            }
        }
        if !is_wild {
            kept.push(c.clone());
        }
    }

    let mut roots_detail: Vec<WildcardRoot> = roots_sorted
        .iter()
        .map(|(r, ips)| WildcardRoot {
            root: r.clone(),
            ips: ips.iter().cloned().collect(),
        })
        .collect();
    roots_detail.sort_by(|a, b| a.root.cmp(&b.root));

    let mut wildcard_roots: Vec<String> =
        roots_sorted.iter().map(|(r, _)| format!("*.{}", r)).collect();
    wildcard_roots.sort();

    WildcardResult {
        domain: domain_norm,
        dropped: dropped_names.len(),
        kept,
        wildcard_roots,
        dropped_names,
        candidates: cands.len(),
        tests,
        roots_detail,
    }
}

async fn find_wildcard_root(
    parent: &str,
    domain: &str,
    tests: usize,
    client: &Client,
    sem: &Semaphore,
    cache: &Mutex<HashMap<String, BTreeSet<String>>>,
) -> Option<(String, BTreeSet<String>)> {
    let mut cur = parent.to_string();
    let mut ips = test_level(&cur, tests, client, sem, cache).await;
    if ips.is_empty() {
        return None;
    }
    let dom_labels = label_count(domain);
    loop {
        if label_count(&cur) <= dom_labels {
            break;
        }
        let gp = match parent_of(&cur) {
            Some(g) => g,
            None => break,
        };
        let gp_ips = test_level(&gp, tests, client, sem, cache).await;
        if gp_ips.is_empty() {
            break;
        }
        if intersects(&ips, &gp_ips) {
            for ip in &gp_ips {
                ips.insert(ip.clone());
            }
            cur = gp;
        } else {
            break;
        }
    }
    Some((cur, ips))
}

async fn test_level(
    level: &str,
    tests: usize,
    client: &Client,
    sem: &Semaphore,
    cache: &Mutex<HashMap<String, BTreeSet<String>>>,
) -> BTreeSet<String> {
    {
        let guard = cache.lock().await;
        if let Some(hit) = guard.get(level) {
            return hit.clone();
        }
    }
    let mut union = BTreeSet::new();
    for _ in 0..tests {
        let fqdn = format!("{}.{}", random_label(LABEL_LEN), level);
        for ip in resolve_ips(&fqdn, client, sem).await {
            union.insert(ip);
        }
    }
    {
        let mut guard = cache.lock().await;
        guard.insert(level.to_string(), union.clone());
    }
    union
}

async fn resolve_ips(fqdn: &str, client: &Client, sem: &Semaphore) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for rtype in ["A", "AAAA"] {
        if let Ok(_permit) = sem.acquire().await {
            if let Some(ips) = doh_query(fqdn, rtype, client).await {
                for ip in ips {
                    out.insert(ip);
                }
            }
        }
    }
    out
}

async fn doh_query(name: &str, rtype: &str, client: &Client) -> Option<Vec<String>> {
    let want: u64 = if rtype == "AAAA" { 28 } else { 1 };
    let google = format!("https://dns.google/resolve?name={}&type={}", name, rtype);
    if let Some(v) = doh_fetch(client, &google, None).await {
        return Some(extract_ips(&v, want));
    }
    let cloudflare = format!(
        "https://cloudflare-dns.com/dns-query?name={}&type={}",
        name, rtype
    );
    if let Some(v) = doh_fetch(client, &cloudflare, Some("application/dns-json")).await {
        return Some(extract_ips(&v, want));
    }
    None
}

async fn doh_fetch(client: &Client, url: &str, accept: Option<&str>) -> Option<serde_json::Value> {
    let mut req = client.get(url).timeout(Duration::from_secs(DOH_TIMEOUT_SECS));
    if let Some(a) = accept {
        req = req.header("accept", a);
    }
    match req.send().await {
        Ok(resp) => resp.json::<serde_json::Value>().await.ok(),
        Err(_) => None,
    }
}

fn extract_ips(v: &serde_json::Value, want_type: u64) -> Vec<String> {
    let mut out = Vec::new();
    if v.get("Status").and_then(|s| s.as_u64()) != Some(0) {
        return out;
    }
    if let Some(ans) = v.get("Answer").and_then(|a| a.as_array()) {
        for rec in ans {
            if rec.get("type").and_then(|x| x.as_u64()) == Some(want_type) {
                if let Some(data) = rec.get("data").and_then(|x| x.as_str()) {
                    let ip = data.trim().trim_end_matches('.').to_ascii_lowercase();
                    if !ip.is_empty() {
                        out.push(ip);
                    }
                }
            }
        }
    }
    out
}

fn normalize_host(h: &str) -> Option<String> {
    let mut s = h.trim().to_ascii_lowercase();
    while let Some(stripped) = s.strip_prefix("*.") {
        s = stripped.to_string();
    }
    let s = s.trim_end_matches('.').trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn parent_of(name: &str) -> Option<String> {
    let idx = name.find('.')?;
    let rest = &name[idx + 1..];
    if rest.contains('.') {
        Some(rest.to_string())
    } else {
        None
    }
}

fn label_count(name: &str) -> usize {
    name.split('.').filter(|s| !s.is_empty()).count()
}

fn intersects(a: &BTreeSet<String>, b: &BTreeSet<String>) -> bool {
    a.iter().any(|x| b.contains(x))
}

fn random_label(n: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    let mut seed = base
        .wrapping_add(RAND_CTR.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed))
        .wrapping_mul(0xd1b5_4a32_d192_ed03);
    if seed == 0 {
        seed = 0x9e37_79b9_7f4a_7c15;
    }
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.push(ALPHABET[(seed % 36) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn diag() {
        async fn probe(label: &str, c: &reqwest::Client, url: &str, json: bool) {
            let mut r = c.get(url).timeout(Duration::from_secs(8));
            if json {
                r = r.header("accept", "application/dns-json");
            }
            match r.send().await {
                Ok(resp) => println!("DIAG {} OK status={}", label, resp.status()),
                Err(e) => println!(
                    "DIAG {} ERR timeout={} connect={} e={}",
                    label,
                    e.is_timeout(),
                    e.is_connect(),
                    e
                ),
            }
        }
        let c = client();
        probe("example-https", &c, "https://www.example.com/", false).await;
        probe("http-plain", &c, "http://1.1.1.1/dns-query?name=example.com&type=A", true).await;
        probe("neverssl-http", &c, "http://neverssl.com/", false).await;
        probe("cf-ip", &c, "https://1.1.1.1/dns-query?name=example.com&type=A", true).await;
    }

    #[tokio::test]
    #[ignore]
    async fn smoke_wildcard() {
        let cands = vec![
            "www.lvh.me".to_string(),
            "app.lvh.me".to_string(),
            "mail.lvh.me".to_string(),
        ];
        let r = filter("lvh.me", &cands, &client(), 3).await;
        println!("WILDCARD {}", serde_json::to_string_pretty(&r).unwrap());
        assert_eq!(r.kept.len(), 0);
        assert_eq!(r.dropped, 3);
        assert!(!r.wildcard_roots.is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn smoke_real() {
        let cands = vec![
            "www.example.com".to_string(),
            "zq8x1k3m9p2w7v4t.example.com".to_string(),
        ];
        let r = filter("example.com", &cands, &client(), 3).await;
        println!("REAL {}", serde_json::to_string_pretty(&r).unwrap());
        assert_eq!(r.dropped, 0);
        assert_eq!(r.kept.len(), 2);
    }
}
