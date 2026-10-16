use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

#[derive(Debug, Default, Clone, Serialize)]
pub struct DnsRecords {
    pub name: String,
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub cname: Vec<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
    pub soa: Vec<String>,
    pub caa: Vec<String>,
    pub srv: Vec<String>,
    pub ptr: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct EmailAuth {
    pub domain: String,
    pub spf: Option<String>,
    pub dmarc: Option<String>,
    pub dkim_selectors: Vec<String>,
    pub mta_sts: Option<String>,
    pub mta_sts_policy: Option<String>,
    pub tls_rpt: Option<String>,
    pub bimi: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DohResponse {
    #[serde(default, rename = "Status")]
    status: i32,
    #[serde(default, rename = "Answer")]
    answer: Vec<DohAnswer>,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct DohAnswer {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    rtype: u16,
    #[serde(default, rename = "TTL")]
    ttl: u32,
    #[serde(default)]
    data: String,
}

const GOOGLE_DOH: &str = "https://dns.google/resolve";
const CLOUDFLARE_DOH: &str = "https://cloudflare-dns.com/dns-query";
const QUERY_TIMEOUT: Duration = Duration::from_secs(6);
const POLICY_TIMEOUT: Duration = Duration::from_secs(5);
const FANOUT: usize = 4;

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn doh_get(
    client: &Client,
    endpoint: &str,
    name: &str,
    rtype: &str,
    cloudflare: bool,
) -> Option<Vec<DohAnswer>> {
    let url = format!(
        "{}?name={}&type={}",
        endpoint,
        url_encode(name),
        url_encode(rtype)
    );
    let mut req = client.get(&url).timeout(QUERY_TIMEOUT);
    if cloudflare {
        req = req.header("accept", "application/dns-json");
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(_) => return None,
    };
    if !resp.status().is_success() {
        return None;
    }
    let parsed = resp.json::<DohResponse>().await.ok()?;
    let _ = parsed.status;
    Some(parsed.answer)
}

async fn doh_query(client: &Client, name: &str, rtype: &str) -> Vec<DohAnswer> {
    if let Some(answers) = doh_get(client, GOOGLE_DOH, name, rtype, false).await {
        return answers;
    }
    doh_get(client, CLOUDFLARE_DOH, name, rtype, true)
        .await
        .unwrap_or_default()
}

async fn doh_txt(client: &Client, name: &str) -> Vec<String> {
    answers_to_txt(doh_query(client, name, "TXT").await)
}

fn norm_host(raw: &str) -> String {
    raw.trim()
        .trim_end_matches('.')
        .trim_start_matches("*.")
        .to_ascii_lowercase()
}

fn mx_host(raw: &str) -> Option<String> {
    let host = raw.split_whitespace().last()?;
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host == "." {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn unquote_txt(raw: &str) -> String {
    let trimmed = raw.trim();
    if !trimmed.contains('"') {
        return trimmed.to_string();
    }
    let mut out = String::new();
    let mut in_quote = false;
    let mut chars = trimmed.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_quote = !in_quote,
            '\\' => {
                if let Some(next) = chars.next() {
                    if in_quote {
                        out.push(next);
                    }
                }
            }
            _ => {
                if in_quote {
                    out.push(c);
                }
            }
        }
    }
    out
}

fn dedup(items: &mut Vec<String>) {
    let mut seen = HashSet::new();
    items.retain(|x| !x.is_empty() && seen.insert(x.clone()));
}

fn find_prefixed(txt: &[String], prefix: &str) -> Option<String> {
    txt.iter()
        .find(|t| t.to_ascii_lowercase().starts_with(prefix))
        .cloned()
}

fn find_prefixed_or_first(txt: &[String], prefix: &str) -> Option<String> {
    find_prefixed(txt, prefix).or_else(|| txt.first().cloned())
}

fn ipv4_to_arpa(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for p in &parts {
        let _: u8 = p.parse().ok()?;
    }
    let reversed: Vec<&str> = parts.iter().rev().copied().collect();
    Some(format!("{}.in-addr.arpa", reversed.join(".")))
}

fn apply_answers(rec: &mut DnsRecords, num: u16, answers: Vec<DohAnswer>) {
    for a in answers {
        if a.rtype != num {
            continue;
        }
        let _ = (&a.name, a.ttl);
        match num {
            1 => rec.a.push(a.data.trim().to_string()),
            28 => rec.aaaa.push(a.data.trim().to_ascii_lowercase()),
            5 => rec.cname.push(norm_host(&a.data)),
            15 => {
                if let Some(host) = mx_host(&a.data) {
                    rec.mx.push(host);
                }
            }
            2 => rec.ns.push(norm_host(&a.data)),
            16 => rec.txt.push(unquote_txt(&a.data)),
            6 => rec.soa.push(a.data.trim().to_string()),
            257 => rec.caa.push(a.data.trim().to_string()),
            33 => rec.srv.push(a.data.trim().to_string()),
            _ => {}
        }
    }
}

fn answers_to_txt(answers: Vec<DohAnswer>) -> Vec<String> {
    answers
        .into_iter()
        .filter(|a| a.rtype == 16)
        .map(|a| unquote_txt(&a.data))
        .filter(|t| !t.is_empty())
        .collect()
}

pub async fn resolve(name: &str, client: &reqwest::Client) -> DnsRecords {
    let normalized = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let types: [(&str, u16); 9] = [
        ("A", 1),
        ("AAAA", 28),
        ("CNAME", 5),
        ("MX", 15),
        ("NS", 2),
        ("TXT", 16),
        ("SOA", 6),
        ("CAA", 257),
        ("SRV", 33),
    ];

    let sem = Arc::new(Semaphore::new(FANOUT));
    let mut set: JoinSet<(u16, Vec<DohAnswer>)> = JoinSet::new();
    for (rtype, num) in types {
        let client = client.clone();
        let query = normalized.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire().await.ok();
            let answers = doh_query(&client, &query, rtype).await;
            (num, answers)
        });
    }

    let mut rec = DnsRecords {
        name: normalized.clone(),
        ..Default::default()
    };

    while let Some(joined) = set.join_next().await {
        let (num, answers) = match joined {
            Ok(v) => v,
            Err(_) => continue,
        };
        apply_answers(&mut rec, num, answers);
    }

    dedup(&mut rec.a);
    dedup(&mut rec.aaaa);
    dedup(&mut rec.cname);
    dedup(&mut rec.mx);
    dedup(&mut rec.ns);
    dedup(&mut rec.txt);
    dedup(&mut rec.soa);
    dedup(&mut rec.caa);
    dedup(&mut rec.srv);

    rec
}

pub async fn reverse_ptr(ip: &str, client: &reqwest::Client) -> Vec<String> {
    let arpa = match ipv4_to_arpa(ip) {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut names: Vec<String> = doh_query(client, &arpa, "PTR")
        .await
        .into_iter()
        .filter(|a| a.rtype == 12)
        .map(|a| norm_host(&a.data))
        .collect();
    dedup(&mut names);
    names
}

async fn fetch_mta_sts_policy(client: &Client, domain: &str) -> Option<String> {
    let url = format!("https://mta-sts.{}/.well-known/mta-sts.txt", domain);
    let resp = client.get(&url).timeout(POLICY_TIMEOUT).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(4000).collect())
}

pub async fn email_auth(domain: &str, client: &reqwest::Client) -> EmailAuth {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut out = EmailAuth {
        domain: d.clone(),
        ..Default::default()
    };

    let dmarc_name = format!("_dmarc.{}", d);
    let mta_name = format!("_mta-sts.{}", d);
    let tlsrpt_name = format!("_smtp._tls.{}", d);
    let bimi_name = format!("default._bimi.{}", d);

    let (apex, dmarc_txt, mta_txt, tlsrpt_txt, bimi_txt, policy) = tokio::join!(
        doh_txt(client, &d),
        doh_txt(client, &dmarc_name),
        doh_txt(client, &mta_name),
        doh_txt(client, &tlsrpt_name),
        doh_txt(client, &bimi_name),
        fetch_mta_sts_policy(client, &d),
    );

    out.spf = find_prefixed(&apex, "v=spf1");
    out.dmarc = find_prefixed(&dmarc_txt, "v=dmarc1");
    out.mta_sts = find_prefixed_or_first(&mta_txt, "v=stsv1");
    out.tls_rpt = find_prefixed_or_first(&tlsrpt_txt, "v=tlsrptv1");
    out.bimi = find_prefixed_or_first(&bimi_txt, "v=bimi1");
    out.mta_sts_policy = policy;

    let selectors = [
        "google",
        "default",
        "selector1",
        "selector2",
        "s1",
        "s1024",
        "k1",
        "dkim",
        "mail",
    ];
    let sem = Arc::new(Semaphore::new(FANOUT));
    let mut set: JoinSet<Option<String>> = JoinSet::new();
    for sel in selectors {
        let client = client.clone();
        let sem = sem.clone();
        let fqdn = format!("{}._domainkey.{}", sel, d);
        let label = sel.to_string();
        set.spawn(async move {
            let _permit = sem.acquire().await.ok();
            let records = doh_txt(&client, &fqdn).await;
            let has_key = records.iter().any(|t| {
                let lower = t.to_ascii_lowercase();
                lower.starts_with("v=dkim1") || lower.contains("p=") || lower.contains("k=rsa")
            });
            if has_key {
                Some(label)
            } else {
                None
            }
        });
    }

    let mut found: Vec<String> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(sel)) = joined {
            found.push(sel);
        }
    }
    found.sort();
    found.dedup();
    out.dkim_selectors = found;

    out
}
