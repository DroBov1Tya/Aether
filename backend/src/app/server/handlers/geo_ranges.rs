use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinSet;

use crate::app::AppState;

const CACHE_TTL: Duration = Duration::from_secs(6 * 3600);
const RIPE_BASE: &str = "https://stat.ripe.net/data";

type CountryCache = HashMap<String, (Instant, Vec<u32>)>;

fn cache() -> &'static RwLock<CountryCache> {
    static C: OnceLock<RwLock<CountryCache>> = OnceLock::new();
    C.get_or_init(|| RwLock::new(HashMap::new()))
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .user_agent("aether-recon")
        .build()
        .unwrap_or_default()
}

fn parse_asn_list(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            cur.push(ch);
        } else if !cur.is_empty() {
            if let Ok(n) = cur.parse::<u32>() {
                out.push(n);
            }
            cur.clear();
        }
    }
    if !cur.is_empty() {
        if let Ok(n) = cur.parse::<u32>() {
            out.push(n);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

async fn country_asns(cc: &str) -> anyhow::Result<Vec<u32>> {
    if let Some((at, list)) = cache().read().await.get(cc) {
        if at.elapsed() < CACHE_TTL {
            return Ok(list.clone());
        }
    }
    let url = format!("{RIPE_BASE}/country-asns/data.json?resource={cc}&lod=1");
    let body: Value = http().get(&url).send().await?.json().await?;
    let mut asns = Vec::new();
    if let Some(countries) = body
        .get("data")
        .and_then(|d| d.get("countries"))
        .and_then(|c| c.as_array())
    {
        for c in countries {
            if let Some(routed) = c.get("routed").and_then(|v| v.as_str()) {
                asns.extend(parse_asn_list(routed));
            }
        }
    }
    asns.sort_unstable();
    asns.dedup();
    cache()
        .write()
        .await
        .insert(cc.to_string(), (Instant::now(), asns.clone()));
    Ok(asns)
}

async fn asn_holder(asn: u32) -> Option<String> {
    let url = format!("{RIPE_BASE}/as-overview/data.json?resource=AS{asn}");
    let body: Value = http().get(&url).send().await.ok()?.json().await.ok()?;
    body.get("data")
        .and_then(|d| d.get("holder"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

async fn asn_prefixes(asn: u32) -> Vec<String> {
    let url = format!("{RIPE_BASE}/announced-prefixes/data.json?resource=AS{asn}");
    let body: Value = match http().get(&url).send().await {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        },
        Err(_) => return Vec::new(),
    };
    body.get("data")
        .and_then(|d| d.get("prefixes"))
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("prefix").and_then(|v| v.as_str()))
                .filter(|p| p.contains('.'))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Deserialize)]
pub struct CountryQuery {
    pub country: String,
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub page: Option<usize>,
    #[serde(default)]
    pub size: Option<usize>,
}

pub async fn list_country_asns(
    State(_state): State<Arc<AppState>>,
    Query(q): Query<CountryQuery>,
) -> impl IntoResponse {
    let cc: String = q
        .country
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .take(2)
        .collect::<String>()
        .to_lowercase();
    if cc.len() != 2 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "country must be a 2-letter ISO code" })),
        );
    }

    let all = match country_asns(&cc).await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("country-asns {cc} error: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "status": "error", "error": e.to_string() })),
            );
        }
    };

    let filtered: Vec<u32> = match q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(needle) => all
            .into_iter()
            .filter(|n| n.to_string().contains(needle))
            .collect(),
        None => all,
    };

    let total = filtered.len();
    let size = q.size.unwrap_or(40).clamp(1, 100);
    let page = q.page.unwrap_or(0);
    let start = page.saturating_mul(size).min(total);
    let end = (start + size).min(total);
    let slice = &filtered[start..end];

    let mut set = JoinSet::new();
    for &asn in slice {
        set.spawn(async move { (asn, asn_holder(asn).await) });
    }
    let mut holders: HashMap<u32, String> = HashMap::new();
    while let Some(res) = set.join_next().await {
        if let Ok((asn, Some(h))) = res {
            holders.insert(asn, h);
        }
    }

    let asns: Vec<Value> = slice
        .iter()
        .map(|&asn| {
            json!({
                "asn": asn,
                "holder": holders.get(&asn).cloned().unwrap_or_default(),
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "country": cc,
            "total": total,
            "page": page,
            "size": size,
            "asns": asns,
        })),
    )
}

#[derive(Deserialize)]
pub struct PrefixQuery {
    pub asns: String,
}

pub async fn list_asn_prefixes(
    State(_state): State<Arc<AppState>>,
    Query(q): Query<PrefixQuery>,
) -> impl IntoResponse {
    let ids: Vec<u32> = q
        .asns
        .split(',')
        .filter_map(|s| s.trim().trim_start_matches(['A', 'S', 'a', 's']).parse::<u32>().ok())
        .take(50)
        .collect();

    if ids.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "no valid ASNs" })),
        );
    }

    let mut set = JoinSet::new();
    for asn in ids {
        set.spawn(async move { (asn, asn_prefixes(asn).await) });
    }
    let mut per_asn: Vec<Value> = Vec::new();
    let mut all_cidrs: Vec<String> = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok((asn, cidrs)) = res {
            all_cidrs.extend(cidrs.iter().cloned());
            per_asn.push(json!({ "asn": asn, "cidrs": cidrs }));
        }
    }
    all_cidrs.sort();
    all_cidrs.dedup();

    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "count": all_cidrs.len(),
            "cidrs": all_cidrs,
            "per_asn": per_asn,
        })),
    )
}
