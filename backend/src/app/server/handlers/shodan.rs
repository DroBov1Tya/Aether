use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::import;

const SHODAN_BASE: &str = "https://api.shodan.io";

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("aether-recon")
        .build()
        .unwrap_or_default()
}

fn key_or_err(state: &Arc<AppState>) -> Result<String, (StatusCode, Json<Value>)> {
    let k = state.cfg.shodan_api_key.trim();
    if k.is_empty() {
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "SHODAN_API_KEY not configured on the server" })),
        ))
    } else {
        Ok(k.to_string())
    }
}

pub async fn api_info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let key = match key_or_err(&state) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let url = format!("{SHODAN_BASE}/api-info?key={key}");
    match http().get(&url).send().await {
        Ok(r) => {
            let status = r.status();
            let body: Value = r.json().await.unwrap_or_else(|_| json!({}));
            if status.is_success() {
                (StatusCode::OK, Json(json!({ "status": "ok", "info": body })))
            } else {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "status": "error",
                        "error": body.get("error").and_then(|v| v.as_str()).unwrap_or("shodan api-info failed"),
                    })),
                )
            }
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}

fn as_u16(v: &Value, k: &str) -> Option<u16> {
    v.get(k).and_then(|x| x.as_u64()).map(|n| n as u16)
}

fn norm_host(m: &Value) -> Option<Value> {
    let ip = m
        .get("ip_str")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| m.get("ip").and_then(|v| v.as_u64()).map(|n| {
            format!(
                "{}.{}.{}.{}",
                (n >> 24) & 255,
                (n >> 16) & 255,
                (n >> 8) & 255,
                n & 255
            )
        }))?;

    let port = as_u16(m, "port").unwrap_or(0);
    let transport = m
        .get("transport")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp")
        .to_string();
    let product = m.get("product").and_then(|v| v.as_str()).map(String::from);
    let version = m.get("version").and_then(|v| v.as_str()).map(String::from);

    let mut port_obj = json!({ "port": port, "protocol": transport });
    if let Some(p) = &product {
        port_obj["service"] = json!(p);
        port_obj["product"] = json!(p);
    }
    if let Some(v) = &version {
        port_obj["version"] = json!(v);
    }

    let mut host = json!({ "target": ip, "ports": [port_obj] });

    let loc = m.get("location");
    let country = loc
        .and_then(|l| l.get("country_name"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let country_code = loc
        .and_then(|l| l.get("country_code"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let city = loc
        .and_then(|l| l.get("city"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let lat = loc.and_then(|l| l.get("latitude")).and_then(|v| v.as_f64());
    let lon = loc.and_then(|l| l.get("longitude")).and_then(|v| v.as_f64());
    let asn = m.get("asn").and_then(|v| v.as_str()).map(String::from);
    let org = m.get("org").and_then(|v| v.as_str()).map(String::from);
    let isp = m.get("isp").and_then(|v| v.as_str()).map(String::from);

    if country.is_some() || asn.is_some() || org.is_some() {
        host["geo"] = json!({
            "country": country.unwrap_or_default(),
            "country_code": country_code.unwrap_or_default(),
            "city": city.unwrap_or_default(),
            "lat": lat.unwrap_or(0.0),
            "lon": lon.unwrap_or(0.0),
            "asn": asn.unwrap_or_default(),
            "org": org.unwrap_or_default(),
            "isp": isp.unwrap_or_default(),
        });
    }
    if let Some(country_code) = host
        .get("geo")
        .and_then(|g| g.get("country_code"))
        .and_then(|v| v.as_str())
        .map(String::from)
    {
        if !country_code.is_empty() {
            host["country"] = json!(country_code);
        }
    }

    let hostnames = m
        .get("hostnames")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    if let Some(http_obj) = m.get("http") {
        let mut h = json!({ "port": port });
        if let Some(t) = http_obj.get("title").and_then(|v| v.as_str()) {
            h["title"] = json!(t);
        }
        if let Some(s) = http_obj.get("server").and_then(|v| v.as_str()) {
            h["webserver"] = json!(s);
        }
        let scheme = if port == 443 { "https" } else { "http" };
        h["url"] = json!(format!("{scheme}://{ip}:{port}"));
        host["http"] = h;
    }

    if let Some(ssl) = m.get("ssl") {
        let cert = ssl.get("cert");
        let mut san: Vec<String> = Vec::new();
        if let Some(exts) = cert
            .and_then(|c| c.get("extensions"))
            .and_then(|e| e.as_array())
        {
            for ext in exts {
                if ext.get("name").and_then(|v| v.as_str()) == Some("subjectAltName") {
                    if let Some(data) = ext.get("data").and_then(|v| v.as_str()) {
                        san.extend(data.split(',').map(|s| s.trim().to_string()));
                    }
                }
            }
        }
        host["tls"] = json!({
            "port": port,
            "subject": cert.and_then(|c| c.get("subject")).and_then(|s| s.get("CN")).and_then(|v| v.as_str()).unwrap_or(""),
            "issuer": cert.and_then(|c| c.get("issuer")).and_then(|s| s.get("CN")).and_then(|v| v.as_str()).unwrap_or(""),
            "san": san,
        });
    }

    if !hostnames.is_empty() {
        host["dns"] = json!({ "ptr": hostnames });
    }

    Some(host)
}

#[derive(Deserialize)]
pub struct SearchQuery {
    pub query: String,
    #[serde(default)]
    pub page: Option<u32>,
}

pub async fn search(
    State(state): State<Arc<AppState>>,
    Query(q): Query<SearchQuery>,
) -> impl IntoResponse {
    let key = match key_or_err(&state) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let query = q.query.trim();
    if query.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "empty query" })),
        );
    }
    let page = q.page.unwrap_or(1).max(1);
    let encoded = urlencode(query);
    let url = format!("{SHODAN_BASE}/shodan/host/search?key={key}&query={encoded}&page={page}");

    let resp = match http().get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "status": "error", "error": e.to_string() })),
            );
        }
    };
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "status": "error",
                "error": body.get("error").and_then(|v| v.as_str()).unwrap_or("shodan search failed"),
            })),
        );
    }

    let matches = body.get("matches").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let total = body.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    let preview: Vec<Value> = matches
        .iter()
        .take(100)
        .map(|m| {
            json!({
                "ip": m.get("ip_str").and_then(|v| v.as_str()).unwrap_or(""),
                "port": m.get("port").and_then(|v| v.as_u64()).unwrap_or(0),
                "transport": m.get("transport").and_then(|v| v.as_str()).unwrap_or("tcp"),
                "product": m.get("product").and_then(|v| v.as_str()).unwrap_or(""),
                "org": m.get("org").and_then(|v| v.as_str()).unwrap_or(""),
                "hostnames": m.get("hostnames").cloned().unwrap_or(json!([])),
                "country_code": m.get("location").and_then(|l| l.get("country_code")).and_then(|v| v.as_str()).unwrap_or(""),
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "total": total,
            "page": page,
            "returned": matches.len(),
            "matches": preview,
        })),
    )
}

#[derive(Deserialize)]
pub struct ImportReq {
    pub query: String,
    #[serde(default = "default_pages")]
    pub pages: u32,
    #[serde(default)]
    pub project: Option<String>,
}

fn default_pages() -> u32 {
    1
}

pub async fn import_search(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportReq>,
) -> impl IntoResponse {
    let key = match key_or_err(&state) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let query = req.query.trim();
    if query.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "empty query" })),
        );
    }
    let project = clean_project(req.project.as_deref());

    let pages = req.pages.clamp(1, 20);
    let encoded = urlencode(query);
    let scan_uid = format!("shodan-{}", Uuid::new_v4());
    let client = http();

    let mut hosts: Vec<Value> = Vec::new();
    let mut fetched_pages = 0u32;
    let mut total_reported = 0u64;

    for page in 1..=pages {
        let url = format!("{SHODAN_BASE}/shodan/host/search?key={key}&query={encoded}&page={page}");
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("shodan import page {page} error: {e}");
                break;
            }
        };
        if !resp.status().is_success() {
            let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
            if fetched_pages == 0 {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "status": "error",
                        "error": body.get("error").and_then(|v| v.as_str()).unwrap_or("shodan search failed"),
                    })),
                );
            }
            break;
        }
        let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
        if total_reported == 0 {
            total_reported = body.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        }
        let matches = body.get("matches").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        if matches.is_empty() {
            fetched_pages += 1;
            break;
        }
        for m in &matches {
            if let Some(h) = norm_host(m) {
                hosts.push(h);
            }
        }
        fetched_pages += 1;
    }

    if hosts.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "imported": { "hosts": 0 },
                "pages_fetched": fetched_pages,
                "total_available": total_reported,
                "note": "no results",
            })),
        );
    }

    match import::import_payload(&state.ch, &project, &scan_uid, &hosts).await {
        Ok(counts) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "project": project,
                "scan_uid": scan_uid,
                "pages_fetched": fetched_pages,
                "total_available": total_reported,
                "imported": counts,
            })),
        ),
        Err(e) => {
            tracing::warn!("shodan import insert error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

fn norm_lookup(body: &Value) -> Option<Value> {
    let ip = body.get("ip_str").and_then(|v| v.as_str())?.to_string();
    let data = body.get("data").and_then(|v| v.as_array())?;

    let mut ports: Vec<Value> = Vec::new();
    let mut http: Option<Value> = None;
    let mut tls: Option<Value> = None;
    let mut seen_ports = std::collections::HashSet::new();

    for banner in data {
        let mut enriched = banner.clone();
        if enriched.get("location").is_none() {
            if let Some(loc) = body.get("location") {
                enriched["location"] = loc.clone();
            }
        }
        for k in ["asn", "org", "isp"] {
            if enriched.get(k).is_none() {
                if let Some(v) = body.get(k) {
                    enriched[k] = v.clone();
                }
            }
        }
        if let Some(h) = norm_host(&enriched) {
            if let Some(hp) = h.get("ports").and_then(|v| v.as_array()) {
                for p in hp {
                    let pn = p.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                    if seen_ports.insert(pn) {
                        ports.push(p.clone());
                    }
                }
            }
            if http.is_none() {
                if let Some(hh) = h.get("http") {
                    http = Some(hh.clone());
                }
            }
            if tls.is_none() {
                if let Some(ht) = h.get("tls") {
                    tls = Some(ht.clone());
                }
            }
        }
    }

    if ports.is_empty() {
        return None;
    }

    let mut host = json!({ "target": ip, "ports": ports });

    let loc = body.get("location");
    let country = loc.and_then(|l| l.get("country_name")).and_then(|v| v.as_str()).unwrap_or_default();
    let country_code = loc.and_then(|l| l.get("country_code")).and_then(|v| v.as_str()).unwrap_or_default();
    let city = loc.and_then(|l| l.get("city")).and_then(|v| v.as_str()).unwrap_or_default();
    let latv = loc.and_then(|l| l.get("latitude")).and_then(|v| v.as_f64()).unwrap_or(0.0);
    let lonv = loc.and_then(|l| l.get("longitude")).and_then(|v| v.as_f64()).unwrap_or(0.0);
    let asn = body.get("asn").and_then(|v| v.as_str()).unwrap_or_default();
    let org = body.get("org").and_then(|v| v.as_str()).unwrap_or_default();
    let isp = body.get("isp").and_then(|v| v.as_str()).unwrap_or_default();

    if !country.is_empty() || !asn.is_empty() || !org.is_empty() {
        host["geo"] = json!({
            "country": country,
            "country_code": country_code,
            "city": city,
            "lat": latv,
            "lon": lonv,
            "asn": asn,
            "org": org,
            "isp": isp,
        });
    }
    if !country_code.is_empty() {
        host["country"] = json!(country_code);
    }
    if let Some(h) = http {
        host["http"] = h;
    }
    if let Some(t) = tls {
        host["tls"] = t;
    }
    if let Some(hn) = body.get("hostnames").and_then(|v| v.as_array()) {
        let ptr: Vec<&str> = hn.iter().filter_map(|e| e.as_str()).collect();
        if !ptr.is_empty() {
            host["dns"] = json!({ "ptr": ptr });
        }
    }

    Some(host)
}

async fn fetch_host(client: &reqwest::Client, key: &str, ip: &str) -> Result<Value, String> {
    let url = format!("{SHODAN_BASE}/shodan/host/{ip}?key={key}");
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: Value = resp.json().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("shodan host lookup failed")
            .to_string());
    }
    Ok(body)
}

#[derive(Deserialize)]
pub struct HostQuery {
    pub ip: String,
}

pub async fn host_lookup(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HostQuery>,
) -> impl IntoResponse {
    let key = match key_or_err(&state) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let ip = q.ip.trim();
    if ip.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "empty ip" })),
        );
    }
    match fetch_host(&http(), &key, ip).await {
        Ok(body) => {
            let ports = body
                .get("ports")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|p| p.as_u64()).collect::<Vec<_>>())
                .unwrap_or_default();
            let hostnames = body.get("hostnames").cloned().unwrap_or(json!([]));
            let loc = body.get("location");
            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "ip": body.get("ip_str").and_then(|v| v.as_str()).unwrap_or(ip),
                    "ports": ports,
                    "hostnames": hostnames,
                    "org": body.get("org").and_then(|v| v.as_str()).unwrap_or(""),
                    "asn": body.get("asn").and_then(|v| v.as_str()).unwrap_or(""),
                    "country_code": loc.and_then(|l| l.get("country_code")).and_then(|v| v.as_str()).unwrap_or(""),
                    "os": body.get("os").and_then(|v| v.as_str()).unwrap_or(""),
                    "last_update": body.get("last_update").and_then(|v| v.as_str()).unwrap_or(""),
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "status": "error", "error": e })),
        ),
    }
}

#[derive(Deserialize)]
pub struct ImportHostsReq {
    pub ips: Vec<String>,
    #[serde(default)]
    pub project: Option<String>,
}

pub async fn import_hosts(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportHostsReq>,
) -> impl IntoResponse {
    let key = match key_or_err(&state) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let ips: Vec<String> = req
        .ips
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .take(256)
        .collect();
    if ips.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "no ips provided" })),
        );
    }

    let project = clean_project(req.project.as_deref());
    let scan_uid = format!("shodan-host-{}", Uuid::new_v4());
    let client = http();

    let mut hosts: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    for ip in &ips {
        match fetch_host(&client, &key, ip).await {
            Ok(body) => match norm_lookup(&body) {
                Some(h) => hosts.push(h),
                None => failed.push(json!({ "ip": ip, "error": "no service data" })),
            },
            Err(e) => failed.push(json!({ "ip": ip, "error": e })),
        }
    }

    if hosts.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "imported": { "hosts": 0 },
                "failed": failed,
            })),
        );
    }

    match import::import_payload(&state.ch, &project, &scan_uid, &hosts).await {
        Ok(counts) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "project": project,
                "scan_uid": scan_uid,
                "requested": ips.len(),
                "imported": counts,
                "failed": failed,
            })),
        ),
        Err(e) => {
            tracing::warn!("shodan host import insert error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

fn clean_project(raw: Option<&str>) -> String {
    raw.map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("global"))
        .map(|s| {
            s.chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
                .take(64)
                .collect::<String>()
        })
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "global".to_string())
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
