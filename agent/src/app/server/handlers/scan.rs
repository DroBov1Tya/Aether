use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::app::tools;

#[derive(Debug, Deserialize)]
pub struct ScanTarget {
    pub target: String,
    pub task_uid: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ScanSettings {
    pub port_range: Option<String>,
    pub threads: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub proxy: Option<String>,
}

pub fn expand_target(target: &str) -> Vec<String> {
    let Some((s, e)) = target.split_once('-') else {
        return vec![target.to_string()];
    };
    let (Ok(a), Ok(b)) = (s.parse::<std::net::Ipv4Addr>(), e.parse::<std::net::Ipv4Addr>())
    else {
        return vec![target.to_string()];
    };
    let [o1, o2, o3, o4] = a.octets();
    let [p1, p2, p3, p4] = b.octets();
    let start = ((o1 as u32) << 24) | ((o2 as u32) << 16) | ((o3 as u32) << 8) | o4 as u32;
    let end = ((p1 as u32) << 24) | ((p2 as u32) << 16) | ((p3 as u32) << 8) | p4 as u32;
    (start..=end)
        .map(|n| std::net::Ipv4Addr::from(n).to_string())
        .collect()
}

pub async fn run_pipeline(
    state: &AppState,
    target: &str,
    task_uid: Option<&str>,
    settings: &ScanSettings,
) {
    let scan_uid = Uuid::new_v4().to_string();
    let permits = state.scan_permits.clone();

    let _permit = match permits.acquire().await {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("scan semaphore closed, dropping {}", target);
            return;
        }
    };

    let hosts = expand_target(target);
    tracing::info!("pipeline {} hosts={}", target, hosts.len());

    // Fetch the current proxy pool once per task. Each stage tries direct
    // first, then walks this pool in order when it hits blocks/errors.
    let pool = tools::proxy::fetch_pool(&state.cfg.external_server_path, &state.cfg.api_key).await;
    if !pool.is_empty() {
        tracing::info!("proxy pool loaded: {} entries", pool.len());
    }

    let ports: Vec<i64> = match run_rustscan_ladder(state, target, &scan_uid, task_uid, settings, &pool).await {
        Some(p) => {
            tracing::info!("✅ rustscan  {}  ports={:?}", target, p);
            p
        }
        None => {
            tracing::warn!("❌ rustscan  {}  all attempts failed", target);
            return;
        }
    };

    let ports_str = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let mut http_ports: Vec<String> = Vec::new();
    for host in &hosts {
        match run_nmap_ladder(state, host, &scan_uid, task_uid, &ports_str, &pool).await {
            Some(h) => {
                tracing::info!("✅ nmap  {}  http={:?}", host, h);
                for p in h {
                    http_ports.push(format!("{host}:{p}"));
                }
            }
            None => tracing::warn!("❌ nmap  {}  all attempts failed", host),
        }
    }

    // Always probe common web ports per host so the HTTP layer runs even when
    // nmap reports nothing on them. httpx drops dead endpoints itself.
    for host in &hosts {
        for wp in &state.cfg.httpx_web_ports {
            let candidate = format!("{host}:{wp}");
            if !http_ports.contains(&candidate) {
                http_ports.push(candidate);
            }
        }
    }

    if state.cfg.geo_enabled {
        match tools::geo::enrich_hosts(
            &state.cfg.external_server_path,
            &hosts,
            &scan_uid,
            task_uid,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(n) => tracing::info!("✅ geo  {}  enriched={}", target, n),
            Err(e) => tracing::warn!("❌ geo  {}  err={e}", target),
        }
    }

    let mut host_ports: std::collections::HashMap<&str, Vec<String>> = std::collections::HashMap::new();
    for hp in &http_ports {
        if let Some(port) = hp.rsplit_once(':') {
            host_ports.entry(port.0).or_default().push(port.1.to_string());
        }
    }

    let mut live_urls: Vec<String> = Vec::new();
    if !http_ports.is_empty() {
        match tools::httpx::run_httpx(
            &state.cfg.external_server_path,
            &http_ports,
            &scan_uid,
            task_uid,
            state.cfg.httpx_screenshots,
            &pool,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(urls) => {
                tracing::info!("✅ httpx  {}  urls={}", target, urls.len());
                live_urls = urls;
            }
            Err(e) => tracing::warn!("❌ httpx  {}  err={e}", target),
        }
    }

    if state.cfg.nuclei_enabled && !live_urls.is_empty() {
        match tools::nuclei::run_nuclei(
            &state.cfg.external_server_path,
            &live_urls,
            &scan_uid,
            task_uid,
            &pool,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(n) => tracing::info!("✅ nuclei  {}  findings={}", target, n),
            Err(e) => tracing::warn!("❌ nuclei  {}  err={e}", target),
        }
    }

    for (host, ports_list) in &host_ports {
        match tools::fuzzing::run_fuzzing(
            &state.cfg.external_server_path,
            host,
            &scan_uid,
            task_uid,
            ports_list,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(f) => tracing::info!("✅ fuzzing  {}  found={}", host, f.len()),
            Err(e) => tracing::warn!("❌ fuzzing  {}  err={e}", host),
        }
    }

    if !http_ports.is_empty() {
        match tools::tlsx::run_tlsx(
            &state.cfg.external_server_path,
            &http_ports,
            &scan_uid,
            task_uid,
            &pool,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(n) => tracing::info!("✅ tlsx  {}  certs={}", target, n),
            Err(e) => tracing::warn!("❌ tlsx  {}  err={e}", target),
        }
    }

    let is_ip_chunk = matches!(target.split_once('-'), Some((s, e)) if s.parse::<std::net::Ipv4Addr>().is_ok() && e.parse::<std::net::Ipv4Addr>().is_ok());
    if !is_ip_chunk {
        let root = target;
        match tools::dnsx::run_dnsx(
            &state.cfg.external_server_path,
            std::slice::from_ref(&root.to_string()),
            &scan_uid,
            task_uid,
            &pool,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(n) => tracing::info!("✅ dnsx  {}  resolved={}", root, n),
            Err(e) => tracing::warn!("❌ dnsx  {}  err={e}", root),
        }

        match tools::whois::run_whois(
            &state.cfg.external_server_path,
            root,
            &scan_uid,
            task_uid,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(_) => tracing::info!("✅ whois  {}", root),
            Err(e) => tracing::warn!("❌ whois  {}  err={e}", root),
        }
    }
}

/// rustscan ladder: direct first, then each pool proxy in order. rustscan
/// takes a single proxy, so we pass one candidate per attempt.
async fn run_rustscan_ladder(
    state: &AppState,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    settings: &ScanSettings,
    pool: &[String],
) -> Option<Vec<i64>> {
    // Honor an explicit per-task proxy override before falling back to direct.
    let explicit = settings.proxy.clone();
    let mut attempts: Vec<Option<String>> = Vec::new();
    if let Some(p) = explicit.filter(|s| !s.trim().is_empty()) {
        attempts.push(Some(p));
    }
    for a in tools::proxy::attempts(pool) {
        if !attempts.contains(&a) {
            attempts.push(a);
        }
    }

    for attempt in attempts {
        match tools::rustscan::run_rustscan(
            &state.cfg.external_server_path,
            target,
            scan_uid,
            task_uid,
            settings.port_range.as_deref(),
            settings.threads,
            settings.timeout_ms,
            attempt.as_deref(),
            &state.cfg.api_key,
        )
        .await
        {
            Ok(p) if !p.is_empty() => return Some(p),
            Ok(_) => tracing::debug!(proxy = ?attempt, "rustscan: no ports, trying next proxy"),
            Err(e) => tracing::debug!(proxy = ?attempt, err = %e, "rustscan: attempt failed, trying next proxy"),
        }
    }
    None
}

/// nmap ladder: direct first, then each pool proxy in order. nmap proxying is
/// applied inside the tool via env, so the pool is threaded through there.
async fn run_nmap_ladder(
    state: &AppState,
    host: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    ports_str: &str,
    pool: &[String],
) -> Option<Vec<String>> {
    for attempt in tools::proxy::attempts(pool) {
        match tools::nmap::run_nmap(
            &state.cfg.external_server_path,
            host,
            scan_uid,
            task_uid,
            ports_str,
            &state.cfg.scans_output_path,
            attempt.as_deref(),
            &state.cfg.api_key,
        )
        .await
        {
            Ok(h) => return Some(h),
            Err(e) => tracing::debug!(proxy = ?attempt, err = %e, "nmap: attempt failed, trying next proxy"),
        }
    }
    None
}

pub async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(scan_target): Json<ScanTarget>,
) -> impl IntoResponse {
    let target = scan_target.target.clone();
    let task_uid = scan_target.task_uid.clone();
    let settings = ScanSettings::default();

    tokio::task::spawn(async move {
        run_pipeline(&state, &target, task_uid.as_deref(), &settings).await;
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "started" })),
    )
}
