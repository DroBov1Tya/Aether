use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::app::tools;
use crate::app::tools::common::ExternalReq;
use crate::app::tools::sink::{Sink, Stage};

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

#[derive(Debug, Clone)]
pub struct PipelineOpts {
    pub portscan: bool,
    pub deep_tls: bool,
    pub screenshots: bool,
    pub cooldown_secs: u64,
    pub screenshot_dir: String,
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
) -> bool {
    let cfg = state.cfg;
    let sink = Sink::Backend {
        base: cfg.external_server_path.clone(),
        api_key: cfg.api_key.clone(),
    };
    let pool = tools::proxy::fetch_pool(&cfg.external_server_path, &cfg.api_key).await;
    if !pool.is_empty() {
        tracing::info!("proxy pool loaded: {} entries", pool.len());
    }
    let opts = PipelineOpts {
        portscan: true,
        deep_tls: false,
        screenshots: cfg.httpx_screenshots,
        cooldown_secs: cfg.scan_cooldown,
        screenshot_dir: "/app/screenshots".to_string(),
    };
    run_pipeline_with(state, target, task_uid, settings, &sink, &pool, opts).await
}

pub async fn run_pipeline_with(
    state: &AppState,
    target: &str,
    task_uid: Option<&str>,
    settings: &ScanSettings,
    sink: &Sink,
    pool: &[String],
    opts: PipelineOpts,
) -> bool {
    let cfg = state.cfg;
    let scan_uid = Uuid::new_v4().to_string();
    let permits = state.scan_permits.clone();

    let _permit = match permits.acquire().await {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("scan semaphore closed, dropping {}", target);
            return false;
        }
    };

    let hosts = expand_target(target);
    tracing::info!("pipeline {} hosts={}", target, hosts.len());

    let mut http_ports: Vec<String> = Vec::new();

    if opts.portscan {
        let ports: Vec<i64> = {
            let mut masscan_ports: Vec<i64> = Vec::new();
            if cfg.masscan_enabled {
                match tools::masscan::run_masscan(
                    sink,
                    target,
                    &scan_uid,
                    task_uid,
                    &cfg.masscan_ports,
                    cfg.masscan_max_rate,
                    &cfg.scans_output_path,
                )
                .await
                {
                    Ok(map) => {
                        let mut all: Vec<i64> = map.values().flatten().copied().collect();
                        all.sort_unstable();
                        all.dedup();
                        tracing::info!("✅ masscan  {}  hosts={} ports={:?}", target, map.len(), all);
                        masscan_ports = all;
                    }
                    Err(e) => tracing::warn!("❌ masscan  {}  err={e}", target),
                }
            }

            if !masscan_ports.is_empty() {
                masscan_ports
            } else {
                match run_rustscan_ladder(state, sink, target, &scan_uid, task_uid, settings, pool, &opts).await {
                    Some(p) => {
                        tracing::info!("✅ rustscan  {}  ports={:?}", target, p);
                        p
                    }
                    None => {
                        tracing::warn!("❌ rustscan  {}  all attempts failed", target);
                        return false;
                    }
                }
            }
        };

        let ports_str = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        for host in &hosts {
            match run_nmap_ladder(state, sink, host, &scan_uid, task_uid, &ports_str, pool, &opts).await {
                Some(h) => {
                    tracing::info!("✅ nmap  {}  http={:?}", host, h);
                    for p in h {
                        http_ports.push(format!("{host}:{p}"));
                    }
                }
                None => tracing::warn!("❌ nmap  {}  all attempts failed", host),
            }
        }
    }

    let mut probe_hosts: Vec<String> = hosts.clone();
    let is_domain = target.parse::<std::net::Ipv4Addr>().is_err()
        && !matches!(target.split_once('-'), Some((s, e)) if s.parse::<std::net::Ipv4Addr>().is_ok() && e.parse::<std::net::Ipv4Addr>().is_ok());
    if is_domain {
        let discovered = recon_discovery(target, sink, &scan_uid, task_uid).await;
        tracing::info!("✅ recon  {}  discovered={}", target, discovered.len());
        for d in discovered {
            if !probe_hosts.contains(&d) {
                probe_hosts.push(d);
            }
        }
    }

    for host in &probe_hosts {
        for wp in &cfg.httpx_web_ports {
            let candidate = format!("{host}:{wp}");
            if !http_ports.contains(&candidate) {
                http_ports.push(candidate);
            }
        }
    }

    if cfg.geo_enabled {
        match tools::geo::enrich_hosts(sink, &hosts, &scan_uid, task_uid).await {
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
            sink,
            &http_ports,
            &scan_uid,
            task_uid,
            opts.screenshots,
            pool,
            &opts.screenshot_dir,
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

    if cfg.nuclei_enabled && !live_urls.is_empty() {
        match tools::nuclei::run_nuclei(sink, &live_urls, &scan_uid, task_uid, pool).await {
            Ok(n) => tracing::info!("✅ nuclei  {}  findings={}", target, n),
            Err(e) => tracing::warn!("❌ nuclei  {}  err={e}", target),
        }
    }

    for (host, ports_list) in &host_ports {
        match tools::fuzzing::run_fuzzing(
            sink,
            host,
            &scan_uid,
            task_uid,
            ports_list,
            opts.screenshots,
            &opts.screenshot_dir,
        )
        .await
        {
            Ok(f) => tracing::info!("✅ fuzzing  {}  found={}", host, f.len()),
            Err(e) => tracing::warn!("❌ fuzzing  {}  err={e}", host),
        }
    }

    if !http_ports.is_empty() {
        match tools::tlsx::run_tlsx(sink, &http_ports, &scan_uid, task_uid, pool).await {
            Ok(n) => tracing::info!("✅ tlsx  {}  certs={}", target, n),
            Err(e) => tracing::warn!("❌ tlsx  {}  err={e}", target),
        }
    }

    if opts.deep_tls && !http_ports.is_empty() {
        let proxy = pool.first().map(|s| s.as_str());
        let rows = tools::deep_tls::deep_scan(&http_ports, 30, proxy).await;
        tracing::info!("✅ deep_tls  {}  rows={}", target, rows.len());
        for row in &rows {
            let req = ExternalReq {
                status: "complete".to_string(),
                target: row.host.clone(),
                body: serde_json::to_string(row).unwrap_or_else(|_| "{}".to_string()),
                version: crate::config::VERSION,
                scan_uid: scan_uid.to_string(),
                task_uid: task_uid.map(String::from),
                country: None,
                port: Some(row.port.clone()),
            };
            if let Err(e) = sink.emit(Stage::DeepTls, req).await {
                tracing::warn!(target = %row.host, err = %e, "deep_tls checkout failed");
            }
        }
    }

    let is_ip_chunk = matches!(target.split_once('-'), Some((s, e)) if s.parse::<std::net::Ipv4Addr>().is_ok() && e.parse::<std::net::Ipv4Addr>().is_ok());
    if !is_ip_chunk {
        let root = target;
        match tools::dnsx::run_dnsx(
            sink,
            std::slice::from_ref(&root.to_string()),
            &scan_uid,
            task_uid,
            pool,
        )
        .await
        {
            Ok(n) => tracing::info!("✅ dnsx  {}  resolved={}", root, n),
            Err(e) => tracing::warn!("❌ dnsx  {}  err={e}", root),
        }

        match tools::whois::run_whois(sink, root, &scan_uid, task_uid).await {
            Ok(_) => tracing::info!("✅ whois  {}", root),
            Err(e) => tracing::warn!("❌ whois  {}  err={e}", root),
        }
    }

    true
}

async fn run_rustscan_ladder(
    state: &AppState,
    sink: &Sink,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    settings: &ScanSettings,
    pool: &[String],
    opts: &PipelineOpts,
) -> Option<Vec<i64>> {
    let _ = state;
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
            sink,
            target,
            scan_uid,
            task_uid,
            settings.port_range.as_deref(),
            settings.threads,
            settings.timeout_ms,
            attempt.as_deref(),
            opts.cooldown_secs,
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

async fn recon_discovery(
    domain: &str,
    sink: &Sink,
    scan_uid: &str,
    task_uid: Option<&str>,
) -> Vec<String> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("aether-agent/recon")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(err = %e, "recon: http client build failed");
            return Vec::new();
        }
    };

    let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let keys = tools::passive_subs::PassiveKeys {
        otx: std::env::var("OTX_API_KEY").ok().filter(|s| !s.is_empty()),
        certspotter: std::env::var("CERTSPOTTER_API_KEY").ok().filter(|s| !s.is_empty()),
        virustotal: std::env::var("VT_API_KEY").ok().filter(|s| !s.is_empty()),
        securitytrails: std::env::var("SECURITYTRAILS_API_KEY").ok().filter(|s| !s.is_empty()),
    };

    let passive = tools::passive_subs::enumerate(&dom, &keys, 25, &client).await;
    emit_json(sink, Stage::Subdomain, &dom, scan_uid, task_uid, &passive).await;

    const MAX_ACTIVE: usize = 1500;
    let mut cand_pool: Vec<String> = passive.subdomains.clone();
    let capped = cand_pool.len() > MAX_ACTIVE;
    if capped {
        tracing::warn!(
            domain = %dom,
            total = cand_pool.len(),
            cap = MAX_ACTIVE,
            "recon: passive set exceeds active cap, truncating for resolve/probe"
        );
        cand_pool.truncate(MAX_ACTIVE);
    }

    let filtered = tools::wildcard::filter(&dom, &cand_pool, &client, 3).await;
    emit_json(sink, Stage::CtLog, &dom, scan_uid, task_uid, &filtered).await;

    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    seen.insert(dom.clone());
    for s in &filtered.kept {
        seen.insert(s.clone());
    }

    let dns = tools::dns_records::resolve(&dom, &client).await;
    emit_json(sink, Stage::DnsRecords, &dom, scan_uid, task_uid, &dns).await;
    let mail = tools::dns_records::email_auth(&dom, &client).await;
    emit_json(sink, Stage::DnsRecords, &dom, scan_uid, task_uid, &mail).await;

    let suffix = format!(".{}", dom);
    let mut frontier: Vec<String> = seen.iter().cloned().collect();
    let max_rounds = 2usize;
    for _ in 0..max_rounds {
        let mut new_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for host in frontier.iter().take(64) {
            for ip in resolve_ips_for(host, &client).await {
                if let Some(db) = tools::passive_subs::internetdb(&ip, &client).await {
                    for h in db.hostnames {
                        let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
                        if (h == dom || h.ends_with(&suffix)) && !seen.contains(&h) {
                            new_names.insert(h);
                        }
                    }
                }
            }
        }
        if new_names.is_empty() {
            break;
        }
        let batch: Vec<String> = new_names.iter().cloned().collect();
        let wf = tools::wildcard::filter(&dom, &batch, &client, 3).await;
        let mut next: Vec<String> = Vec::new();
        for h in wf.kept {
            if seen.insert(h.clone()) {
                next.push(h);
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }

    seen.into_iter().filter(|h| h != &dom).collect()
}

async fn resolve_ips_for(host: &str, client: &reqwest::Client) -> Vec<String> {
    let url = format!("https://dns.google/resolve?name={}&type=A", host);
    let Ok(resp) = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(8))
        .send()
        .await
    else {
        return Vec::new();
    };
    let Ok(v) = resp.json::<serde_json::Value>().await else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(ans) = v.get("Answer").and_then(|a| a.as_array()) {
        for rec in ans {
            if rec.get("type").and_then(|x| x.as_u64()) == Some(1) {
                if let Some(d) = rec.get("data").and_then(|x| x.as_str()) {
                    out.push(d.trim().to_string());
                }
            }
        }
    }
    out
}

async fn emit_json<T: serde::Serialize>(
    sink: &Sink,
    stage: Stage,
    target: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    body: &T,
) {
    let req = ExternalReq {
        status: "complete".to_string(),
        target: target.to_string(),
        body: serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string()),
        version: crate::config::VERSION,
        scan_uid: scan_uid.to_string(),
        task_uid: task_uid.map(String::from),
        country: None,
        port: None,
    };
    if let Err(e) = sink.emit(stage, req).await {
        tracing::warn!(target = %target, stage = stage.name(), err = %e, "recon emit failed");
    }
}

async fn run_nmap_ladder(
    state: &AppState,
    sink: &Sink,
    host: &str,
    scan_uid: &str,
    task_uid: Option<&str>,
    ports_str: &str,
    pool: &[String],
    opts: &PipelineOpts,
) -> Option<Vec<String>> {
    let cfg = state.cfg;
    for attempt in tools::proxy::attempts(pool) {
        match tools::nmap::run_nmap(
            sink,
            host,
            scan_uid,
            task_uid,
            ports_str,
            &cfg.scans_output_path,
            attempt.as_deref(),
            opts.cooldown_secs,
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
        let _ = run_pipeline(&state, &target, task_uid.as_deref(), &settings).await;
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "started" })),
    )
}
