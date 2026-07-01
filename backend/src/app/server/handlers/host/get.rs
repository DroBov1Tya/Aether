use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{Value, json};
use std::sync::Arc;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;

pub async fn get_host(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    let (nmap, rustscan, whatweb, screenshots, summary, dns, ssl, fuzzing) = tokio::join!(
        search::fetch_host_nmap(&state.ch, &ip),
        search::fetch_host_rustscan(&state.ch, &ip),
        search::fetch_host_whatweb(&state.ch, &ip),
        search::fetch_host_screenshots(&state.ch, &ip),
        search::host_summary(&state.ch, &ip),
        search::fetch_host_dns(&state.ch, &ip),
        search::fetch_host_ssl(&state.ch, &ip),
        search::fetch_host_fuzzing(&state.ch, &ip),
    );

    let nmap = nmap.unwrap_or_else(|e| {
        tracing::error!("nmap: {e}");
        vec![]
    });

    let rustscan = rustscan.unwrap_or_else(|e| {
        tracing::error!("rustscan: {e}");
        vec![]
    });

    let nmap = if nmap.is_empty() { rustscan } else { nmap };
    let whatweb = whatweb.unwrap_or_else(|e| {
        tracing::error!("whatweb: {e}");
        vec![]
    });
    let screenshots = screenshots.unwrap_or_else(|e| {
        tracing::error!("screenshots: {e}");
        vec![]
    });
    let dns = dns.unwrap_or_else(|e| {
        tracing::error!("dns: {e}");
        Value::Null
    });
    let ssl = ssl.unwrap_or_else(|e| {
        tracing::error!("ssl: {e}");
        vec![]
    });
    let fuzzing = fuzzing.unwrap_or_else(|e| {
        tracing::error!("fuzzing: {e}");
        vec![]
    });

    let summary = summary.unwrap_or_else(|_| json!({ "open_ports": nmap.len(), "first_seen": Value::Null, "last_seen": Value::Null }));

    if nmap.is_empty()
        && whatweb.is_empty()
        && screenshots.is_empty()
        && dns.is_null()
        && ssl.is_empty()
        && fuzzing.is_empty()
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "error": "no data found for this host" })),
        );
    }

    let total_services = whatweb.iter().filter_map(|r| r["title"].as_str()).count()
        + nmap.iter().filter_map(|r| r["service"].as_str()).count();

    (
        StatusCode::OK,
        Json(json!({
            "status": "ok", "target": ip, "open_ports": nmap, "web_services": whatweb,
            "screenshots": screenshots, "dns": dns, "ssl": ssl, "fuzzing": fuzzing,
            "summary": { "open_ports": summary["open_ports"], "total_services": total_services, "first_seen": summary["first_seen"], "last_seen": summary["last_seen"] }
        })),
    )
}
