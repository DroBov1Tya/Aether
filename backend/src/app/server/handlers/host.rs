use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::app::databases::clickhouse::queries::search;
use crate::app::AppState;

pub async fn get_host(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    let (nmap, whatweb, screenshots, summary) = tokio::join!(
        search::fetch_host_nmap(&state.ch, &ip),
        search::fetch_host_whatweb(&state.ch, &ip),
        search::fetch_host_screenshots(&state.ch, &ip),
        search::host_summary(&state.ch, &ip),
    );

    match (nmap, whatweb, screenshots, summary) {
        (Ok(nmap), Ok(whatweb), Ok(screenshots), Ok(summary)) => {
            let total_services = whatweb
                .iter()
                .filter_map(|r| r["title"].as_str())
                .count()
                + nmap
                    .iter()
                    .filter_map(|r| r["service"].as_str())
                    .count();
            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "target": ip,
                    "open_ports": nmap,
                    "web_services": whatweb,
                    "screenshots": screenshots,
                    "summary": {
                        "open_ports": summary["open_ports"],
                        "total_services": total_services,
                        "first_seen": summary["first_seen"],
                        "last_seen": summary["last_seen"],
                    }
                })),
            )
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": "failed to fetch host data" })),
        ),
    }
}
