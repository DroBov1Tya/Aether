use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;

pub async fn host_history(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    let (nmap_history, whatweb_history) = tokio::join!(
        search::fetch_host_nmap_history(&state.ch, &ip),
        search::fetch_host_whatweb_history(&state.ch, &ip),
    );

    let nmap = nmap_history.unwrap_or_else(|e| {
        tracing::error!("nmap_history: {e}");
        vec![]
    });
    let whatweb = whatweb_history.unwrap_or_else(|e| {
        tracing::error!("whatweb_history: {e}");
        vec![]
    });

    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "data": { "nmap": nmap, "whatweb": whatweb } })),
    )
}
