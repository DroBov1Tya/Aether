use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::proxies;

#[derive(Debug, Deserialize)]
pub struct AddProxiesReq {
    // Either a list of proxy URLs, or a single blob with one proxy per line.
    #[serde(default)]
    pub proxies: Vec<String>,
    #[serde(default)]
    pub raw: Option<String>,
}

/// Split the request into a clean, deduped list of proxy URLs. Accepts both a
/// JSON array and a newline-delimited blob (the web textarea sends `raw`).
fn collect_items(req: &AddProxiesReq) -> Vec<String> {
    let mut items: Vec<String> = Vec::new();
    for p in &req.proxies {
        let v = p.trim();
        if !v.is_empty() {
            items.push(v.to_string());
        }
    }
    if let Some(raw) = &req.raw {
        for line in raw.lines() {
            let v = line.trim();
            if !v.is_empty() {
                items.push(v.to_string());
            }
        }
    }
    items.sort();
    items.dedup();
    items
}

/// GET /api/proxies — the active proxy pool. Serves both the web UI and agents.
pub async fn list_proxies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match proxies::list(&state.ch).await {
        Ok(data) => (StatusCode::OK, Json(json!({ "status": "ok", "data": data }))),
        Err(e) => {
            tracing::warn!("list_proxies error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

/// POST /api/proxies — add a batch of proxies (JSON array or newline blob).
pub async fn add_proxies(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddProxiesReq>,
) -> impl IntoResponse {
    let items = collect_items(&req);
    if items.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "no proxies provided" })),
        );
    }
    match proxies::add_many(&state.ch, &items).await {
        Ok(added) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "added": added })),
        ),
        Err(e) => {
            tracing::warn!("add_proxies error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

/// DELETE /api/proxies — clear the entire pool.
pub async fn delete_all_proxies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match proxies::delete_all(&state.ch).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => {
            tracing::warn!("delete_all_proxies error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DeleteOneReq {
    pub url: String,
}

/// DELETE /api/proxies/one — remove a single proxy by URL (sent in the body so
/// URL-unsafe proxy strings survive transport intact).
pub async fn delete_one_proxy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeleteOneReq>,
) -> impl IntoResponse {
    let url = req.url.trim();
    if url.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "empty url" })),
        );
    }
    match proxies::delete_one(&state.ch, url).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => {
            tracing::warn!("delete_one_proxy error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
