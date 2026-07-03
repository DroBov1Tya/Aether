use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::common::CheckoutReq;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::insert_whois;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let Some(row) = insert_whois::WhoisRow::from_json(&req.target, &req.scan_uid, &req.body) else {
        tracing::warn!("whois  {}  invalid body", req.target);
        return (StatusCode::OK, Json(json!({ "status": "skipped" })));
    };

    if let Err(e) = insert_whois::insert(&state.ch, row).await {
        tracing::warn!("whois insert error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }

    tracing::info!("whois  {}  stored", req.target);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
