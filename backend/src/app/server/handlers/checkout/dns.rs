use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::common::CheckoutReq;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::insert_dns;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let item = match insert_dns::from_json(&req.scan_uid, req.country.clone(), &req.body) {
        Some(row) => row,
        None => {
            tracing::warn!("dns  {}  invalid body", req.target);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "error": "invalid body" })),
            );
        }
    };

    if let Err(e) = insert_dns::insert(&state.ch, item).await {
        tracing::warn!("dns insert error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }

    tracing::info!("dns  {}  saved", req.target);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
