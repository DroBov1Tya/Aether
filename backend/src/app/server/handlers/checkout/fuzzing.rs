use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::common::CheckoutReq;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::insert_fuzzing;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let items: Vec<insert_fuzzing::FuzzingRow> = req
        .body
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| insert_fuzzing::from_json(&req.target, &req.scan_uid, v))
                .collect()
        })
        .unwrap_or_default();

    let count = items.len();
    for row in items {
        if let Err(e) = insert_fuzzing::insert(&state.ch, row).await {
            tracing::warn!("fuzzing insert error: {e}");
        }
    }

    tracing::info!("fuzzing  {}  {} results", req.target, count);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
