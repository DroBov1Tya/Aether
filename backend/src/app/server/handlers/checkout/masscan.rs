use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::common::CheckoutReq;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::insert_masscan;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let ports: Vec<u16> = req
        .body
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u16))
                .collect()
        })
        .unwrap_or_default();

    if let Err(e) = insert_masscan::insert(
        &state.ch,
        &req.target,
        &req.scan_uid,
        &ports,
        req.country.clone(),
    )
    .await
    {
        tracing::warn!("masscan insert error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }

    tracing::info!("masscan  {}  ports={:?}", req.target, ports);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
