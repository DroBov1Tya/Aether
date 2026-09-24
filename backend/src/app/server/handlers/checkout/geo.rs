use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::common::CheckoutReq;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::insert_geo;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let row = insert_geo::from_json(&req.target, &req.body);
    if let Err(e) = insert_geo::insert(&state.ch, row).await {
        tracing::warn!("geo insert error: {e}");
    }
    tracing::info!("geo  {}", req.target);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
