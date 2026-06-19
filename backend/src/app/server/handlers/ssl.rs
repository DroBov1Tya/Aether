use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::common::CheckoutReq;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::insert_ssl;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let item = match insert_ssl::from_json(&req.body) {
        Some(row) => row,
        None => {
            tracing::warn!("ssl  {}  invalid body", req.target);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "error": "invalid body" })),
            );
        }
    };

    if let Err(e) = insert_ssl::insert(&state.ch, item).await {
        tracing::warn!("ssl insert error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }

    tracing::info!("ssl  {}  saved", req.target);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
