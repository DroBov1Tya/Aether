use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use super::common::CheckoutReq;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::insert_ssl;
use crate::app::databases::redis::tasks;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let item = match insert_ssl::from_json(&req.scan_uid, req.country.clone(), &req.body) {
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

    if let Some(task_uid) = &req.task_uid {
        if let Ok(uid) = Uuid::parse_str(task_uid) {
            let mut con = state.redis.clone();
            tasks::update_field(&mut con, uid, "ssl", true).await;
            if tasks::is_all_done(&mut con, uid).await {
                tasks::cleanup(&mut con, uid).await;
            }
        }
    }

    tracing::info!("ssl  {}  saved", req.target);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
