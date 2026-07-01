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
use crate::app::databases::clickhouse::queries::insert_rustscan;
use crate::app::databases::redis::tasks;

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

    if let Err(e) = insert_rustscan::insert(
        &state.ch,
        &req.target,
        &req.scan_uid,
        &ports,
        req.country.clone(),
    )
    .await
    {
        tracing::warn!("rustscan insert error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }

    if let Some(task_uid) = &req.task_uid {
        if let Ok(uid) = Uuid::parse_str(task_uid) {
            let mut con = state.redis.clone();
            tasks::update_field(&mut con, uid, "rustscan", true).await;
            if tasks::is_all_done(&mut con, uid).await {
                tasks::cleanup(&mut con, uid).await;
            }
        }
    }

    tracing::info!("rustscan  {}  ports={:?}", req.target, ports);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
