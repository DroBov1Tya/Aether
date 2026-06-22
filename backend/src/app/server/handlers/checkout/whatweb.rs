use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use super::common::CheckoutReq;
use crate::app::databases::redis::tasks;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::insert_whatweb;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let items: Vec<insert_whatweb::WhatwebRow> = req
        .body
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| insert_whatweb::from_json(&req.target, &req.scan_uid, req.country.clone(), v))
                .collect()
        })
        .unwrap_or_default();

    let count = items.len();
    for row in items {
        if let Err(e) = insert_whatweb::insert(&state.ch, row).await {
            tracing::warn!("whatweb insert error: {e}");
        }
    }

    if let Some(task_uid) = &req.task_uid {
        if let Ok(uid) = Uuid::parse_str(task_uid) {
            let mut con = state.redis.clone();
            tasks::update_field(&mut con, uid, "whatweb", true).await;
            if tasks::is_all_done(&mut con, uid).await {
                tasks::cleanup(&mut con, uid).await;
            }
        }
    }

    tracing::info!("whatweb  {}  {} results", req.target, count);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
