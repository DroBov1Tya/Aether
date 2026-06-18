use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use crate::app::databases::clickhouse::queries::insert_whatweb;
use crate::app::AppState;
use super::common::CheckoutReq;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let items: Vec<insert_whatweb::WhatwebRow> = req
        .body
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| insert_whatweb::from_json(&req.target, v))
                .collect()
        })
        .unwrap_or_default();

    let count = items.len();
    for row in items {
        if let Err(e) = insert_whatweb::insert(&state.ch, row).await {
            tracing::warn!("whatweb insert error: {e}");
        }
    }

    tracing::info!("whatweb  {}  {} results", req.target, count);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
