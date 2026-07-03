use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::common::CheckoutReq;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::insert_nmap;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let Some(row) =
        insert_nmap::from_json(&req.target, &req.scan_uid, req.country.clone(), &req.body)
    else {
        tracing::warn!("nmap  {}  invalid body: {}", req.target, req.body);
        return (StatusCode::OK, Json(json!({ "status": "skipped" })));
    };

    if let Err(e) = insert_nmap::insert(&state.ch, row).await {
        tracing::warn!("nmap insert error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }

    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
