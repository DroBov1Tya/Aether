use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use std::sync::Arc;

use crate::app::databases::clickhouse::queries::insert_screenshot;
use crate::app::databases::s3::queries::insert_screenshot as s3_screenshot;
use crate::app::AppState;
use super::common::CheckoutReq;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let raw = match req.body.as_str() {
        Some(s) => s.to_string(),
        None => {
            tracing::warn!("hxn  {}  body is not a string", req.target);
            return (StatusCode::OK, Json(json!({ "status": "skipped" })));
        }
    };

    let image_bytes = match STANDARD.decode(&raw) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("hxn  {}  base64 decode error: {e}", req.target);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "error": e.to_string() })),
            );
        }
    };

    let port: u16 = 443;

    let s3_key = match s3_screenshot::upload(&state.s3, &req.target, port, &image_bytes).await {
        Ok(key) => key,
        Err(e) => {
            tracing::warn!("hxn  {}  s3 upload error: {e}", req.target);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            );
        }
    };

    let row = insert_screenshot::ScreenshotRow {
        target: req.target.clone(),
        port,
        s3_key: s3_key.clone(),
        file_size: image_bytes.len() as u32,
    };

    if let Err(e) = insert_screenshot::insert(&state.ch, row).await {
        tracing::warn!("hxn  {}  clickhouse insert error: {e}", req.target);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }

    tracing::info!("hxn  {}  screenshot={}  size={}", req.target, s3_key, image_bytes.len());
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
