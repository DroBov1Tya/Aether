use axum::{
    body::Body,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;

pub async fn get_screenshot(
    State(state): State<Arc<AppState>>,
    Path((ip, port)): Path<(String, u16)>,
) -> impl IntoResponse {
    let (s3_key, _file_size) = match search::fetch_screenshot_s3_key(&state.ch, &ip, port).await {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!("Screenshot not found: {}:{} — {}", ip, port, e);
            return (StatusCode::NOT_FOUND, "Screenshot not found").into_response();
        }
    };

    match state.s3.get_object(&s3_key).await {
        Ok(response_data) => {
            let status = response_data.status_code();
            if status != 200 {
                tracing::warn!("S3 returned status {} for key: {}", status, s3_key);
                return (StatusCode::NOT_FOUND, "Screenshot not found in storage").into_response();
            }

            let bytes = response_data.bytes().to_vec();
            let content_type = if s3_key.ends_with(".jpg") || s3_key.ends_with(".jpeg") {
                "image/jpeg"
            } else if s3_key.ends_with(".webp") {
                "image/webp"
            } else {
                "image/png"
            };

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CACHE_CONTROL, "public, max-age=31536000")
                .body(Body::from(bytes))
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to build response: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to build response",
                    )
                        .into_response()
                })
        }
        Err(e) => {
            tracing::error!("S3 get_object failed for key {}: {}", s3_key, e);
            (StatusCode::NOT_FOUND, "Screenshot not found in storage").into_response()
        }
    }
}
