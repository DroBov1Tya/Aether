use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{Value, json};
use std::sync::Arc;

use super::ScreenshotListParams;
use crate::app::databases::clickhouse::queries::search;

#[tracing::instrument(skip(state))]
pub async fn list_screenshots_thumbnails(
    State(state): State<Arc<crate::app::AppState>>,
    Query(params): Query<ScreenshotListParams>,
) -> impl IntoResponse {
    let limit = params.per_page.unwrap_or(20);
    let offset = params.offset();

    let rows = match search::list_all_screenshots(&state.ch, limit, offset).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("list_screenshots_thumbnails error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            );
        }
    };

    let results: Vec<Value> = rows
        .into_iter()
        .map(|mut v| {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("s3_key");
            }
            v
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "data": results })),
    )
}
