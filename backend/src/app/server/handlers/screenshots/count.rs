use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use std::sync::Arc;

use crate::app::databases::clickhouse::queries::search;

#[tracing::instrument(skip(state))]
pub async fn list_screenshots_count(
    State(state): State<Arc<crate::app::AppState>>,
) -> impl IntoResponse {
    let total = match search::count_screenshots(&state.ch).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("count screenshots error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            );
        }
    };
    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "data": { "total": total } })),
    )
}
