use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use std::sync::Arc;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;

pub async fn stats_summary(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match search::summary_stats(&state.ch).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "data": data })),
        ),
        Err(e) => {
            tracing::warn!("stats_summary error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
