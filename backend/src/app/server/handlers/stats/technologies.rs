use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::TopParams;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;

pub async fn stats_technologies(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TopParams>,
) -> impl IntoResponse {
    match search::top_technologies(&state.ch, params.limit).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "data": data })),
        ),
        Err(e) => {
            tracing::warn!("stats_technologies error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
