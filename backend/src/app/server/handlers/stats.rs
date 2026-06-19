use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;

#[derive(Deserialize)]
pub struct TopParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    25
}

pub async fn stats_ports(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TopParams>,
) -> impl IntoResponse {
    match search::top_ports(&state.ch, params.limit).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "data": data })),
        ),
        Err(e) => {
            tracing::warn!("stats_ports error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

pub async fn stats_services(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TopParams>,
) -> impl IntoResponse {
    match search::top_services(&state.ch, params.limit).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "data": data })),
        ),
        Err(e) => {
            tracing::warn!("stats_services error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

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
