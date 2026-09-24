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

pub async fn stats_countries(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TopParams>,
) -> impl IntoResponse {
    respond(search::top_countries(&state.ch, params.limit).await, "stats_countries")
}

pub async fn stats_asns(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TopParams>,
) -> impl IntoResponse {
    respond(search::top_asns(&state.ch, params.limit).await, "stats_asns")
}

pub async fn stats_orgs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TopParams>,
) -> impl IntoResponse {
    respond(search::top_orgs(&state.ch, params.limit).await, "stats_orgs")
}

fn respond(
    result: anyhow::Result<Vec<serde_json::Value>>,
    label: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    match result {
        Ok(data) => (StatusCode::OK, Json(json!({ "status": "ok", "data": data }))),
        Err(e) => {
            tracing::warn!("{label} error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
