use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use std::sync::Arc;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::agents;

pub async fn list_agents(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match agents::list_all(&state.ch).await {
        Ok(list) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "data": list })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}
