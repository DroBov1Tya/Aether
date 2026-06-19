use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct LastParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    12
}

pub async fn get_last_scans(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LastParams>,
) -> impl IntoResponse {
    match search::get_last_scans(&state.ch, params.limit).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "data": data })),
        ),
        Err(e) => {
            tracing::warn!("get_last_scans error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
