use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::PortParam;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;

pub async fn search_port(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PortParam>,
) -> impl IntoResponse {
    match search::search_by_port(&state.ch, params.q, params.per_page, params.offset()).await {
        Ok(data) => (
            StatusCode::OK,
            Json(
                json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "data": data }),
            ),
        ),
        Err(e) => {
            tracing::warn!("search_port error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
