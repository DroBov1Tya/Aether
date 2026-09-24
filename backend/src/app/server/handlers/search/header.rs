use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::QParam;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;

pub async fn search_header(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QParam>,
) -> impl IntoResponse {
    let total = search::count_search_by_header(&state.ch, &params.q, &params.project).await.unwrap_or(0);
    match search::search_by_header(&state.ch, &params.q, &params.project, params.per_page, params.offset()).await {
        Ok(data) => (
            StatusCode::OK,
            Json(
                json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "total": total, "data": data }),
            ),
        ),
        Err(e) => {
            tracing::warn!("search_header error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
