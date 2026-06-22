use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;

pub async fn host_snapshots(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    match search::fetch_host_snapshots(&state.ch, &ip).await {
        Ok(snapshots) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "target": ip, "snapshots": snapshots })),
        ),
        Err(e) => {
            tracing::error!("host_snapshots failed for {}: {}", ip, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
