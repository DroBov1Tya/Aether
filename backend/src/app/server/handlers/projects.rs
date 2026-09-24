use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::{import, search};

fn clean_project(raw: &str) -> Option<String> {
    let safe: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
        .take(64)
        .collect();
    let safe = safe.trim().to_string();
    if safe.is_empty() || safe.eq_ignore_ascii_case("global") {
        None
    } else {
        Some(safe)
    }
}

#[derive(Debug, Deserialize)]
pub struct ImportPayload {
    pub project: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub hosts: Vec<Value>,
}

pub async fn import_data(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ImportPayload>,
) -> impl IntoResponse {
    let project = match clean_project(&payload.project) {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "error": "invalid project name (empty or reserved 'global')" })),
            );
        }
    };
    if payload.hosts.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "no hosts in payload" })),
        );
    }

    let scan_uid = format!("import-{}", Uuid::new_v4());
    match import::import_payload(&state.ch, &project, &scan_uid, &payload.hosts).await {
        Ok(counts) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "project": project,
                "source": payload.source,
                "scan_uid": scan_uid,
                "imported": counts,
            })),
        ),
        Err(e) => {
            tracing::warn!("import error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

pub async fn list_projects(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match search::list_projects(&state.ch).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "data": data })),
        ),
        Err(e) => {
            tracing::warn!("list_projects error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ProjectQuery {
    pub project: String,
}

pub async fn project_hosts(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ProjectQuery>,
) -> impl IntoResponse {
    let project = match clean_project(&q.project) {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "error": "invalid project" })),
            );
        }
    };
    match search::search_aggregated(&state.ch, "", &project, 200, 0).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "project": project, "data": data })),
        ),
        Err(e) => {
            tracing::warn!("project_hosts error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
