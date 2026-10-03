use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::enroll;

fn admin_ok(state: &AppState, headers: &HeaderMap) -> bool {
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|k| k == state.cfg.api_key)
        .unwrap_or(false)
}

#[derive(Deserialize)]
pub struct CreateEnrollReq {
    pub label: Option<String>,
    pub max_uses: Option<u32>,
    pub expires_in_hours: Option<i64>,
}

pub async fn create_enroll_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateEnrollReq>,
) -> impl IntoResponse {
    if !admin_ok(&state, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "error": "invalid api key" })),
        );
    }

    let token = format!("enr_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let expires_at = req
        .expires_in_hours
        .filter(|h| *h > 0)
        .map(|h| chrono::Utc::now() + chrono::Duration::hours(h));

    if let Err(e) = enroll::create(
        &state.ch,
        &token,
        req.label.as_deref().unwrap_or(""),
        req.max_uses.unwrap_or(0),
        expires_at,
    )
    .await
    {
        tracing::warn!("create enroll token error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }

    (
        StatusCode::CREATED,
        Json(json!({ "status": "ok", "token": token })),
    )
}

pub async fn list_enroll_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !admin_ok(&state, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "error": "invalid api key" })),
        );
    }
    match enroll::list(&state.ch).await {
        Ok(list) => (StatusCode::OK, Json(json!({ "status": "ok", "data": list }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}

pub async fn revoke_enroll_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token_hash): Path<String>,
) -> impl IntoResponse {
    if !admin_ok(&state, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "error": "invalid api key" })),
        );
    }
    match enroll::revoke(&state.ch, &token_hash).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "revoked" }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}
