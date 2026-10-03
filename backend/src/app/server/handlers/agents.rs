use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::{enroll, tasks as ch_tasks, tokens};

fn header_key(headers: &HeaderMap) -> Option<&str> {
    headers.get("x-api-key").and_then(|v| v.to_str().ok())
}

async fn verify_token(
    client: &clickhouse::Client,
    agent_id: &str,
    headers: &HeaderMap,
) -> Result<bool, StatusCode> {
    let Some(presented) = header_key(headers) else {
        return Ok(false);
    };
    let Some(resolved) = tokens::resolve_token(client, presented).await else {
        return Ok(false);
    };
    Ok(resolved == agent_id && tokens::is_valid(client, presented).await)
}

macro_rules! auth_check {
    ($state:expr, $agent_id:expr, $headers:expr) => {
        match verify_token(&$state.ch, &$agent_id, &$headers).await {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "status": "error", "error": "invalid agent token" })),
                );
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "status": "error", "error": "auth check failed" })),
                );
            }
        }
    };
}

#[derive(Deserialize)]
pub struct RegisterReq {
    pub hostname: String,
    pub version: String,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub kernel: Option<String>,
    pub ip: Option<String>,
    pub port: Option<i32>,
    pub max_concurrent_tasks: Option<u8>,
    pub agent_id: Option<String>,
    pub name: Option<String>,
}

pub async fn register_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterReq>,
) -> impl IntoResponse {
    let presented = header_key(&headers).unwrap_or("");
    let enroll_token = headers
        .get("x-enroll-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let authorized = if !enroll_token.is_empty() {
        enroll::consume(&state.ch, enroll_token).await
    } else {
        state.cfg.allow_apikey_enroll && !presented.is_empty() && presented == state.cfg.api_key
    };

    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "error": "enrollment not authorized" })),
        );
    }

    let agent_id = req
        .agent_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let token = format!("{agent_id}-{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());

    let ip = req.ip.as_deref().unwrap_or("");
    let port = req.port.unwrap_or(8020) as u16;
    let max_concurrent_tasks = req.max_concurrent_tasks.unwrap_or(10);
    let name = req
        .name
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&req.hostname);

    if let Err(e) = tokens::upsert(
        &state.ch,
        &agent_id,
        &token,
        name,
        ip,
        port,
        &req.version,
        req.os.as_deref().unwrap_or(""),
        req.arch.as_deref().unwrap_or(""),
        req.kernel.as_deref().unwrap_or(""),
        max_concurrent_tasks,
    )
    .await
    {
        tracing::warn!("register error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }

    tracing::info!(
        "registered agent  id={agent_id}  ip={ip}  hostname={}  port={port}",
        req.hostname
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "status": "registered",
            "agent_id": agent_id,
            "token": token,
        })),
    )
}

#[derive(Deserialize)]
pub struct HeartbeatReq {
    pub busy: Option<u8>,
}

pub async fn agent_heartbeat(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatReq>,
) -> impl IntoResponse {
    auth_check!(state, agent_id, headers);

    match tokens::heartbeat(&state.ch, &agent_id, req.busy.unwrap_or(0)).await {
        Ok(capacity) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "max_concurrent_tasks": capacity })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}

#[derive(Deserialize)]
pub struct UpdateAgentReq {
    pub max_concurrent_tasks: u8,
}

pub async fn update_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    Json(req): Json<UpdateAgentReq>,
) -> impl IntoResponse {
    let capacity = req.max_concurrent_tasks.clamp(1, 100);
    match tokens::set_concurrency(&state.ch, &agent_id, capacity).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "max_concurrent_tasks": capacity })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}

#[derive(Deserialize)]
pub struct ClaimQuery {
    pub limit: Option<u32>,
}

pub async fn agent_claim_tasks(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Query(q): Query<ClaimQuery>,
) -> impl IntoResponse {
    auth_check!(state, agent_id, headers);

    let limit = q.limit.unwrap_or(5).clamp(1, 20);
    match ch_tasks::claim(&state.ch, &agent_id, limit).await {
        Ok(batch) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "data": batch })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}

#[derive(Deserialize)]
pub struct FinishReq {
    pub task_id: Option<String>,
    pub success: Option<bool>,
    pub error: Option<String>,
}

pub async fn agent_finish_task(
    State(state): State<Arc<AppState>>,
    Path((agent_id, task_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<FinishReq>,
) -> impl IntoResponse {
    auth_check!(state, agent_id, headers);

    let raw_id = req.task_id.clone().unwrap_or(task_id);
    let Some(id_num) = raw_id.parse::<u64>().ok() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "missing task_id" })),
        );
    };

    let ok = req.success.unwrap_or(true);
    let err = req.error.as_deref().unwrap_or("");
    match ch_tasks::finish(&state.ch, id_num, &agent_id, ok, err).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}

pub async fn list_agents(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match tokens::list(&state.ch).await {
        Ok(list) => (StatusCode::OK, Json(json!({ "status": "ok", "data": list }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}

pub async fn revoke_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = tokens::set_status(&state.ch, &agent_id, "revoked").await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }
    (StatusCode::OK, Json(json!({ "status": "revoked", "agent_id": agent_id })))
}

#[derive(Deserialize)]
pub struct TaskListQuery {
    pub limit: Option<u32>,
}

pub async fn list_tasks(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TaskListQuery>,
) -> impl IntoResponse {
    match ch_tasks::task_list(&state.ch, q.limit.unwrap_or(50)).await {
        Ok(tasks) => (StatusCode::OK, Json(json!({ "status": "ok", "data": tasks }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}

pub async fn task_progress(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
) -> impl IntoResponse {
    match ch_tasks::task_progress(&state.ch, &task_id).await {
        Ok(t) => (StatusCode::OK, Json(json!({ "status": "ok", "data": t }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        ),
    }
}
