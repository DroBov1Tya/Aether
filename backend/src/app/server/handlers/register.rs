use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::app::databases::clickhouse::queries::agents;

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
}

pub async fn register_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterReq>,
) -> impl IntoResponse {
    let ip = req.ip.as_deref().unwrap_or("");
    let port = req.port.unwrap_or(8020);
    let max_concurrent_tasks = req.max_concurrent_tasks.unwrap_or(10);

    match agents::find_by_ip_port(&state.ch, ip, port).await {
        Ok(Some(id_str)) => {
            let agent_id = match Uuid::parse_str(&id_str) {
                Ok(id) => id,
                Err(_) => Uuid::new_v4(),
            };
            tracing::info!("reusing agent  id={agent_id}  ip={ip}  port={port}");
            return (
                StatusCode::OK,
                Json(json!({
                    "status": "registered",
                    "agent_id": agent_id.to_string(),
                })),
            );
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("register lookup error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            );
        }
    }

    let agent_id = Uuid::new_v4();

    if let Err(e) = agents::insert(
        &state.ch,
        agent_id,
        ip,
        &req.hostname,
        &req.version,
        port,
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
        "registered agent  id={agent_id}  ip={}  hostname={}  port={}",
        req.ip.as_deref().unwrap_or("unknown"),
        req.hostname,
        port,
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "status": "registered",
            "agent_id": agent_id.to_string(),
        })),
    )
}
