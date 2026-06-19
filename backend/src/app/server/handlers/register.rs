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
use crate::app::databases::postgres::queries::insert_agent;

#[derive(Debug, Deserialize)]
pub struct RegisterReq {
    pub hostname: String,
    pub ip: String,
    pub version: String,
}

pub async fn register_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterReq>,
) -> impl IntoResponse {
    let agent_id = Uuid::new_v4();

    if let Err(e) =
        insert_agent::insert(&state.pg, agent_id, &req.ip, &req.hostname, &req.version).await
    {
        tracing::warn!("register error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        );
    }

    tracing::info!(
        "registered agent  id={agent_id}  ip={}  hostname={}",
        req.ip,
        req.hostname
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "status": "registered",
            "agent_id": agent_id.to_string(),
        })),
    )
}
