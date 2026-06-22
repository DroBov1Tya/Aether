use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::{AppState, workers};

#[derive(Deserialize, Default)]
pub struct Targets {
    pub ips: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
    pub cidrs: Option<Vec<String>>,
    pub ranges: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
pub struct Settings {
    port_range: Option<String>,
    port_mode: Option<String>,
    threads: Option<u32>,
    timeout_ms: Option<u64>,
    proxy: Option<String>,
    require_http_port: Option<u16>,
}

#[derive(Deserialize)]
pub struct CreateTaskReq {
    #[serde(default)]
    targets: Targets,
    methods: Option<Vec<String>>,
    #[serde(default)]
    settings: Settings,
    #[serde(default = "default_priority")]
    priority: String,
    scheduled_at: Option<String>,
}

fn default_priority() -> String {
    "normal".to_string()
}

pub async fn create_task(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTaskReq>,
) -> impl IntoResponse {
    let id = Uuid::new_v4();

    let pipe = workers::runner::PipelineTask {
        task_id: id,
        cidrs: req.targets.cidrs,
        ranges: req.targets.ranges,
        ips: req.targets.ips,
        domains: req.targets.domains,
        methods: req.methods,
    };
    workers::runner::run_pipeline(pipe, &state.ch, &mut state.redis.clone(), &state.cfg.api_key).await;

    (
        StatusCode::CREATED,
        Json(json!({ "status": "created", "task_id": id.to_string() })),
    )
}
