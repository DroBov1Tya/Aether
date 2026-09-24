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
use crate::app::databases::clickhouse::queries::tasks;
use crate::app::workers::controller;

#[derive(Deserialize, Default)]
pub struct Targets {
    pub ips: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
    pub cidrs: Option<Vec<String>>,
    pub ranges: Option<Vec<String>>,
}

#[derive(Deserialize, Default, serde::Serialize)]
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

const TARGET_CHUNK: u32 = 1024;

fn expand_targets(t: &Targets) -> Vec<String> {
    let mut out = Vec::new();

    for cidr in t.cidrs.iter().flatten() {
        match controller::parse_cidr(cidr) {
            Some((start, end)) => out.extend(split_range(start, end)),
            None if !cidr.trim().is_empty() => out.push(cidr.trim().to_string()),
            None => {}
        }
    }

    for range in t.ranges.iter().flatten() {
        match controller::parse_range(range) {
            Some((start, end)) => out.extend(split_range(start, end)),
            None if !range.trim().is_empty() => out.push(range.trim().to_string()),
            None => {}
        }
    }

    for ip in t.ips.iter().flatten() {
        if !ip.trim().is_empty() {
            out.push(ip.trim().to_string());
        }
    }

    for domain in t.domains.iter().flatten() {
        if !domain.trim().is_empty() {
            out.push(domain.trim().to_string());
        }
    }

    out
}

fn split_range(start: u32, end: u32) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = start;
    while cur <= end {
        let chunk_end = cur.saturating_add(TARGET_CHUNK - 1).min(end);
        if chunk_end == cur {
            out.push(controller::u32_to_ipv4(cur).to_string());
        } else {
            out.push(format!(
                "{}-{}",
                controller::u32_to_ipv4(cur),
                controller::u32_to_ipv4(chunk_end)
            ));
        }
        cur = chunk_end.saturating_add(1);
        if cur == start {
            break;
        }
    }
    out
}

pub async fn create_task(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTaskReq>,
) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    let targets = expand_targets(&req.targets);

    if targets.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "error": "no targets provided" })),
        );
    }

    let payload = json!({
        "settings": {
            "port_range": req.settings.port_range,
            "port_mode": req.settings.port_mode,
            "threads": req.settings.threads,
            "timeout_ms": req.settings.timeout_ms,
            "proxy": req.settings.proxy,
            "require_http_port": req.settings.require_http_port,
        },
        "methods": req.methods,
        "priority": req.priority,
        "scheduled_at": req.scheduled_at,
    });
    let payload = serde_json::to_string(&payload).unwrap_or_default();

    match tasks::enqueue(&state.ch, &id, &targets, &payload).await {
        Ok(n) => {
            tracing::info!("task {} queued: {} targets", id, n);
            (
                StatusCode::CREATED,
                Json(json!({
                    "status": "queued",
                    "task_id": id,
                    "targets": n,
                })),
            )
        }
        Err(e) => {
            tracing::warn!("task {} enqueue error: {e}", id);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
