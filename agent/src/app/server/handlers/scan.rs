use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use std::sync::Arc;

use crate::app::AppState;
use crate::app::tools;

#[derive(Debug, Deserialize)]
pub struct ScanTarget {
    pub target: String,
}

pub async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(scan_target): Json<ScanTarget>,
) -> impl IntoResponse {
    let target = scan_target.target.clone();

    tokio::task::spawn(async move {
        let mut ports: Vec<i64> = Vec::new();

        match tools::rustscan::run_rustscan(
            &state.cfg.external_server_path,
            &target,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(p) => {
                tracing::info!("✅ rustscan  {}  ports={:?}", target, p);
                ports = p;
            }
            Err(e) => {
                tracing::warn!("❌ rustscan  {}  err={e}", target);
                return;
            }
        }

        let ports_str = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let http_ports = match tools::nmap::run_nmap(
            &state.cfg.external_server_path,
            &target,
            &ports_str,
            &state.cfg.scans_output_path,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(h) => {
                tracing::info!("✅ nmap  {}  http={:?}", target, h);
                h
            }
            Err(e) => {
                tracing::warn!("❌ nmap  {}  err={e}", target);
                Vec::new()
            }
        };

        match tools::whatweb::run_whatweb(
            &state.cfg.external_server_path,
            &target,
            &http_ports,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(_) => tracing::info!("✅ whatweb  {}  ports={:?}", target, http_ports),
            Err(e) => tracing::warn!("❌ whatweb  {}  err={e}", target),
        }

        match tools::hxn::run_screenshot(
            &state.cfg.external_server_path,
            &target,
            &state.cfg.hxn_delay,
            &http_ports,
            &state.cfg.api_key,
        )
        .await
        {
            Ok(_) => tracing::info!("✅ hxn  {}  ports={:?}", target, http_ports),
            Err(e) => tracing::warn!("❌ hxn  {}  err={e}", target),
        }
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "started" })),
    )
}
