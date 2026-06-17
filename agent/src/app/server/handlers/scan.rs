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

        match tools::rustscan::run_rustscan(&state.cfg.external_server_path, &target).await {
            Ok(p) => {
                ports = p;
                tracing::info!(target = "scan", host = %target, ports = ?ports, "RustScan completed");
            }
            Err(e) => {
                tracing::warn!(target = "scan", host = %target, error = %e, "RustScan failed — skipping Nmap/WhatWeb/Hxn");
                return;
            }
        }

        let ports_str: String = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let http_ports = match tools::nmap::run_nmap(
            &state.cfg.external_server_path,
            &target,
            &ports_str,
            &state.cfg.scans_output_path,
        )
        .await
        {
            Ok(http_services) => {
                tracing::info!(
                    target = "scan",
                    host = %target,
                    http_ports = ?http_services,
                    "Nmap scan completed, found {} HTTP services",
                    http_services.len()
                );
                http_services
            }
            Err(e) => {
                tracing::error!(
                    target = "scan",
                    host = %target,
                    error = %e,
                    "Nmap scan failed"
                );
                Vec::new()
            }
        };

        match tools::whatweb::run_whatweb(&state.cfg.external_server_path, &target, &http_ports)
            .await
        {
            Ok(_) => tracing::info!(target = "scan", host = %target, "WhatWeb scan completed"),
            Err(e) => {
                tracing::error!(target = "scan", host = %target, error = %e, "WhatWeb scan failed")
            }
        }

        match tools::hxn::run_hxn(
            &state.cfg.external_server_path,
            &target,
            &state.cfg.hxn_delay,
            &http_ports,
        )
        .await
        {
            Ok(_) => tracing::info!(target = "scan", host = %target, "Hxn screenshot completed"),
            Err(e) => {
                tracing::error!(target = "scan", host = %target, error = %e, "Hxn scan failed")
            }
        }
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
           "status": "started",
        })),
    )
}
