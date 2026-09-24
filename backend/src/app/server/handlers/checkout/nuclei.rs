use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::common::CheckoutReq;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::insert_nuclei;

pub async fn save_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutReq>,
) -> impl IntoResponse {
    let project = req.project.as_deref().unwrap_or("global");

    let items: Vec<insert_nuclei::NucleiRow> = req
        .body
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    insert_nuclei::from_json(
                        &req.target,
                        &req.scan_uid,
                        project,
                        req.country.clone(),
                        v,
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let count = items.len();
    for row in items {
        if let Err(e) = insert_nuclei::insert(&state.ch, row).await {
            tracing::warn!("nuclei insert error: {e}");
        }
    }

    tracing::info!("nuclei  {}  {} findings (project={})", req.target, count, project);
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
