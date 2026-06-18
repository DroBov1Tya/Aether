use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::app::databases::clickhouse::queries::search;
use crate::app::databases::s3::queries::download as s3_download;
use crate::app::AppState;

#[derive(Deserialize)]
pub struct QParam {
    pub q: String,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

fn default_page() -> u32 {
    1
}
fn default_per_page() -> u32 {
    50
}

#[derive(Deserialize)]
pub struct PortParam {
    pub q: u16,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

impl QParam {
    fn offset(&self) -> u32 {
        self.per_page * (self.page.saturating_sub(1))
    }
}

impl PortParam {
    fn offset(&self) -> u32 {
        self.per_page * (self.page.saturating_sub(1))
    }
}

pub async fn search_ip(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QParam>,
) -> impl IntoResponse {
    match search::search_by_ip(&state.ch, &params.q, params.per_page, params.offset()).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "data": data })),
        ),
        Err(e) => {
            tracing::warn!("search_ip error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

pub async fn search_domain(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QParam>,
) -> impl IntoResponse {
    match search::search_by_domain(&state.ch, &params.q, params.per_page, params.offset()).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "data": data })),
        ),
        Err(e) => {
            tracing::warn!("search_domain error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

pub async fn search_port(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PortParam>,
) -> impl IntoResponse {
    match search::search_by_port(&state.ch, params.q, params.per_page, params.offset()).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "data": data })),
        ),
        Err(e) => {
            tracing::warn!("search_port error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

pub async fn search_title(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QParam>,
) -> impl IntoResponse {
    match search::search_by_title(&state.ch, &params.q, params.per_page, params.offset()).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "data": data })),
        ),
        Err(e) => {
            tracing::warn!("search_title error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

pub async fn search_technology(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QParam>,
) -> impl IntoResponse {
    match search::search_by_technology(&state.ch, &params.q, params.per_page, params.offset()).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "data": data })),
        ),
        Err(e) => {
            tracing::warn!("search_technology error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

pub async fn search_protocol(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QParam>,
) -> impl IntoResponse {
    match search::search_by_protocol(&state.ch, &params.q, params.per_page, params.offset()).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "data": data })),
        ),
        Err(e) => {
            tracing::warn!("search_protocol error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

pub async fn search_service(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QParam>,
) -> impl IntoResponse {
    match search::search_by_service(&state.ch, &params.q, params.per_page, params.offset()).await {
        Ok(data) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "data": data })),
        ),
        Err(e) => {
            tracing::warn!("search_service error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}

pub async fn search_image(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QParam>,
) -> impl IntoResponse {
    let rows = match search::search_by_image(&state.ch, &params.q, params.per_page, params.offset()).await {
        Ok(data) => data,
        Err(e) => {
            tracing::warn!("search_image error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            );
        }
    };

    let mut data: Vec<serde_json::Value> = Vec::with_capacity(rows.len());
    for row in rows {
        let s3_key = row["s3_key"].as_str().unwrap_or_default().to_string();
        let image = if !s3_key.is_empty() {
            match s3_download::get_object(&state.s3, &s3_key).await {
                Ok(bytes) => Some(STANDARD.encode(&bytes)),
                Err(e) => {
                    tracing::warn!("search_image  s3 download failed: {e}");
                    None
                }
            }
        } else {
            None
        };

        let mut item = row.clone();
        if let Some(img) = image {
            item.as_object_mut()
                .map(|obj| obj.insert("image_base64".to_string(), json!(img)));
        }
        data.push(item);
    }

    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "data": data })),
    )
}
