use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use std::sync::Arc;

use super::QParam;
use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;
use crate::app::databases::s3::queries::download as s3_download;

pub async fn search_image(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QParam>,
) -> impl IntoResponse {
    let rows = match search::search_by_image(&state.ch, &params.q, params.per_page, params.offset())
        .await
    {
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
                    tracing::warn!("search_image s3 download failed: {e}");
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
        Json(
            json!({ "status": "ok", "page": params.page, "per_page": params.per_page, "data": data }),
        ),
    )
}
