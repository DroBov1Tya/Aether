use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

pub async fn get_last_scans() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}
