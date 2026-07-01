use axum::Json;
use serde_json::json;

pub async fn health_check() -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::OK, Json(json!({ "status": "ok" })))
}
