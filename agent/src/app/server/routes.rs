use axum::{Router, routing::post};
use std::sync::Arc;

use super::handlers::scan;
use crate::app::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/scan", post(scan::start_scan))
        .with_state(state)
}
