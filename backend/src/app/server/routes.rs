use axum::{Router, routing::post};
use std::sync::Arc;

use super::handlers::{hxn, nmap, register, rustscan, whatweb};
use crate::app::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/checkout/rustscan", post(rustscan::save_data))
        .route("/api/checkout/nmap", post(nmap::save_data))
        .route("/api/checkout/whatweb", post(whatweb::save_data))
        .route("/api/checkout/hxn", post(hxn::save_data))
        //
        .route("/api/register/agent", post(register::register_agent))
        .with_state(state)
}
