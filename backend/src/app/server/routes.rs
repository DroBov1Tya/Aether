use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

use super::handlers::{getlast, host, hxn, nmap, register, rustscan, search, stats, whatweb};
use crate::app::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/checkout/rustscan", post(rustscan::save_data))
        .route("/api/checkout/nmap", post(nmap::save_data))
        .route("/api/checkout/whatweb", post(whatweb::save_data))
        .route("/api/checkout/hxn", post(hxn::save_data))
        //
        .route("/api/register/agent", post(register::register_agent))
        //
        .route("/api/host/{ip}", get(host::get_host))
        //
        .route("/api/search/ip", get(search::search_ip))
        .route("/api/search/domain", get(search::search_domain))
        .route("/api/search/port", get(search::search_port))
        .route("/api/search/title", get(search::search_title))
        .route("/api/search/technology", get(search::search_technology))
        .route("/api/search/protocol", get(search::search_protocol))
        .route("/api/search/service", get(search::search_service))
        .route("/api/search/image", get(search::search_image))
        //
        .route("/api/stats/ports", get(stats::stats_ports))
        .route("/api/stats/services", get(stats::stats_services))
        .route("/api/stats/technologies", get(stats::stats_technologies))
        .route("/api/stats/summary", get(stats::stats_summary))
        //
        .route("/api/getlast", get(getlast::get_last_scans))
        //
        .with_state(state)
}
