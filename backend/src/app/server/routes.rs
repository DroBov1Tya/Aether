use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

use super::handlers::{checkout, getlast, host, register, screenshots, search, stats, tasks};
use crate::app::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/api/checkout/rustscan",
            post(checkout::rustscan::save_data),
        )
        .route("/api/checkout/nmap", post(checkout::nmap::save_data))
        .route("/api/checkout/whatweb", post(checkout::whatweb::save_data))
        .route("/api/checkout/hxn", post(checkout::hxn::save_data))
        .route("/api/checkout/dns", post(checkout::dns::save_data))
        .route("/api/checkout/ssl", post(checkout::ssl::save_data))
        .route("/api/checkout/whois", post(checkout::whois::save_data))
        //
        .route("/api/register/agent", post(register::register_agent))
        //
        .route("/api/host/{ip}", get(host::get_host))
        .route("/api/host/{ip}/history", get(host::host_history))
        .route("/api/host/{ip}/snapshots", get(host::host_snapshots))
        //
        .route("/api/search/ip", get(search::ip::search_ip))
        .route("/api/search/domain", get(search::domain::search_domain))
        .route("/api/search/port", get(search::port::search_port))
        .route("/api/search/title", get(search::title::search_title))
        .route(
            "/api/search/technology",
            get(search::technology::search_technology),
        )
        .route(
            "/api/search/protocol",
            get(search::protocol::search_protocol),
        )
        .route("/api/search/service", get(search::service::search_service))
        .route("/api/search/image", get(search::image::search_image))
        .route("/api/search/dns", get(search::dns::search_dns))
        .route("/api/search/ssl", get(search::ssl::search_ssl))
        .route(
            "/api/search/aggregated",
            get(search::aggregated::search_aggregated),
        )
        //
        .route(
            "/api/screenshots",
            get(screenshots::list_screenshots_thumbnails),
        )
        .route(
            "/api/screenshots/count",
            get(screenshots::list_screenshots_count),
        )
        .route(
            "/api/screenshots/thumbnails",
            get(screenshots::list_screenshots_thumbnails),
        )
        .route("/api/screenshots/{ip}/{port}", get(host::get_screenshot))
        .route("/api/stats/ports", get(stats::ports::stats_ports))
        .route("/api/stats/services", get(stats::services::stats_services))
        .route(
            "/api/stats/technologies",
            get(stats::technologies::stats_technologies),
        )
        .route("/api/stats/summary", get(stats::summary::stats_summary))
        //
        .route("/api/getlast", get(getlast::get_last_scans))
        //
        .route("/api/tasks/create", post(tasks::create_task))
        .with_state(state)
}
