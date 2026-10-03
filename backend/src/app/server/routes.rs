use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

use super::handlers::{
    agents, checkout, enroll, geo_ranges, getlast, host, projects, proxies, screenshots, search,
    shodan, stats, tasks,
};
use crate::app::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(super::handlers::health::health_check))
        .route(
            "/api/checkout/rustscan",
            post(checkout::rustscan::save_data),
        )
        .route(
            "/api/checkout/masscan",
            post(checkout::masscan::save_data),
        )
        .route("/api/checkout/nmap", post(checkout::nmap::save_data))
        .route("/api/checkout/whatweb", post(checkout::whatweb::save_data))
        .route("/api/checkout/httpx", post(checkout::httpx::save_data))
        .route("/api/checkout/nuclei", post(checkout::nuclei::save_data))
        .route("/api/checkout/hxn", post(checkout::hxn::save_data))
        .route("/api/checkout/fuzzing", post(checkout::fuzzing::save_data))
        .route("/api/checkout/dns", post(checkout::dns::save_data))
        .route("/api/checkout/ssl", post(checkout::ssl::save_data))
        .route("/api/checkout/whois", post(checkout::whois::save_data))
        .route("/api/checkout/geo", post(checkout::geo::save_data))
        .route("/api/register/agent", post(agents::register_agent))
        .route(
            "/api/enroll-tokens",
            get(enroll::list_enroll_tokens).post(enroll::create_enroll_token),
        )
        .route(
            "/api/enroll-tokens/{token_hash}",
            axum::routing::delete(enroll::revoke_enroll_token),
        )
        .route(
            "/api/agents/{agent_id}/heartbeat",
            post(agents::agent_heartbeat),
        )
        .route(
            "/api/agents/{agent_id}/tasks/claim",
            post(agents::agent_claim_tasks),
        )
        .route(
            "/api/agents/{agent_id}/tasks/{task_id}/finish",
            post(agents::agent_finish_task),
        )
        .route("/api/agents", get(agents::list_agents))
        .route(
            "/api/agents/{agent_id}",
            axum::routing::patch(agents::update_agent)
                .delete(agents::revoke_agent),
        )
        .route("/api/tasks", get(agents::list_tasks))
        .route("/api/tasks/{task_id}/progress", get(agents::task_progress))
        .route("/api/host/{ip}", get(host::get_host))
        .route("/api/host/{ip}/history", get(host::host_history))
        .route("/api/host/{ip}/snapshots", get(host::host_snapshots))
        .route("/api/search/ip", get(search::ip::search_ip))
        .route("/api/search/domain", get(search::domain::search_domain))
        .route("/api/search/port", get(search::port::search_port))
        .route("/api/search/title", get(search::title::search_title))
        .route("/api/search/header", get(search::header::search_header))
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
        .route("/api/stats/countries", get(stats::geo::stats_countries))
        .route("/api/stats/asns", get(stats::geo::stats_asns))
        .route("/api/stats/orgs", get(stats::geo::stats_orgs))
        .route("/api/getlast", get(getlast::get_last_scans))
        .route("/api/import", post(projects::import_data))
        .route("/api/projects", get(projects::list_projects))
        .route("/api/projects/hosts", get(projects::project_hosts))
        //
        // Proxy pool: shared by agents (GET) and the web UI (CRUD).
        .route(
            "/api/proxies",
            get(proxies::list_proxies)
                .post(proxies::add_proxies)
                .delete(proxies::delete_all_proxies),
        )
        .route("/api/proxies/one", axum::routing::delete(proxies::delete_one_proxy))
        .route("/api/tasks/create", post(tasks::create_task))
        .route("/api/geo/country-asns", get(geo_ranges::list_country_asns))
        .route("/api/geo/asn-prefixes", get(geo_ranges::list_asn_prefixes))
        .route("/api/shodan/info", get(shodan::api_info))
        .route("/api/shodan/search", get(shodan::search))
        .route("/api/shodan/import", post(shodan::import_search))
        .route("/api/shodan/host", get(shodan::host_lookup))
        .route("/api/shodan/import-hosts", post(shodan::import_hosts))
        .with_state(state)
}
