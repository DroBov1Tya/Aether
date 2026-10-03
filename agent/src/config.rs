use std::sync::OnceLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn init_logger() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(false)
                .with_ansi(false),
        )
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
}

#[derive(Debug)]
pub struct Config {
    pub scans_output_path: String,
    pub server_path: String,
    pub external_server_path: String,
    pub port: u16,
    pub hxn_delay: u64,
    pub scan_cooldown: u64,
    pub api_key: String,
    pub enroll_token: String,
    pub agent_name: String,
    pub agent_token: String,
    pub agent_id: String,
    pub credentials_path: String,
    pub proxies: Vec<String>,
    pub max_concurrent_scans: usize,
    pub max_concurrent_tasks: u8,
    pub rustscan_max_batch: u32,
    pub masscan_enabled: bool,
    pub masscan_max_rate: u32,
    pub masscan_ports: String,
    pub masscan_extra_args: String,
    pub httpx_threads: u32,
    pub httpx_rate_limit: u32,
    pub httpx_timeout: u64,
    pub httpx_screenshots: bool,
    pub httpx_web_ports: Vec<u16>,
    pub nuclei_enabled: bool,
    pub nuclei_severity: String,
    pub nuclei_tags: String,
    pub nuclei_rate_limit: u32,
    pub nuclei_concurrency: u32,
    pub nuclei_timeout: u64,
    pub tlsx_concurrency: u32,
    pub tlsx_timeout: u64,
    pub dnsx_threads: u32,
    pub geo_enabled: bool,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("Missing env var: {}", key))
}

pub fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Config {
    fn load() -> Self {
        let _ = dotenvy::dotenv();

        let proxies_str = std::env::var("PROXIES").unwrap_or_default();
        let proxies: Vec<String> = proxies_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            scans_output_path: std::env::var("SCANS_OUTPUT_PATH")
                .unwrap_or_else(|_| "scans_output".to_string()),
            port: std::env::var("AGENT_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8020),
            server_path: std::env::var("SERVER_PATH")
                .unwrap_or_else(|_| format!("0.0.0.0:{}", 8020)),
            external_server_path: env("EXTERNAL_SERVER_PATH"),
            hxn_delay: env_or("HXN_DELAY", "5").parse().unwrap_or(5),
            scan_cooldown: env_or("SCAN_COOLDOWN", "60").parse().unwrap_or(60),
            api_key: env_or("API_KEY", ""),
            enroll_token: std::env::var("ENROLL_TOKEN").unwrap_or_default(),
            agent_name: std::env::var("AGENT_NAME").unwrap_or_default(),
            agent_token: std::env::var("AGENT_TOKEN").unwrap_or_default(),
            agent_id: std::env::var("AGENT_ID").unwrap_or_default(),
            credentials_path: std::env::var("AGENT_CREDENTIALS_PATH")
                .unwrap_or_else(|_| format!("{}/.aether-agent.json", std::env::var("HOME").unwrap_or_default())),
            proxies,
            max_concurrent_scans: env_or("MAX_CONCURRENT_SCANS", "3").parse().unwrap_or(3),
            max_concurrent_tasks: env_or("MAX_CONCURRENT_TASKS", "10").parse().unwrap_or(10),
            rustscan_max_batch: env_or("RUSTSCAN_MAX_BATCH", "100").parse().unwrap_or(100),
            masscan_enabled: env_or("MASSCAN_ENABLED", "false").parse().unwrap_or(false),
            masscan_max_rate: env_or("MASSCAN_MAX_RATE", "1000").parse().unwrap_or(1000),
            masscan_ports: env_or("MASSCAN_PORTS", "80,443,8080,8443,22,21,25,3389,3306,5432,6379,9200,27017"),
            masscan_extra_args: env_or("MASSCAN_EXTRA_ARGS", ""),
            httpx_threads: env_or("HTTPX_THREADS", "50").parse().unwrap_or(50),
            httpx_rate_limit: env_or("HTTPX_RATE_LIMIT", "150").parse().unwrap_or(150),
            httpx_timeout: env_or("HTTPX_TIMEOUT", "10").parse().unwrap_or(10),
            httpx_screenshots: env_or("HTTPX_SCREENSHOTS", "true").parse().unwrap_or(true),
            httpx_web_ports: env_or("HTTPX_WEB_PORTS", "80,443,8080,8443,8000,8888")
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect(),
            nuclei_enabled: env_or("NUCLEI_ENABLED", "true").parse().unwrap_or(true),
            nuclei_severity: env_or("NUCLEI_SEVERITY", "critical,high,medium"),
            nuclei_tags: env_or("NUCLEI_TAGS", ""),
            nuclei_rate_limit: env_or("NUCLEI_RATE_LIMIT", "150").parse().unwrap_or(150),
            nuclei_concurrency: env_or("NUCLEI_CONCURRENCY", "25").parse().unwrap_or(25),
            nuclei_timeout: env_or("NUCLEI_TIMEOUT", "10").parse().unwrap_or(10),
            tlsx_concurrency: env_or("TLSX_CONCURRENCY", "50").parse().unwrap_or(50),
            tlsx_timeout: env_or("TLSX_TIMEOUT", "5").parse().unwrap_or(5),
            dnsx_threads: env_or("DNSX_THREADS", "100").parse().unwrap_or(100),
            geo_enabled: env_or("GEO_ENABLED", "true").parse().unwrap_or(true),
        }
    }
}

pub fn init() {
    CONFIG
        .set(Config::load())
        .expect("Config already initialized");
}

pub fn cfg() -> &'static Config {
    CONFIG
        .get()
        .expect("Config not initialized — call config::init() first")
}
