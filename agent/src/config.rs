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
    pub proxies: Vec<String>,
    pub max_concurrent_scans: usize,
    pub max_concurrent_tasks: u8,
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
        // Load variables from .env file (only if present)
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
            api_key: env("API_KEY"),
            proxies,
            max_concurrent_scans: env_or("MAX_CONCURRENT_SCANS", "3").parse().unwrap_or(3),
            max_concurrent_tasks: env_or("MAX_CONCURRENT_TASKS", "10").parse().unwrap_or(10),
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
