use std::sync::OnceLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    pub db_location: String,
    pub scans_output_path: String,
    pub server_path: String,
    pub external_server_path: String,
    pub scan_timeout: u64,
    pub hxn_delay: u64,
    pub image_output_path: String,
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
        let mut db_loc =
            std::env::var("DB_LOCATION").unwrap_or_else(|_| "sqlite:./db/agent.db".to_string());

        if db_loc.starts_with("sqlite:./") {
            if let Ok(exe_path) = std::env::current_exe() {
                if let Some(parent) = exe_path.parent() {
                    let new_prefix = format!("sqlite:{}/", parent.to_string_lossy());
                    db_loc = db_loc.replace("sqlite:./", &new_prefix);
                }
            }
        }

        Self {
            db_location: db_loc,
            scans_output_path: std::env::var("SCANS_OUTPUT_PATH")
                .unwrap_or_else(|_| "scans_output".to_string()),
            server_path: std::env::var("SERVER_PATH")
                .unwrap_or_else(|_| "localhost:8020".to_string()),

            external_server_path: env("EXTERNAL_SERVER_PATH"),

            scan_timeout: env_or("SCAN_TIMEOUT", "60").parse().unwrap_or(60),
            hxn_delay: env_or("HXN_DELAY", "5").parse().unwrap_or(5),
            image_output_path: std::env::var("IMAGE_OUTPUT_PATH")
                .unwrap_or_else(|_| "./images_output".to_string()),
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
