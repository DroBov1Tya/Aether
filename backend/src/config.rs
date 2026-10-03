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
    pub server_path: String,
    pub api_key: String,
    pub clickhouse_url: String,
    pub clickhouse_user: String,
    pub clickhouse_password: String,
    pub s3_endpoint: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_bucket: String,
    pub shodan_api_key: String,
    pub allow_apikey_enroll: bool,
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
        Self {
            server_path: env_or("SERVER_PATH", "0.0.0.0:8080"),
            api_key: env("API_KEY"),
            clickhouse_url: env("CLICKHOUSE_URL"),
            clickhouse_user: env("CLICKHOUSE_USER"),
            clickhouse_password: env("CLICKHOUSE_PASSWORD"),
            s3_endpoint: env("S3_ENDPOINT"),
            s3_access_key: env("S3_ACCESS_KEY"),
            s3_secret_key: env("S3_SECRET_KEY"),
            s3_bucket: env("S3_BUCKET"),
            shodan_api_key: env_or("SHODAN_API_KEY", ""),
            allow_apikey_enroll: env_or("ALLOW_APIKEY_ENROLL", "false")
                .parse()
                .unwrap_or(false),
        }
    }
}

pub fn init() {
    CONFIG
        .set(Config::load())
        .expect("Config already initialized");
}

pub fn cfg() -> &'static Config {
    CONFIG.get().expect("config not initialized")
}
