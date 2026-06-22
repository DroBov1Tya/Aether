use crate::config::{self, Config};
use anyhow::Result;
use clickhouse::Client as ChClient;
use redis::aio::ConnectionManager;
use s3::bucket::Bucket;
use std::sync::Arc;
use tokio::sync::broadcast;

mod databases;
mod server;
mod workers;

#[derive(Clone)]
pub struct AppState {
    pub cfg: &'static Config,
    pub ch: ChClient,
    pub s3: Bucket,
    pub redis: ConnectionManager,
    pub shutdown: broadcast::Sender<()>,
}

pub struct Application {
    state: Arc<AppState>,
}

impl Application {
    pub async fn build() -> Result<Self> {
        tracing::info!("⏳ Building...");

        config::init();
        let cfg = config::cfg();
        let (shutdown, _) = broadcast::channel(1);

        tracing::info!("  clickhouse_url  = {}", cfg.clickhouse_url);
        tracing::info!("  s3_endpoint     = {}", cfg.s3_endpoint);
        tracing::info!("  redis_url       = {}", cfg.redis_url);

        let ch = databases::clickhouse::new(
            &cfg.clickhouse_url,
            &cfg.clickhouse_user,
            &cfg.clickhouse_password,
        )?;
        tracing::info!("  ✅ ClickHouse connected");

        let s3 = databases::s3::new(
            &cfg.s3_endpoint,
            &cfg.s3_access_key,
            &cfg.s3_secret_key,
            &cfg.s3_bucket,
        )?;
        tracing::info!("  ✅ S3/MinIO connected");

        let redis = databases::redis::new(&cfg.redis_url).await?;
        tracing::info!("  ✅ Redis connected");

        let state = Arc::new(AppState {
            cfg,
            ch,
            s3,
            redis,
            shutdown,
        });

        Ok(Self { state })
    }

    pub async fn run(self) -> Result<()> {
        tracing::info!("🚀 Starting...");

        let server_state = Arc::clone(&self.state);

        let server_handle = tokio::spawn(async move {
            match server::api::start(server_state).await {
                Ok(()) => tracing::info!("✅ REST API stopped"),
                Err(e) => tracing::warn!("⚠️ REST API error: {}", e),
            }
        });

        tracing::info!("✨ Ready");

        tokio::signal::ctrl_c().await.ok();
        tracing::info!("🛑 Shutdown");
        let _ = self.state.shutdown.send(());

        let _ = server_handle.await;

        Ok(())
    }
}
