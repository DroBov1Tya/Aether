use crate::config::{self, Config};
use anyhow::Result;
use clickhouse::Client as ChClient;
use s3::bucket::Bucket;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;

mod databases;
mod server;

#[derive(Clone)]
pub struct AppState {
    pub cfg: &'static Config,
    pub ch: ChClient,
    pub pg: PgPool,
    pub s3: Bucket,
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

        tracing::info!("  db_location     = {}", cfg.db_location);
        tracing::info!("  clickhouse_url  = {}", cfg.clickhouse_url);
        tracing::info!("  s3_endpoint     = {}", cfg.s3_endpoint);

        let pg = databases::postgres::new(&cfg.db_location).await?;
        tracing::info!("  ✅ PostgreSQL connected");

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

        let state = Arc::new(AppState {
            cfg,
            ch,
            pg,
            s3,
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
