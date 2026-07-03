use std::sync::Arc;

use clickhouse::Client as ChClient;
use tokio::sync::broadcast;

use crate::config::{self, Config};

fn rss_mb() -> u64 {
    if let Ok(f) = std::fs::read_to_string("/proc/self/statm") {
        if let Some(pages) = f.split_whitespace().next() {
            if let Ok(pages) = pages.parse::<u64>() {
                return pages * 4096 / 1024 / 1024;
            }
        }
    }
    0
}

mod databases;
mod server;
mod workers;

#[derive(Clone)]
pub struct AppState {
    pub cfg: &'static Config,
    pub ch: ChClient,
    pub s3: Option<s3::bucket::Bucket>,
    pub shutdown: broadcast::Sender<()>,
}

pub struct Application {
    state: Arc<AppState>,
}

impl Application {
    pub async fn build() -> anyhow::Result<Self> {
        tracing::info!("Building...");

        config::init();
        let cfg = config::cfg();
        let (shutdown, _) = broadcast::channel(1);

        tracing::info!("clickhouse_url = {}", cfg.clickhouse_url);

        let ch = databases::clickhouse::new(
            &cfg.clickhouse_url,
            &cfg.clickhouse_user,
            &cfg.clickhouse_password,
        )?;
        tracing::info!("ClickHouse connected");

        let s3 = databases::s3::new(
            &cfg.s3_endpoint,
            &cfg.s3_access_key,
            &cfg.s3_secret_key,
            &cfg.s3_bucket,
        )
        .await;
        if s3.is_some() {
            tracing::info!("S3/MinIO connected");
        } else {
            tracing::warn!("S3/MinIO unavailable — screenshot features disabled");
        }

        let state = Arc::new(AppState {
            cfg,
            ch,
            s3,
            shutdown,
        });

        Ok(Self { state })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!("Starting...");

        let server_state = Arc::clone(&self.state);

        let server_handle = tokio::spawn(async move {
            match server::api::start(server_state).await {
                Ok(()) => tracing::info!("REST API stopped"),
                Err(e) => tracing::warn!("REST API error: {}", e),
            }
        });

        let distributor_ch = self.state.ch.clone();
        let distributor_key = self.state.cfg.api_key.to_string();
        tokio::spawn(async move {
            workers::distributor::run(distributor_ch, distributor_key).await;
        });

        tracing::info!("Ready  RSS={}MB", rss_mb());

        let sigterm = async {
            if let Ok(mut s) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                s.recv().await;
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received"),
            _ = sigterm => tracing::info!("SIGTERM received"),
        }
        tracing::info!("Shutdown");
        let _ = self.state.shutdown.send(());

        let _ = server_handle.await;

        Ok(())
    }
}
