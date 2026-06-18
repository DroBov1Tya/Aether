use crate::config::{self, Config};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;

mod server;
pub mod tools;

#[derive(Clone)]
pub struct AppState {
    pub cfg: &'static Config,
    pub shutdown: broadcast::Sender<()>,
}

pub struct Application {
    state: Arc<AppState>,
}

impl Application {
    pub async fn build() -> Result<Self> {
        tracing::info!("Building application");

        let _ = config::init();
        let cfg = config::cfg();
        let (shutdown, _) = broadcast::channel(1);

        let state = Arc::new(AppState { cfg, shutdown });

        Ok(Self { state })
    }

    pub async fn run(self) -> Result<()> {
        tracing::info!("Starting");

        let server_state = Arc::clone(&self.state);

        let server_handle = tokio::spawn(async move {
            match server::api::start(server_state).await {
                Ok(()) => tracing::info!("REST API stopped"),
                Err(e) => tracing::warn!("REST API error: {}", e),
            }
        });

        tracing::info!("Ready");

        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Shutdown");
        let _ = self.state.shutdown.send(());

        let _ = server_handle.await;

        Ok(())
    }
}
