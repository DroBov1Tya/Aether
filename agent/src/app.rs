use crate::config::{self, Config};
use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use tokio::sync::{Semaphore, broadcast};

mod server;
pub mod tools;

#[derive(Clone)]
pub struct AppState {
    pub cfg: &'static Config,
    pub shutdown: broadcast::Sender<()>,
    pub scan_permits: Arc<Semaphore>,
    pub busy: Arc<AtomicU8>,
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

        let scan_permits = Arc::new(Semaphore::new(cfg.max_concurrent_scans));
        let busy = Arc::new(AtomicU8::new(0));
        let state = Arc::new(AppState {
            cfg,
            shutdown,
            scan_permits,
            busy,
        });

        Ok(Self { state })
    }

    pub async fn run(self) -> Result<()> {
        tracing::info!("Starting");

        let server_state = Arc::clone(&self.state);
        let backend_state = Arc::clone(&self.state);

        let server_handle = tokio::spawn(async move {
            match server::api::start(server_state).await {
                Ok(()) => tracing::info!("REST API stopped"),
                Err(e) => tracing::warn!("REST API error: {}", e),
            }
        });

        let backend_handle = tokio::spawn(async move {
            match tools::backend::start(backend_state).await {
                Ok(()) => tracing::info!("Backend stopped"),
                Err(e) => tracing::warn!("Backend error: {}", e),
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
