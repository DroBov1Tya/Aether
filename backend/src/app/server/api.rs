use anyhow::Result;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use axum_listener::DualListener;
use std::path::Path;
use std::sync::Arc;

use super::routes;
use crate::app::AppState;

async fn require_api_key(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(key) = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
    else {
        return (StatusCode::UNAUTHORIZED, "missing x-api-key header").into_response();
    };

    if key != state.cfg.api_key {
        return (StatusCode::UNAUTHORIZED, "invalid api key").into_response();
    }

    next.run(req).await
}

pub async fn start(state: Arc<AppState>) -> Result<()> {
    let server_path = state.cfg.server_path.clone();
    let mut shutdown_rx = state.shutdown.subscribe();

    if Path::new(&server_path).exists() {
        tokio::fs::remove_file(&server_path).await?;
        tracing::info!("🧹 Removed old socket");
    }

    let listener = match DualListener::bind(format!("{}", &server_path)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                "⚠️ Could not bind API listener on {}: {}. REST API will not be available.",
                &server_path,
                e
            );
            return Ok(());
        }
    };
    tracing::info!("🚀 API listening on {}", &server_path);

    let app = routes::build_router(Arc::clone(&state))
        .layer(middleware::from_fn_with_state(state, require_api_key));

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
        })
        .await?;

    Ok(())
}
