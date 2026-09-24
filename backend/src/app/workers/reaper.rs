use clickhouse::Client as ChClient;

use crate::app::databases::clickhouse::queries::tokens;

pub async fn run(ch: ChClient) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
    ticker.tick().await;

    loop {
        ticker.tick().await;

        let Ok(stale) = tokens::stale_active(&ch, 180).await else {
            continue;
        };
        for agent_id in stale {
            if let Err(e) = tokens::set_status(&ch, &agent_id, "inactive").await {
                tracing::warn!("reaper: failed to mark {agent_id} inactive: {e}");
                continue;
            }
            tracing::info!("reaper: agent {agent_id} marked inactive (no heartbeat 180s)");
        }
    }
}
