use anyhow::Result;
use redis::aio::ConnectionManager;

pub async fn new(url: &str) -> Result<ConnectionManager> {
    let client = redis::Client::open(url)?;
    let mgr = ConnectionManager::new(client).await?;
    Ok(mgr)
}
