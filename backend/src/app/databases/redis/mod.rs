use anyhow::Result;

pub async fn new(url: &str) -> Result<redis::aio::MultiplexedConnection> {
    let client = redis::Client::open(url)?;
    let conn = client.get_multiplexed_async_connection().await?;
    Ok(conn)
}
