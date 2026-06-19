use anyhow::Result;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub mod queries;

pub async fn new(url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await?;

    Ok(pool)
}
