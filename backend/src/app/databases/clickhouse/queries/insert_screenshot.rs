use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;

#[derive(Debug, Row, Serialize)]
pub struct ScreenshotRow {
    pub target: String,
    pub port: u16,
    pub s3_key: String,
    pub file_size: u32,
}

pub async fn insert(client: &Client, row: ScreenshotRow) -> Result<()> {
    let mut inserter = client.insert::<ScreenshotRow>("scan_screenshots").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}
