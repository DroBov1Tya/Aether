use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;

#[derive(Debug, Row, Serialize)]
pub struct RustscanRow {
    pub target: String,
    pub ports: Vec<u16>,
}

pub async fn insert(client: &Client, target: &str, ports: &[u16]) -> Result<()> {
    let mut inserter = client
        .insert::<RustscanRow>("scan_results_rustscan")
        .await?;

    inserter
        .write(&RustscanRow {
            target: target.to_string(),
            ports: ports.to_vec(),
        })
        .await?;

    inserter.end().await?;
    Ok(())
}
