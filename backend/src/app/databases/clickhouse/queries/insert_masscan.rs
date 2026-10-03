use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;

#[derive(Debug, Row, Serialize)]
pub struct MasscanRow {
    pub target: String,
    pub ports: Vec<u16>,
    pub country: Option<String>,
    pub scan_uid: String,
}

pub async fn insert(
    client: &Client,
    target: &str,
    scan_uid: &str,
    ports: &[u16],
    country: Option<String>,
) -> Result<()> {
    let mut inserter = client
        .insert::<MasscanRow>("scan_results_masscan")
        .await?;

    inserter
        .write(&MasscanRow {
            target: target.to_string(),
            scan_uid: scan_uid.to_string(),
            ports: ports.to_vec(),
            country,
        })
        .await?;

    inserter.end().await?;
    Ok(())
}
