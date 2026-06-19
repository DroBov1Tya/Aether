use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;

#[derive(Debug, Row, Serialize)]
pub struct DnsRow {
    pub target: String,
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub cname: Vec<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
    pub ptr: Vec<String>,
}

pub async fn insert(client: &Client, row: DnsRow) -> Result<()> {
    let mut inserter = client.insert::<DnsRow>("scan_results_dns").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub fn from_json(item: &serde_json::Value) -> Option<DnsRow> {
    Some(DnsRow {
        target: item.get("target")?.as_str()?.to_string(),
        a: parse_str_array(item.get("a")?),
        aaaa: parse_str_array(item.get("aaaa")?),
        cname: parse_str_array(item.get("cname")?),
        mx: parse_str_array(item.get("mx")?),
        ns: parse_str_array(item.get("ns")?),
        txt: parse_str_array(item.get("txt")?),
        ptr: parse_str_array(item.get("ptr")?),
    })
}

fn parse_str_array(val: &serde_json::Value) -> Vec<String> {
    val.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
