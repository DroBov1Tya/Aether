use anyhow::Result;
use clickhouse::{Client, Row};
use serde::Serialize;
use serde_json::Value;

use super::search::parse_json_each_row;

#[derive(Debug, Row, Serialize)]
struct ProxyRow {
    url: String,
}

/// Return the active proxy pool, oldest first (stable rotation order).
pub async fn list(client: &Client) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT url, added_at
        FROM proxies FINAL
        ORDER BY added_at ASC, url ASC
    "#;
    let bytes = client
        .query(sql)
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;
    parse_json_each_row(&bytes)
}

/// Return just the proxy URLs in rotation order (consumed by agents).
pub async fn list_urls(client: &Client) -> Result<Vec<String>> {
    let rows = list(client).await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.get("url").and_then(|v| v.as_str()).map(String::from))
        .collect())
}

/// Insert many proxies at once; duplicates collapse via ReplacingMergeTree.
/// Returns the count actually written.
pub async fn add_many(client: &Client, items: &[String]) -> Result<usize> {
    let mut inserter = client.insert::<ProxyRow>("proxies").await?;
    let mut written = 0usize;
    for item in items {
        let url = item.trim();
        if url.is_empty() {
            continue;
        }
        inserter.write(&ProxyRow { url: url.to_string() }).await?;
        written += 1;
    }
    inserter.end().await?;
    Ok(written)
}

/// Delete one proxy by exact URL.
pub async fn delete_one(client: &Client, url: &str) -> Result<()> {
    client
        .query("DELETE FROM proxies WHERE url = ?")
        .bind(url)
        .execute()
        .await?;
    Ok(())
}

/// Delete every proxy in the pool.
pub async fn delete_all(client: &Client) -> Result<()> {
    client
        .query("DELETE FROM proxies WHERE 1 = 1")
        .execute()
        .await?;
    Ok(())
}
