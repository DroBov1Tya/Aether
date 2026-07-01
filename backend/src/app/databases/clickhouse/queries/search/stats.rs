use anyhow::{Context, Result};
use clickhouse::Client;
use serde_json::Value;

use super::parse_json_each_row;

pub async fn count_screenshots(client: &Client) -> Result<u64> {
    let sql = "SELECT count() AS count FROM scan_screenshots";
    let bytes = client
        .query(sql)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["count"].as_u64()).unwrap_or(0))
}

pub async fn fetch_screenshot_s3_key(
    client: &Client,
    target: &str,
    port: u16,
) -> Result<(String, u32)> {
    let sql = r#"
        SELECT s3_key, file_size
        FROM scan_screenshots
        WHERE target = ? AND port = ?
        ORDER BY taken_at DESC
        LIMIT 1
    "#;
    let mut cursor = client
        .query(sql)
        .bind(target)
        .bind(port)
        .fetch::<(String, u32)>()
        .context("ClickHouse query failed")?;

    match cursor.next().await {
        Ok(Some(row)) => Ok(row),
        Ok(None) => anyhow::bail!("screenshot not found for {}:{}", target, port),
        Err(e) => anyhow::bail!("failed to fetch screenshot row: {}", e),
    }
}

pub async fn list_all_screenshots(client: &Client, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT
            s.target, s.port, s.s3_key, s.file_size, s.taken_at,
            w.title, w.http_status, w.technologies
        FROM scan_screenshots s
        LEFT ANY JOIN scan_results_whatweb w
            ON s.target = w.target AND s.port = w.port
        ORDER BY s.taken_at DESC
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn top_ports(client: &Client, limit: u32) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT port, uniqExact(target) AS count
        FROM scan_results_nmap
        GROUP BY port
        ORDER BY count DESC
        LIMIT ?
    "#;
    let bytes = client
        .query(sql)
        .bind(limit)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn top_services(client: &Client, limit: u32) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT service, uniqExact(target) AS count
        FROM scan_results_nmap
        WHERE service IS NOT NULL AND service != ''
        GROUP BY service
        ORDER BY count DESC
        LIMIT ?
    "#;
    let bytes = client
        .query(sql)
        .bind(limit)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn top_technologies(client: &Client, limit: u32) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT arrayJoin(technologies) AS technology, uniqExact(target) AS count
        FROM scan_results_whatweb
        GROUP BY technology
        ORDER BY count DESC
        LIMIT ?
    "#;
    let bytes = client
        .query(sql)
        .bind(limit)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn summary_stats(client: &Client) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT
            (SELECT uniqExact(target) FROM scan_results_nmap) AS total_hosts,
            (SELECT uniqExact(port) FROM scan_results_nmap) AS unique_ports,
            (SELECT uniqExact(service) FROM scan_results_nmap WHERE service != '') AS unique_services,
            (SELECT uniqExact(arrayJoin(technologies)) FROM scan_results_whatweb) AS unique_technologies,
            (SELECT count() FROM scan_screenshots) AS total_screenshots,
            (SELECT uniqExact(host) FROM scan_results_ssl) AS ssl_hosts,
            (SELECT max(scanned_at) FROM scan_results_nmap) AS last_scan
    "#;
    let bytes = client
        .query(sql)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn get_last_scans(client: &Client, limit: u32) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT target, port, url, http_status, title, technologies, scanned_at
        FROM scan_results_whatweb
        ORDER BY scanned_at DESC
        LIMIT 1 BY target
        LIMIT ?
    "#;
    let bytes = client
        .query(sql)
        .bind(limit)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}
