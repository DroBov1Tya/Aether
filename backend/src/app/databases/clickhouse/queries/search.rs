use anyhow::Result;
use clickhouse::Client;
use serde_json::Value;

async fn run_query(client: &Client, sql: &str, bind: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", bind);
    let mut cursor = client
        .query(sql)
        .bind(&pattern)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

async fn run_exact(client: &Client, sql: &str, bind: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let mut cursor = client
        .query(sql)
        .bind(bind)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn search_by_ip(client: &Client, q: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let sql = r#"SELECT target, port, url, http_status, title, technologies, scanned_at
                 FROM scan_results_whatweb
                 WHERE target LIKE ?
                 ORDER BY scanned_at DESC
                 LIMIT ? OFFSET ?"#;
    run_query(client, sql, q, limit, offset).await
}

pub async fn search_by_domain(client: &Client, q: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let sql = r#"SELECT target, port, url, http_status, title, technologies, scanned_at
                 FROM scan_results_whatweb
                 WHERE url LIKE ?
                 ORDER BY scanned_at DESC
                 LIMIT ? OFFSET ?"#;
    run_query(client, sql, q, limit, offset).await
}

pub async fn search_by_port(client: &Client, q: u16, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let sql = r#"SELECT target, port, protocol, state, service, product, version, scanned_at
                 FROM scan_results_nmap
                 WHERE port = ?
                 ORDER BY scanned_at DESC
                 LIMIT ? OFFSET ?"#;
    let mut cursor = client
        .query(sql)
        .bind(q)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn search_by_title(client: &Client, q: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let sql = r#"SELECT target, port, url, http_status, title, technologies, scanned_at
                 FROM scan_results_whatweb
                 WHERE title LIKE ?
                 ORDER BY scanned_at DESC
                 LIMIT ? OFFSET ?"#;
    run_query(client, sql, q, limit, offset).await
}

pub async fn search_by_technology(client: &Client, q: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let sql = r#"WITH ? AS tech
                 SELECT target, port, url, http_status, title, technologies, scanned_at
                 FROM scan_results_whatweb
                 WHERE has(technologies, tech)
                 ORDER BY scanned_at DESC
                 LIMIT ? OFFSET ?"#;
    let mut cursor = client
        .query(sql)
        .bind(q)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn search_by_protocol(client: &Client, q: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let sql = r#"SELECT target, port, protocol, state, service, product, version, scanned_at
                 FROM scan_results_nmap
                 WHERE protocol = ?
                 ORDER BY scanned_at DESC
                 LIMIT ? OFFSET ?"#;
    run_exact(client, sql, q, limit, offset).await
}

pub async fn search_by_service(client: &Client, q: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let sql = r#"SELECT target, port, protocol, state, service, product, version, scanned_at
                 FROM scan_results_nmap
                 WHERE service LIKE ?
                 ORDER BY scanned_at DESC
                 LIMIT ? OFFSET ?"#;
    run_query(client, sql, q, limit, offset).await
}

pub async fn search_by_image(client: &Client, q: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let sql = r#"SELECT target, port, s3_key, file_size, taken_at
                 FROM scan_screenshots
                 WHERE target LIKE ?
                 ORDER BY taken_at DESC
                 LIMIT ? OFFSET ?"#;
    run_query(client, sql, q, limit, offset).await
}

// ── Host details ──────────────────────────────────────────────

pub async fn fetch_host_nmap(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"SELECT * FROM scan_results_nmap WHERE target = ? ORDER BY port"#;
    let mut cursor = client.query(sql).bind(target).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn fetch_host_whatweb(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"SELECT * FROM scan_results_whatweb WHERE target = ? ORDER BY port"#;
    let mut cursor = client.query(sql).bind(target).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn fetch_host_screenshots(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"SELECT * FROM scan_screenshots WHERE target = ? ORDER BY port"#;
    let mut cursor = client.query(sql).bind(target).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn host_summary(client: &Client, target: &str) -> Result<Value> {
    let sql = r#"SELECT
                    count(DISTINCT port) AS open_ports,
                    min(scanned_at) AS first_seen,
                    max(scanned_at) AS last_seen
                 FROM scan_results_nmap WHERE target = ?"#;
    let mut cursor = client.query(sql).bind(target).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"][0].clone())
}

// ── Stats ────────────────────────────────────────────────────

pub async fn top_ports(client: &Client, limit: u32) -> Result<Vec<Value>> {
    let sql = r#"SELECT port, count(DISTINCT target) AS count
                 FROM scan_results_nmap
                 GROUP BY port
                 ORDER BY count DESC
                 LIMIT ?"#;
    let mut cursor = client.query(sql).bind(limit).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn top_services(client: &Client, limit: u32) -> Result<Vec<Value>> {
    let sql = r#"SELECT service, count(DISTINCT target) AS count
                 FROM scan_results_nmap
                 WHERE service IS NOT NULL AND service != ''
                 GROUP BY service
                 ORDER BY count DESC
                 LIMIT ?"#;
    let mut cursor = client.query(sql).bind(limit).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn top_technologies(client: &Client, limit: u32) -> Result<Vec<Value>> {
    let sql = r#"SELECT arrayJoin(technologies) AS technology, count(DISTINCT target) AS count
                 FROM scan_results_whatweb
                 GROUP BY technology
                 ORDER BY count DESC
                 LIMIT ?"#;
    let mut cursor = client.query(sql).bind(limit).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn summary_stats(client: &Client) -> Result<Value> {
    let sql = r#"SELECT
                    (SELECT count(DISTINCT target) FROM scan_results_nmap) AS total_hosts,
                    (SELECT count(*) FROM scan_results_nmap) AS total_ports,
                    (SELECT count(DISTINCT service) FROM scan_results_nmap WHERE service IS NOT NULL AND service != '') AS total_services,
                    (SELECT count(DISTINCT arrayJoin(technologies)) FROM scan_results_whatweb) AS total_technologies"#;
    let mut cursor = client.query(sql).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"][0].clone())
}

// ── Lists ────────────────────────────────────────────────────

pub async fn list_protocols(client: &Client) -> Result<Vec<Value>> {
    let sql = r#"SELECT DISTINCT protocol AS value
                 FROM scan_results_nmap
                 WHERE protocol != ''
                 ORDER BY protocol"#;
    let mut cursor = client.query(sql).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn list_services(client: &Client) -> Result<Vec<Value>> {
    let sql = r#"SELECT DISTINCT service AS value
                 FROM scan_results_nmap
                 WHERE service IS NOT NULL AND service != ''
                 ORDER BY service"#;
    let mut cursor = client.query(sql).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}

pub async fn list_technologies(client: &Client) -> Result<Vec<Value>> {
    let sql = r#"SELECT DISTINCT arrayJoin(technologies) AS value
                 FROM scan_results_whatweb
                 ORDER BY value"#;
    let mut cursor = client.query(sql).fetch_bytes("JSON")?;
    let bytes = cursor.collect().await?;
    let json: Value = serde_json::from_slice(&bytes)?;
    Ok(json["data"].as_array().cloned().unwrap_or_default())
}
