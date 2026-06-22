use anyhow::{Context, Result};
use clickhouse::Client;
use serde_json::Value;

pub async fn search_by_ip(client: &Client, q: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT target, port, protocol, state, service, product, version, scanned_at
        FROM scan_results_nmap
        WHERE target = ?
        ORDER BY scanned_at DESC
        LIMIT 1 BY port
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(&pattern)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn search_by_domain(
    client: &Client,
    q: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let lower_q = q.to_lowercase();
    let sql = r#"
        SELECT * FROM (
            SELECT
                target, port, 'whatweb' AS source,
                url, http_status, title, technologies,
                '' AS subject, emptyArrayString() AS san,
                scanned_at
            FROM scan_results_whatweb
            WHERE ilike(target, ?) OR ilike(url, ?)

            UNION ALL

            SELECT
                host AS target, port, 'ssl' AS source,
                '' AS url, toUInt16(0) AS http_status,
                '' AS title, emptyArrayString() AS technologies,
                subject, san, scanned_at
            FROM scan_results_ssl
            WHERE ilike(host, ?)
               OR position(lower(subject), ?) > 0
               OR arrayExists(x -> position(lower(x), ?) > 0, san)

            UNION ALL

            SELECT
                target, toUInt16(0) AS port, 'dns' AS source,
                '' AS url, toUInt16(0) AS http_status,
                '' AS title, emptyArrayString() AS technologies,
                '' AS subject, emptyArrayString() AS san,
                scanned_at
            FROM scan_results_dns
            WHERE ilike(target, ?)
               OR arrayExists(x -> ilike(x, ?), a)
               OR arrayExists(x -> ilike(x, ?), cname)
               OR arrayExists(x -> ilike(x, ?), mx)
               OR arrayExists(x -> ilike(x, ?), ns)
               OR arrayExists(x -> ilike(x, ?), ptr)
        )
        ORDER BY scanned_at DESC
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&lower_q)
        .bind(&lower_q)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn search_by_port(
    client: &Client,
    q: u16,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT target, port, protocol, state, service, product, version, scanned_at
        FROM scan_results_nmap
        WHERE port = ?
        ORDER BY scanned_at DESC
        LIMIT 1 BY target
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(q)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn search_by_title(
    client: &Client,
    q: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT target, port, url, http_status, title, technologies, scanned_at
        FROM scan_results_whatweb
        WHERE ilike(title, ?)
        ORDER BY scanned_at DESC
        LIMIT 1 BY target, port
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(&pattern)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn search_by_technology(
    client: &Client,
    q: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT target, port, url, http_status, title, technologies, scanned_at
        FROM scan_results_whatweb
        WHERE has(technologies, ?)
        ORDER BY scanned_at DESC
        LIMIT 1 BY target, port
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(q)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn search_by_protocol(
    client: &Client,
    q: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT target, port, protocol, state, service, product, version, scanned_at
        FROM scan_results_nmap
        WHERE protocol = ?
        ORDER BY scanned_at DESC
        LIMIT 1 BY target, port
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(q)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn search_by_service(
    client: &Client,
    q: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT target, port, protocol, state, service, product, version, scanned_at
        FROM scan_results_nmap
        WHERE ilike(service, ?)
        ORDER BY scanned_at DESC
        LIMIT 1 BY target, port
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(&pattern)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn search_by_image(
    client: &Client,
    q: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT target, port, s3_key, file_size, taken_at
        FROM scan_screenshots
        WHERE ilike(target, ?)
        ORDER BY taken_at DESC
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(&pattern)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn search_by_dns(
    client: &Client,
    q: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT target, a, aaaa, cname, mx, ns, txt, ptr, scanned_at
        FROM scan_results_dns
        WHERE ilike(target, ?)
           OR arrayExists(x -> ilike(x, ?), a)
           OR arrayExists(x -> ilike(x, ?), aaaa)
           OR arrayExists(x -> ilike(x, ?), cname)
           OR arrayExists(x -> ilike(x, ?), mx)
           OR arrayExists(x -> ilike(x, ?), ns)
           OR arrayExists(x -> ilike(x, ?), txt)
           OR arrayExists(x -> ilike(x, ?), ptr)
        ORDER BY scanned_at DESC
        LIMIT 1 BY target
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn search_by_ssl(
    client: &Client,
    q: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let lower_q = q.to_lowercase();
    let sql = r#"
        SELECT host, port, subject, issuer, not_before, not_after,
               serial, san, ssl_version, cipher, chain_length, scanned_at
        FROM scan_results_ssl
        WHERE ilike(host, ?)
           OR ilike(subject, ?)
           OR ilike(issuer, ?)
           OR ilike(serial, ?)
           OR arrayExists(x -> ilike(x, ?), san)
           OR position(lower(subject), ?) > 0
           OR position(lower(issuer), ?) > 0
           OR arrayExists(x -> position(lower(x), ?) > 0, san)
        ORDER BY scanned_at DESC
        LIMIT 1 BY host, port
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&lower_q)
        .bind(&lower_q)
        .bind(&lower_q)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn search_aggregated(
    client: &Client,
    q: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        WITH matching_targets AS (
            SELECT target, max(scanned_at) AS latest
            FROM scan_results_nmap
            WHERE ilike(target, ?)
               OR ilike(service, ?)
               OR ilike(product, ?)
            GROUP BY target

            UNION DISTINCT

            SELECT target, max(scanned_at) AS latest
            FROM scan_results_whatweb
            WHERE ilike(target, ?)
               OR ilike(title, ?)
               OR has(technologies, ?)
            GROUP BY target
        ),
        nmap_agg AS (
            SELECT target,
                   groupArray(port) AS ports,
                   min(scanned_at) AS first_seen_n,
                   max(scanned_at) AS last_seen_n,
                   count() AS scan_count_n
            FROM scan_results_nmap
            WHERE target IN (SELECT target FROM matching_targets)
            GROUP BY target
        ),
        whatweb_agg AS (
            SELECT target,
                   arrayDistinct(arrayFlatten(groupArray(technologies))) AS technologies,
                   groupUniqArray(title) AS titles,
                   any(url) AS url,
                   max(http_status) AS http_status,
                   min(scanned_at) AS first_seen_w,
                   max(scanned_at) AS last_seen_w,
                   count() AS scan_count_w
            FROM scan_results_whatweb
            WHERE target IN (SELECT target FROM matching_targets)
            GROUP BY target
        )
        SELECT
            mt.target AS target,
            ifNull(n.ports, []) AS ports,
            ifNull(w.technologies, []) AS technologies,
            ifNull(w.titles, []) AS titles,
            w.url AS url,
            w.http_status AS http_status,
            multiIf(
                isNull(n.first_seen_n) AND isNull(w.first_seen_w), toDateTime('1970-01-01 00:00:00'),
                isNull(n.first_seen_n), w.first_seen_w,
                isNull(w.first_seen_w), n.first_seen_n,
                n.first_seen_n = toDateTime('1970-01-01 00:00:00') AND w.first_seen_w != toDateTime('1970-01-01 00:00:00'), w.first_seen_w,
                w.first_seen_w = toDateTime('1970-01-01 00:00:00') AND n.first_seen_n != toDateTime('1970-01-01 00:00:00'), n.first_seen_n,
                least(n.first_seen_n, w.first_seen_w)
            ) AS first_seen,
            multiIf(
                isNull(n.last_seen_n) AND isNull(w.last_seen_w), toDateTime('1970-01-01 00:00:00'),
                isNull(n.last_seen_n), w.last_seen_w,
                isNull(w.last_seen_w), n.last_seen_n,
                greatest(n.last_seen_n, w.last_seen_w)
            ) AS last_seen,
            ifNull(n.scan_count_n, 0) + ifNull(w.scan_count_w, 0) AS scan_count
        FROM matching_targets mt
        LEFT JOIN nmap_agg n ON mt.target = n.target
        LEFT JOIN whatweb_agg w ON mt.target = w.target
        ORDER BY mt.latest DESC
        LIMIT ? OFFSET ?
    "#;
    let bytes = client
        .query(sql)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(q)
        .bind(limit)
        .bind(offset)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

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

pub async fn fetch_host_nmap(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT
            port, protocol, state, service, product, version,
            confidence, detection_method, extra_info, os_type,
            state_reason, banner, cpe, scripts, os_name, os_accuracy, ttl,
            scanned_at, scan_uid
        FROM scan_results_nmap
        WHERE target = ?
        ORDER BY scanned_at DESC
    "#;
    let bytes = client
        .query(sql)
        .bind(target)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    let mut rows = parse_json_each_row(&bytes)?;
    rows.sort_by_key(|r| r["port"].as_u64().unwrap_or(0));
    Ok(rows)
}

pub async fn fetch_host_whatweb(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT port, url, http_status, title, technologies,
               server, powered_by, meta_generator, headers, scanned_at,
               scan_uid
        FROM scan_results_whatweb
        WHERE target = ?
        ORDER BY scanned_at DESC
    "#;
    let bytes = client
        .query(sql)
        .bind(target)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    let mut rows = parse_json_each_row(&bytes)?;
    rows.sort_by_key(|r| r["port"].as_u64().unwrap_or(0));
    Ok(rows)
}

pub async fn fetch_host_screenshots(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT port, s3_key, file_size, taken_at, scan_uid
        FROM scan_screenshots
        WHERE target = ?
        ORDER BY taken_at DESC
    "#;
    let bytes = client
        .query(sql)
        .bind(target)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    let mut rows = parse_json_each_row(&bytes)?;
    rows.sort_by_key(|r| r["port"].as_u64().unwrap_or(0));
    Ok(rows)
}

pub async fn fetch_host_dns(client: &Client, target: &str) -> Result<Value> {
    let sql = r#"
        SELECT a, aaaa, cname, mx, ns, txt, ptr, scanned_at
        FROM scan_results_dns
        WHERE target = ?
        ORDER BY scanned_at DESC
        LIMIT 1
    "#;
    let bytes = client
        .query(sql)
        .bind(target)
        .fetch_bytes("JSON")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    let j: Value = serde_json::from_slice(&bytes).context("Failed to parse JSON")?;

    if j["data"].as_array().is_none_or(|a| a.is_empty()) {
        return Ok(Value::Null);
    }
    Ok(j["data"][0].clone())
}

pub async fn fetch_host_ssl(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT port, subject, issuer, not_before, not_after, serial,
               san, ssl_version, cipher, chain_length, scanned_at,
               scan_uid
        FROM scan_results_ssl
        WHERE host = ?
        ORDER BY scanned_at DESC
    "#;
    let bytes = client
        .query(sql)
        .bind(target)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    let mut rows = parse_json_each_row(&bytes)?;
    rows.sort_by_key(|r| r["port"].as_u64().unwrap_or(0));
    Ok(rows)
}

pub async fn fetch_host_nmap_history(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT
            scanned_at,
            groupArray(port) AS ports,
            count() AS port_count,
            groupUniqArray(service) AS services,
            groupUniqArray(product) AS products
        FROM scan_results_nmap
        WHERE target = ?
        GROUP BY scanned_at
        ORDER BY scanned_at DESC
    "#;
    let bytes = client
        .query(sql)
        .bind(target)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn fetch_host_whatweb_history(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT
            scanned_at,
            groupUniqArray(port) AS ports,
            groupUniqArray(http_status) AS statuses,
            groupUniqArray(title) AS titles,
            arrayDistinct(arrayFlatten(groupArray(technologies))) AS technologies
        FROM scan_results_whatweb
        WHERE target = ?
        GROUP BY scanned_at
        ORDER BY scanned_at DESC
    "#;
    let bytes = client
        .query(sql)
        .bind(target)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn fetch_host_snapshots(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"
        WITH scan_dates AS (
            SELECT scanned_at AS d FROM scan_results_nmap WHERE target = ?
            UNION DISTINCT
            SELECT scanned_at FROM scan_results_whatweb WHERE target = ?
            UNION DISTINCT
            SELECT taken_at FROM scan_screenshots WHERE target = ?
            UNION DISTINCT
            SELECT scanned_at FROM scan_results_ssl WHERE host = ?
            ORDER BY d DESC
        )
        SELECT
            d AS scanned_at,
            (SELECT groupArray((
                port, protocol, state, service, product, version,
                confidence, detection_method, extra_info, os_type,
                state_reason, banner, cpe, scripts, os_name, os_accuracy, ttl
            ))
             FROM scan_results_nmap
             WHERE target = ? AND scanned_at = d
            ) AS nmap,
            (SELECT groupArray((port, url, http_status, title, technologies))
             FROM scan_results_whatweb
             WHERE target = ? AND scanned_at = d
            ) AS whatweb,
            (SELECT groupArray((port, s3_key, file_size))
             FROM scan_screenshots
             WHERE target = ? AND taken_at = d
            ) AS screenshots,
            (SELECT groupArray((port, subject, issuer, not_before, not_after,
                                serial, san, ssl_version, cipher, chain_length))
             FROM scan_results_ssl
             WHERE host = ? AND scanned_at = d
            ) AS ssl
        FROM scan_dates
    "#;
    let bytes = client
        .query(sql)
        .bind(target)
        .bind(target)
        .bind(target)
        .bind(target)
        .bind(target)
        .bind(target)
        .bind(target)
        .bind(target)
        .fetch_bytes("JSONEachRow")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    parse_json_each_row(&bytes)
}

pub async fn host_summary(client: &Client, target: &str) -> Result<Value> {
    let sql = r#"
        SELECT
            uniqExact(port) AS open_ports,
            uniqExact(protocol) AS protocols,
            uniqExact(service) AS services,
            min(scanned_at) AS first_seen,
            max(scanned_at) AS last_seen,
            count() AS total_records
        FROM scan_results_nmap
        WHERE target = ?
    "#;
    let bytes = client
        .query(sql)
        .bind(target)
        .fetch_bytes("JSON")
        .context("ClickHouse query failed")?
        .collect()
        .await
        .context("Failed to collect ClickHouse response")?;

    let j: Value = serde_json::from_slice(&bytes).context("Failed to parse JSON")?;
    Ok(j["data"][0].clone())
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

fn parse_json_each_row(bytes: &[u8]) -> Result<Vec<Value>> {
    if bytes.is_empty() {
        return Ok(vec![]);
    }

    let mut rows = Vec::new();
    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<Value>(line) {
            Ok(v) => rows.push(v),
            Err(e) => {
                tracing::warn!("Failed to parse ClickHouse row: {}", e);
            }
        }
    }
    Ok(rows)
}
