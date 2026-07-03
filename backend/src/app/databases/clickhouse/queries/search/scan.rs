use anyhow::{Context, Result};
use clickhouse::Client;
use serde_json::Value;

use super::parse_json_each_row;

pub async fn search_by_ip(client: &Client, q: &str, limit: u32, offset: u32) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT target, port, protocol, state, service, product, version, scanned_at, scan_uid
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
                scanned_at, scan_uid
            FROM scan_results_whatweb
            WHERE ilike(target, ?) OR ilike(url, ?)

            UNION ALL

            SELECT
                host AS target, port, 'ssl' AS source,
                '' AS url, toUInt16(0) AS http_status,
                '' AS title, emptyArrayString() AS technologies,
                subject, san, scanned_at, scan_uid
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
                scanned_at, '' AS scan_uid
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
        SELECT target, port, protocol, state, service, product, version, scanned_at, scan_uid
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
        SELECT target, port, url, http_status, title, technologies, scanned_at, scan_uid
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
        SELECT target, port, url, http_status, title, technologies, scanned_at, scan_uid
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
        SELECT target, port, protocol, state, service, product, version, scanned_at, scan_uid
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
        SELECT target, port, protocol, state, service, product, version, scanned_at, scan_uid
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
        SELECT target, port, s3_key, file_size, taken_at, scan_uid
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
        SELECT target, a, aaaa, cname, mx, ns, txt, ptr, scanned_at, '' AS scan_uid
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
               serial, san, ssl_version, cipher, chain_length, scanned_at, scan_uid
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
        WITH targets AS (
            SELECT DISTINCT target FROM (
                SELECT target FROM scan_results_nmap
                WHERE ilike(target, ?) OR ilike(service, ?) OR ilike(product, ?)
                UNION ALL
                SELECT target FROM scan_results_whatweb
                WHERE ilike(target, ?) OR ilike(title, ?) OR has(technologies, ?)
                UNION ALL
                SELECT target FROM scan_results_rustscan
                WHERE ilike(target, ?)
            )
        ),
        nmap_agg AS (
            SELECT target, groupArray(port) AS ports,
                   min(scanned_at) AS first_seen, max(scanned_at) AS last_seen
            FROM scan_results_nmap WHERE target IN (SELECT target FROM targets)
            GROUP BY target
        ),
        rustscan_agg AS (
            SELECT target,
                   arrayFlatten(groupArray(ports)) AS ports,
                   min(scanned_at) AS first_seen, max(scanned_at) AS last_seen
            FROM scan_results_rustscan WHERE target IN (SELECT target FROM targets)
            GROUP BY target
        ),
        whatweb_agg AS (
            SELECT target,
                   arrayDistinct(arrayFlatten(groupArray(technologies))) AS technologies,
                   groupUniqArray(title) AS titles,
                   any(url) AS url,
                   max(http_status) AS http_status
            FROM scan_results_whatweb WHERE target IN (SELECT target FROM targets)
            GROUP BY target
        ),
        scan_stats AS (
            SELECT target, uniqExact(scan_uid) AS scan_count,
                   groupUniqArray(scan_uid) AS scan_uids
            FROM (
                SELECT target, scan_uid FROM scan_results_nmap
                WHERE target IN (SELECT target FROM targets)
                UNION ALL
                SELECT target, scan_uid FROM scan_results_whatweb
                WHERE target IN (SELECT target FROM targets)
                UNION ALL
                SELECT target, scan_uid FROM scan_results_rustscan
                WHERE target IN (SELECT target FROM targets)
            )
            GROUP BY target
        )
         SELECT t.target AS target,
                ifNull(n.ports, ifNull(rs.ports, [])) AS ports,
                ifNull(w.technologies, []) AS technologies,
                ifNull(w.titles, []) AS titles,
                w.url AS url,
                w.http_status AS http_status,
                ifNull(n.first_seen, ifNull(rs.first_seen, toDateTime('1970-01-01 00:00:00'))) AS first_seen,
                ifNull(n.last_seen, ifNull(rs.last_seen, toDateTime('1970-01-01 00:00:00'))) AS last_seen,
                s.scan_count AS scan_count,
                s.scan_uids AS scan_uids
         FROM targets t
         LEFT JOIN nmap_agg n ON t.target = n.target
         LEFT JOIN rustscan_agg rs ON t.target = rs.target
         LEFT JOIN whatweb_agg w ON t.target = w.target
         LEFT JOIN scan_stats s ON t.target = s.target
        ORDER BY n.last_seen DESC NULLS LAST, t.target
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

pub async fn count_search_by_ip(client: &Client, q: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT count(*) AS cnt FROM (
            SELECT port FROM scan_results_nmap
            WHERE target = ?
            ORDER BY scanned_at DESC
            LIMIT 1 BY port
        )
    "#;
    let bytes = client.query(sql).bind(&pattern).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_domain(client: &Client, q: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let lower_q = q.to_lowercase();
    let sql = r#"
        SELECT count(*) AS cnt FROM (
            SELECT 1 AS src FROM scan_results_whatweb
            WHERE ilike(target, ?) OR ilike(url, ?)
            UNION ALL
            SELECT 1 AS src FROM scan_results_ssl
            WHERE ilike(host, ?)
               OR position(lower(subject), ?) > 0
               OR arrayExists(x -> position(lower(x), ?) > 0, san)
            UNION ALL
            SELECT 1 AS src FROM scan_results_dns
            WHERE ilike(target, ?)
               OR arrayExists(x -> ilike(x, ?), a)
               OR arrayExists(x -> ilike(x, ?), cname)
               OR arrayExists(x -> ilike(x, ?), mx)
               OR arrayExists(x -> ilike(x, ?), ns)
               OR arrayExists(x -> ilike(x, ?), ptr)
        )
    "#;
    let bytes = client.query(sql)
        .bind(&pattern).bind(&pattern)
        .bind(&pattern).bind(&lower_q).bind(&lower_q)
        .bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern)
        .fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_port(client: &Client, q: u16) -> Result<u64> {
    let sql = r#"
        SELECT count(*) AS cnt FROM (
            SELECT target FROM scan_results_nmap
            WHERE port = ?
            ORDER BY scanned_at DESC
            LIMIT 1 BY target
        )
    "#;
    let bytes = client.query(sql).bind(q).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_title(client: &Client, q: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT count(*) AS cnt FROM (
            SELECT target, port FROM scan_results_whatweb
            WHERE ilike(title, ?)
            ORDER BY scanned_at DESC
            LIMIT 1 BY target, port
        )
    "#;
    let bytes = client.query(sql).bind(&pattern).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_technology(client: &Client, q: &str) -> Result<u64> {
    let sql = r#"
        SELECT count(*) AS cnt FROM (
            SELECT target, port FROM scan_results_whatweb
            WHERE has(technologies, ?)
            ORDER BY scanned_at DESC
            LIMIT 1 BY target, port
        )
    "#;
    let bytes = client.query(sql).bind(q).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_protocol(client: &Client, q: &str) -> Result<u64> {
    let sql = r#"
        SELECT count(*) AS cnt FROM (
            SELECT target, port FROM scan_results_nmap
            WHERE protocol = ?
            ORDER BY scanned_at DESC
            LIMIT 1 BY target, port
        )
    "#;
    let bytes = client.query(sql).bind(q).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_service(client: &Client, q: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT count(*) AS cnt FROM (
            SELECT target, port FROM scan_results_nmap
            WHERE ilike(service, ?)
            ORDER BY scanned_at DESC
            LIMIT 1 BY target, port
        )
    "#;
    let bytes = client.query(sql).bind(&pattern).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_image(client: &Client, q: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = "SELECT count(*) AS cnt FROM scan_screenshots WHERE ilike(target, ?)";
    let bytes = client.query(sql).bind(&pattern).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_dns(client: &Client, q: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT count(*) AS cnt FROM (
            SELECT target FROM scan_results_dns
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
        )
    "#;
    let bytes = client.query(sql)
        .bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern)
        .bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern)
        .fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_ssl(client: &Client, q: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let lower_q = q.to_lowercase();
    let sql = r#"
        SELECT count(*) AS cnt FROM (
            SELECT host, port FROM scan_results_ssl
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
        )
    "#;
    let bytes = client.query(sql)
        .bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern)
        .bind(&lower_q).bind(&lower_q).bind(&lower_q)
        .fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_aggregated(client: &Client, q: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = r#"
        SELECT count(*) AS cnt FROM (
            SELECT DISTINCT target FROM (
                SELECT target FROM scan_results_nmap
                WHERE ilike(target, ?) OR ilike(service, ?) OR ilike(product, ?)
                UNION ALL
                SELECT target FROM scan_results_whatweb
                WHERE ilike(target, ?) OR ilike(title, ?) OR has(technologies, ?)
                UNION ALL
                SELECT target FROM scan_results_rustscan
                WHERE ilike(target, ?)
            )
        )
    "#;
    let bytes = client.query(sql)
        .bind(&pattern).bind(&pattern).bind(&pattern)
        .bind(&pattern).bind(&pattern).bind(q)
        .bind(&pattern)
        .fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}
