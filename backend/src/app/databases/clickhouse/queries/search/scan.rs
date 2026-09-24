use anyhow::{Context, Result};
use clickhouse::Client;
use serde_json::Value;

use super::parse_json_each_row;

pub fn project_clause(project: &str) -> String {
    let safe: String = project
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
        .take(64)
        .collect();
    let safe = if safe.trim().is_empty() {
        "global".to_string()
    } else {
        safe
    };
    format!("project = '{}'", safe)
}

pub async fn search_by_ip(
    client: &Client,
    q: &str,
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT target, port, protocol, state, service, product, version, scanned_at, scan_uid
        FROM scan_results_nmap
        WHERE {p} AND ilike(target, ?)
        ORDER BY scanned_at DESC
        LIMIT 1 BY port
        LIMIT ? OFFSET ?
    "#,
        p = project_clause(project)
    );
    let bytes = client
        .query(&sql)
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
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let lower_q = q.to_lowercase();
    let p = project_clause(project);
    let sql = format!(
        r#"
        SELECT * FROM (
            SELECT
                target, port, 'whatweb' AS source,
                url, http_status, title, technologies,
                '' AS subject, emptyArrayString() AS san,
                scanned_at, scan_uid
            FROM scan_results_whatweb
            WHERE {p} AND (ilike(target, ?) OR ilike(url, ?))

            UNION ALL

            SELECT
                host AS target, port, 'ssl' AS source,
                '' AS url, toUInt16(0) AS http_status,
                '' AS title, emptyArrayString() AS technologies,
                subject, san, scanned_at, scan_uid
            FROM scan_results_ssl
            WHERE {p} AND (ilike(host, ?)
               OR position(lower(subject), ?) > 0
               OR arrayExists(x -> position(lower(x), ?) > 0, san))

            UNION ALL

            SELECT
                target, toUInt16(0) AS port, 'dns' AS source,
                '' AS url, toUInt16(0) AS http_status,
                '' AS title, emptyArrayString() AS technologies,
                '' AS subject, emptyArrayString() AS san,
                scanned_at, '' AS scan_uid
            FROM scan_results_dns
            WHERE {p} AND (ilike(target, ?)
               OR arrayExists(x -> ilike(x, ?), a)
               OR arrayExists(x -> ilike(x, ?), cname)
               OR arrayExists(x -> ilike(x, ?), mx)
               OR arrayExists(x -> ilike(x, ?), ns)
               OR arrayExists(x -> ilike(x, ?), ptr))
        )
        ORDER BY scanned_at DESC
        LIMIT ? OFFSET ?
    "#,
        p = p
    );
    let bytes = client
        .query(&sql)
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
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let sql = format!(
        r#"
        SELECT target, port, protocol, state, service, product, version, scanned_at, scan_uid
        FROM scan_results_nmap
        WHERE {p} AND port = ?
        ORDER BY scanned_at DESC
        LIMIT 1 BY target
        LIMIT ? OFFSET ?
    "#,
        p = project_clause(project)
    );
    let bytes = client
        .query(&sql)
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
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT target, port, url, http_status, title, technologies, scanned_at, scan_uid
        FROM scan_results_whatweb
        WHERE {p} AND ilike(title, ?)
        ORDER BY scanned_at DESC
        LIMIT 1 BY target, port
        LIMIT ? OFFSET ?
    "#,
        p = project_clause(project)
    );
    let bytes = client
        .query(&sql)
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

pub async fn search_by_header(
    client: &Client,
    q: &str,
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT target, port, url, http_status, title, technologies, headers, scanned_at, scan_uid
        FROM scan_results_whatweb
        WHERE {p} AND headers != '' AND ilike(headers, ?)
        ORDER BY scanned_at DESC
        LIMIT 1 BY target, port
        LIMIT ? OFFSET ?
    "#,
        p = project_clause(project)
    );
    let bytes = client
        .query(&sql)
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
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let sql = format!(
        r#"
        SELECT target, port, url, http_status, title, technologies, scanned_at, scan_uid
        FROM scan_results_whatweb
        WHERE {p} AND has(technologies, ?)
        ORDER BY scanned_at DESC
        LIMIT 1 BY target, port
        LIMIT ? OFFSET ?
    "#,
        p = project_clause(project)
    );
    let bytes = client
        .query(&sql)
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
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let sql = format!(
        r#"
        SELECT target, port, protocol, state, service, product, version, scanned_at, scan_uid
        FROM scan_results_nmap
        WHERE {p} AND protocol = ?
        ORDER BY scanned_at DESC
        LIMIT 1 BY target, port
        LIMIT ? OFFSET ?
    "#,
        p = project_clause(project)
    );
    let bytes = client
        .query(&sql)
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
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT target, port, protocol, state, service, product, version, scanned_at, scan_uid
        FROM scan_results_nmap
        WHERE {p} AND ilike(service, ?)
        ORDER BY scanned_at DESC
        LIMIT 1 BY target, port
        LIMIT ? OFFSET ?
    "#,
        p = project_clause(project)
    );
    let bytes = client
        .query(&sql)
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
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT target, port, s3_key, file_size, taken_at, scan_uid
        FROM scan_screenshots
        WHERE {p} AND ilike(target, ?)
        ORDER BY taken_at DESC
        LIMIT ? OFFSET ?
    "#,
        p = project_clause(project)
    );
    let bytes = client
        .query(&sql)
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
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT target, a, aaaa, cname, mx, ns, txt, ptr, scanned_at, '' AS scan_uid
        FROM scan_results_dns
        WHERE {p} AND (ilike(target, ?)
           OR arrayExists(x -> ilike(x, ?), a)
           OR arrayExists(x -> ilike(x, ?), aaaa)
           OR arrayExists(x -> ilike(x, ?), cname)
           OR arrayExists(x -> ilike(x, ?), mx)
           OR arrayExists(x -> ilike(x, ?), ns)
           OR arrayExists(x -> ilike(x, ?), txt)
           OR arrayExists(x -> ilike(x, ?), ptr))
        ORDER BY scanned_at DESC
        LIMIT 1 BY target
        LIMIT ? OFFSET ?
    "#,
        p = project_clause(project)
    );
    let bytes = client
        .query(&sql)
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
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let lower_q = q.to_lowercase();
    let sql = format!(
        r#"
        SELECT host, port, subject, issuer, not_before, not_after,
               serial, san, ssl_version, cipher, jarm, chain_length, scanned_at, scan_uid
        FROM scan_results_ssl
        WHERE {p} AND (ilike(host, ?)
           OR ilike(subject, ?)
           OR ilike(issuer, ?)
           OR ilike(serial, ?)
           OR arrayExists(x -> ilike(x, ?), san)
           OR position(lower(subject), ?) > 0
           OR position(lower(issuer), ?) > 0
           OR arrayExists(x -> position(lower(x), ?) > 0, san))
        ORDER BY scanned_at DESC
        LIMIT 1 BY host, port
        LIMIT ? OFFSET ?
    "#,
        p = project_clause(project)
    );
    let bytes = client
        .query(&sql)
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
    project: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Value>> {
    let pattern = format!("%{}%", q);
    let p = project_clause(project);
    let sql = format!(
        r#"
        WITH targets AS (
            SELECT DISTINCT target FROM (
                SELECT target FROM scan_results_nmap
                WHERE {p} AND (ilike(target, ?) OR ilike(service, ?) OR ilike(product, ?))
                UNION ALL
                SELECT target FROM scan_results_whatweb
                WHERE {p} AND (ilike(target, ?) OR ilike(title, ?) OR has(technologies, ?))
                UNION ALL
                SELECT target FROM scan_results_rustscan
                WHERE {p} AND ilike(target, ?)
            )
        ),
        nmap_agg AS (
            SELECT target, arrayDistinct(groupArray(port)) AS ports,
                   min(scanned_at) AS first_seen, max(scanned_at) AS last_seen
            FROM scan_results_nmap WHERE {p} AND target IN (SELECT target FROM targets)
            GROUP BY target
        ),
        rustscan_agg AS (
            SELECT target,
                   arrayDistinct(arrayFlatten(groupArray(ports))) AS ports,
                   min(scanned_at) AS first_seen, max(scanned_at) AS last_seen
            FROM scan_results_rustscan WHERE {p} AND target IN (SELECT target FROM targets)
            GROUP BY target
        ),
        whatweb_agg AS (
            SELECT target,
                   arrayDistinct(arrayFlatten(groupArray(technologies))) AS technologies,
                   groupUniqArray(title) AS titles,
                   any(url) AS url,
                   max(http_status) AS http_status
            FROM scan_results_whatweb WHERE {p} AND target IN (SELECT target FROM targets)
            GROUP BY target
        ),
        scan_stats AS (
            SELECT target, uniqExact(scan_uid) AS scan_count,
                   groupUniqArray(scan_uid) AS scan_uids
            FROM (
                SELECT target, scan_uid FROM scan_results_nmap
                WHERE {p} AND target IN (SELECT target FROM targets)
                UNION ALL
                SELECT target, scan_uid FROM scan_results_whatweb
                WHERE {p} AND target IN (SELECT target FROM targets)
                UNION ALL
                SELECT target, scan_uid FROM scan_results_rustscan
                WHERE {p} AND target IN (SELECT target FROM targets)
            )
            GROUP BY target
        ),
        geo_agg AS (
            SELECT target, any(country) AS country, any(country_code) AS country_code,
                   any(asn) AS asn, any(org) AS org
            FROM host_geo FINAL WHERE target IN (SELECT target FROM targets)
            GROUP BY target
        ),
        time_agg AS (
            SELECT target, min(ts) AS first_seen, max(ts) AS last_seen
            FROM (
                SELECT target, scanned_at AS ts FROM scan_results_nmap
                WHERE {p} AND target IN (SELECT target FROM targets)
                UNION ALL
                SELECT target, scanned_at AS ts FROM scan_results_rustscan
                WHERE {p} AND target IN (SELECT target FROM targets)
                UNION ALL
                SELECT target, scanned_at AS ts FROM scan_results_whatweb
                WHERE {p} AND target IN (SELECT target FROM targets)
            )
            GROUP BY target
        )
         SELECT t.target AS target,
                ifNull(n.ports, ifNull(rs.ports, [])) AS ports,
                ifNull(w.technologies, []) AS technologies,
                ifNull(w.titles, []) AS titles,
                w.url AS url,
                w.http_status AS http_status,
                ifNull(g.country, '') AS country,
                ifNull(g.country_code, '') AS country_code,
                ifNull(g.asn, '') AS asn,
                ifNull(g.org, '') AS org,
                tm.first_seen AS first_seen,
                tm.last_seen AS last_seen,
                s.scan_count AS scan_count,
                s.scan_uids AS scan_uids
         FROM targets t
         LEFT JOIN nmap_agg n ON t.target = n.target
         LEFT JOIN rustscan_agg rs ON t.target = rs.target
         LEFT JOIN whatweb_agg w ON t.target = w.target
         LEFT JOIN scan_stats s ON t.target = s.target
         LEFT JOIN geo_agg g ON t.target = g.target
         LEFT JOIN time_agg tm ON t.target = tm.target
        ORDER BY tm.last_seen DESC NULLS LAST, t.target
        LIMIT ? OFFSET ?
    "#,
        p = p
    );
    let bytes = client
        .query(&sql)
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

pub async fn count_search_by_ip(client: &Client, q: &str, project: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT port FROM scan_results_nmap
            WHERE {p} AND ilike(target, ?)
            ORDER BY scanned_at DESC
            LIMIT 1 BY port
        )
    "#,
        p = project_clause(project)
    );
    let bytes = client.query(&sql).bind(&pattern).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_domain(client: &Client, q: &str, project: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let lower_q = q.to_lowercase();
    let p = project_clause(project);
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT 1 AS src FROM scan_results_whatweb
            WHERE {p} AND (ilike(target, ?) OR ilike(url, ?))
            UNION ALL
            SELECT 1 AS src FROM scan_results_ssl
            WHERE {p} AND (ilike(host, ?)
               OR position(lower(subject), ?) > 0
               OR arrayExists(x -> position(lower(x), ?) > 0, san))
            UNION ALL
            SELECT 1 AS src FROM scan_results_dns
            WHERE {p} AND (ilike(target, ?)
               OR arrayExists(x -> ilike(x, ?), a)
               OR arrayExists(x -> ilike(x, ?), cname)
               OR arrayExists(x -> ilike(x, ?), mx)
               OR arrayExists(x -> ilike(x, ?), ns)
               OR arrayExists(x -> ilike(x, ?), ptr))
        )
    "#,
        p = p
    );
    let bytes = client.query(&sql)
        .bind(&pattern).bind(&pattern)
        .bind(&pattern).bind(&lower_q).bind(&lower_q)
        .bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern)
        .fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_port(client: &Client, q: u16, project: &str) -> Result<u64> {
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT target FROM scan_results_nmap
            WHERE {p} AND port = ?
            ORDER BY scanned_at DESC
            LIMIT 1 BY target
        )
    "#,
        p = project_clause(project)
    );
    let bytes = client.query(&sql).bind(q).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_title(client: &Client, q: &str, project: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT target, port FROM scan_results_whatweb
            WHERE {p} AND ilike(title, ?)
            ORDER BY scanned_at DESC
            LIMIT 1 BY target, port
        )
    "#,
        p = project_clause(project)
    );
    let bytes = client.query(&sql).bind(&pattern).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_header(client: &Client, q: &str, project: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT target, port FROM scan_results_whatweb
            WHERE {p} AND headers != '' AND ilike(headers, ?)
            ORDER BY scanned_at DESC
            LIMIT 1 BY target, port
        )
    "#,
        p = project_clause(project)
    );
    let bytes = client.query(&sql).bind(&pattern).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_technology(client: &Client, q: &str, project: &str) -> Result<u64> {
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT target, port FROM scan_results_whatweb
            WHERE {p} AND has(technologies, ?)
            ORDER BY scanned_at DESC
            LIMIT 1 BY target, port
        )
    "#,
        p = project_clause(project)
    );
    let bytes = client.query(&sql).bind(q).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_protocol(client: &Client, q: &str, project: &str) -> Result<u64> {
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT target, port FROM scan_results_nmap
            WHERE {p} AND protocol = ?
            ORDER BY scanned_at DESC
            LIMIT 1 BY target, port
        )
    "#,
        p = project_clause(project)
    );
    let bytes = client.query(&sql).bind(q).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_service(client: &Client, q: &str, project: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT target, port FROM scan_results_nmap
            WHERE {p} AND ilike(service, ?)
            ORDER BY scanned_at DESC
            LIMIT 1 BY target, port
        )
    "#,
        p = project_clause(project)
    );
    let bytes = client.query(&sql).bind(&pattern).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_image(client: &Client, q: &str, project: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        "SELECT count(*) AS cnt FROM scan_screenshots WHERE {p} AND ilike(target, ?)",
        p = project_clause(project)
    );
    let bytes = client.query(&sql).bind(&pattern).fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_dns(client: &Client, q: &str, project: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT target FROM scan_results_dns
            WHERE {p} AND (ilike(target, ?)
               OR arrayExists(x -> ilike(x, ?), a)
               OR arrayExists(x -> ilike(x, ?), aaaa)
               OR arrayExists(x -> ilike(x, ?), cname)
               OR arrayExists(x -> ilike(x, ?), mx)
               OR arrayExists(x -> ilike(x, ?), ns)
               OR arrayExists(x -> ilike(x, ?), txt)
               OR arrayExists(x -> ilike(x, ?), ptr))
            ORDER BY scanned_at DESC
            LIMIT 1 BY target
        )
    "#,
        p = project_clause(project)
    );
    let bytes = client.query(&sql)
        .bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern)
        .bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern)
        .fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_by_ssl(client: &Client, q: &str, project: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let lower_q = q.to_lowercase();
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT host, port FROM scan_results_ssl
            WHERE {p} AND (ilike(host, ?)
               OR ilike(subject, ?)
               OR ilike(issuer, ?)
               OR ilike(serial, ?)
               OR arrayExists(x -> ilike(x, ?), san)
               OR position(lower(subject), ?) > 0
               OR position(lower(issuer), ?) > 0
               OR arrayExists(x -> position(lower(x), ?) > 0, san))
            ORDER BY scanned_at DESC
            LIMIT 1 BY host, port
        )
    "#,
        p = project_clause(project)
    );
    let bytes = client.query(&sql)
        .bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern).bind(&pattern)
        .bind(&lower_q).bind(&lower_q).bind(&lower_q)
        .fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}

pub async fn count_search_aggregated(client: &Client, q: &str, project: &str) -> Result<u64> {
    let pattern = format!("%{}%", q);
    let p = project_clause(project);
    let sql = format!(
        r#"
        SELECT count(*) AS cnt FROM (
            SELECT DISTINCT target FROM (
                SELECT target FROM scan_results_nmap
                WHERE {p} AND (ilike(target, ?) OR ilike(service, ?) OR ilike(product, ?))
                UNION ALL
                SELECT target FROM scan_results_whatweb
                WHERE {p} AND (ilike(target, ?) OR ilike(title, ?) OR has(technologies, ?))
                UNION ALL
                SELECT target FROM scan_results_rustscan
                WHERE {p} AND ilike(target, ?)
            )
        )
    "#,
        p = p
    );
    let bytes = client.query(&sql)
        .bind(&pattern).bind(&pattern).bind(&pattern)
        .bind(&pattern).bind(&pattern).bind(q)
        .bind(&pattern)
        .fetch_bytes("JSONEachRow")?.collect().await?;
    let rows = parse_json_each_row(&bytes)?;
    Ok(rows.first().and_then(|r| r["cnt"].as_u64()).unwrap_or(0))
}
