use anyhow::{Context, Result};
use clickhouse::Client;
use serde_json::{Value, json};

use super::parse_json_each_row;

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
        SELECT port, url, http_status, title, technologies, scanned_at, scan_uid
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
            scan_uid,
            scanned_at,
            groupArray(port) AS ports,
            count() AS port_count,
            groupUniqArray(service) AS services,
            groupUniqArray(product) AS products
        FROM scan_results_nmap
        WHERE target = ?
        GROUP BY scan_uid, scanned_at
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
            scan_uid,
            scanned_at,
            groupUniqArray(port) AS ports,
            groupUniqArray(http_status) AS statuses,
            groupUniqArray(title) AS titles,
            arrayDistinct(arrayFlatten(groupArray(technologies))) AS technologies
        FROM scan_results_whatweb
        WHERE target = ?
        GROUP BY scan_uid, scanned_at
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
        WITH scan_ids AS (
            SELECT scan_uid AS uid, scanned_at AS ts FROM scan_results_nmap WHERE target = ?
            UNION DISTINCT
            SELECT scan_uid, scanned_at FROM scan_results_whatweb WHERE target = ?
            UNION DISTINCT
            SELECT scan_uid, taken_at FROM scan_screenshots WHERE target = ?
            UNION DISTINCT
            SELECT scan_uid, scanned_at FROM scan_results_ssl WHERE host = ?
            ORDER BY ts DESC
        )
        SELECT
            uid AS scan_uid,
            ts AS scanned_at,
            (SELECT groupArray((
                port, protocol, state, service, product, version,
                confidence, detection_method, extra_info, os_type,
                state_reason, banner, cpe, scripts, os_name, os_accuracy, ttl
            ))
             FROM scan_results_nmap
             WHERE target = ? AND scan_uid = uid
            ) AS nmap,
            (SELECT groupArray((port, url, http_status, title, technologies))
             FROM scan_results_whatweb
             WHERE target = ? AND scan_uid = uid
            ) AS whatweb,
            (SELECT groupArray((port, s3_key, file_size))
             FROM scan_screenshots
             WHERE target = ? AND scan_uid = uid
            ) AS screenshots,
            (SELECT groupArray((port, subject, issuer, not_before, not_after,
                                serial, san, ssl_version, cipher, chain_length))
             FROM scan_results_ssl
             WHERE host = ? AND scan_uid = uid
            ) AS ssl
        FROM scan_ids
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

pub async fn fetch_host_rustscan(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT ports, scanned_at, scan_uid
        FROM scan_results_rustscan
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
        return Ok(vec![]);
    }

    let row = &j["data"][0];
    let scanned_at = row["scanned_at"].as_str().unwrap_or("");
    let ports = row["ports"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64())
                .map(|p| {
                    json!({
                        "port": p,
                        "protocol": "tcp",
                        "state": "open",
                        "service": null,
                        "detection_method": "rustscan",
                        "scan_uid": row["scan_uid"],
                        "scanned_at": scanned_at,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(ports)
}

pub async fn fetch_host_fuzzing(client: &Client, target: &str) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT port, path, url, http_status, scanned_at
        FROM scan_results_fuzzing
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
    rows.sort_by(|a, b| {
        let pa = a["port"].as_u64().unwrap_or(0);
        let pb = b["port"].as_u64().unwrap_or(0);
        pa.cmp(&pb).then(
            a["path"]
                .as_str()
                .unwrap_or("")
                .cmp(b["path"].as_str().unwrap_or("")),
        )
    });
    Ok(rows)
}
