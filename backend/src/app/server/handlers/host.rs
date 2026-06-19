use crate::app::AppState;
use crate::app::databases::clickhouse::queries::search;
use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::sync::Arc;

pub async fn get_host(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    let (nmap, whatweb, screenshots, summary, dns, ssl) = tokio::join!(
        search::fetch_host_nmap(&state.ch, &ip),
        search::fetch_host_whatweb(&state.ch, &ip),
        search::fetch_host_screenshots(&state.ch, &ip),
        search::host_summary(&state.ch, &ip),
        search::fetch_host_dns(&state.ch, &ip),
        search::fetch_host_ssl(&state.ch, &ip),
    );

    let nmap = nmap.unwrap_or_else(|e| {
        tracing::error!("nmap: {e}");
        vec![]
    });
    let whatweb = whatweb.unwrap_or_else(|e| {
        tracing::error!("whatweb: {e}");
        vec![]
    });
    let screenshots = screenshots.unwrap_or_else(|e| {
        tracing::error!("screenshots: {e}");
        vec![]
    });
    let dns = dns.unwrap_or_else(|e| {
        tracing::error!("dns: {e}");
        Value::Null
    });
    let ssl = ssl.unwrap_or_else(|e| {
        tracing::error!("ssl: {e}");
        vec![]
    });

    let summary = summary.unwrap_or_else(|_| {
        json!({
            "open_ports": nmap.len(),
            "first_seen": Value::Null,
            "last_seen": Value::Null,
        })
    });

    if nmap.is_empty()
        && whatweb.is_empty()
        && screenshots.is_empty()
        && dns.is_null()
        && ssl.is_empty()
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "error": "no data found for this host" })),
        );
    }

    let total_services = whatweb.iter().filter_map(|r| r["title"].as_str()).count()
        + nmap.iter().filter_map(|r| r["service"].as_str()).count();

    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "target": ip,
            "open_ports": nmap,
            "web_services": whatweb,
            "screenshots": screenshots,
            "dns": dns,
            "ssl": ssl,
            "summary": {
                "open_ports": summary["open_ports"],
                "total_services": total_services,
                "first_seen": summary["first_seen"],
                "last_seen": summary["last_seen"],
            }
        })),
    )
}

pub async fn get_screenshot(
    State(state): State<Arc<AppState>>,
    Path((ip, port)): Path<(String, u16)>,
) -> impl IntoResponse {
    let sql = r#"
        SELECT s3_key, file_size
        FROM scan_screenshots
        WHERE target = ? AND port = ?
        ORDER BY taken_at DESC
        LIMIT 1
    "#;

    let mut cursor = match state
        .ch
        .query(sql)
        .bind(&ip)
        .bind(port)
        .fetch::<(String, u32)>()
    {
        Ok(cursor) => cursor,
        Err(e) => {
            tracing::error!("ClickHouse query failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    let (s3_key, _file_size) = match cursor.next().await {
        Ok(Some(row)) => row,
        Ok(None) => {
            tracing::warn!("Screenshot not found in DB: {}:{}", ip, port);
            return (StatusCode::NOT_FOUND, "Screenshot not found").into_response();
        }
        Err(e) => {
            tracing::error!("Failed to fetch row: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    match state.s3.get_object(&s3_key).await {
        Ok(response_data) => {
            let status = response_data.status_code();
            if status != 200 {
                tracing::warn!("S3 returned status {} for key: {}", status, s3_key);
                return (StatusCode::NOT_FOUND, "Screenshot not found in storage").into_response();
            }

            let bytes = response_data.bytes().to_vec();

            let content_type = if s3_key.ends_with(".jpg") || s3_key.ends_with(".jpeg") {
                "image/jpeg"
            } else if s3_key.ends_with(".webp") {
                "image/webp"
            } else {
                "image/png"
            };

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CACHE_CONTROL, "public, max-age=31536000")
                .body(Body::from(bytes))
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to build response: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to build response",
                    )
                        .into_response()
                })
        }
        Err(e) => {
            tracing::error!("S3 get_object failed for key {}: {}", s3_key, e);
            (StatusCode::NOT_FOUND, "Screenshot not found in storage").into_response()
        }
    }
}

pub async fn host_history(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    let (nmap_history, whatweb_history) = tokio::join!(
        search::fetch_host_nmap_history(&state.ch, &ip),
        search::fetch_host_whatweb_history(&state.ch, &ip),
    );

    let nmap = nmap_history.unwrap_or_else(|e| {
        tracing::error!("nmap_history: {e}");
        vec![]
    });
    let whatweb = whatweb_history.unwrap_or_else(|e| {
        tracing::error!("whatweb_history: {e}");
        vec![]
    });

    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "data": { "nmap": nmap, "whatweb": whatweb }
        })),
    )
}

pub async fn host_snapshots(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    match search::fetch_host_snapshots(&state.ch, &ip).await {
        Ok(snapshots) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "target": ip,
                "snapshots": snapshots,
            })),
        ),
        Err(e) => {
            tracing::error!("host_snapshots failed for {}: {}", ip, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
        }
    }
}
