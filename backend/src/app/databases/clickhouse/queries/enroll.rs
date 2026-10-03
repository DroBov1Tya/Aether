use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
use clickhouse::{Client, Row};
use serde::Serialize;

use super::tokens::sha256_hex;

#[derive(Debug, Row, Serialize)]
struct EnrollRow {
    token_hash: String,
    label: String,
    max_uses: u32,
    uses: u32,
    #[serde(with = "clickhouse::serde::chrono::datetime::option")]
    expires_at: Option<DateTime<Utc>>,
    revoked: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollView {
    pub token_hash: String,
    pub label: String,
    pub max_uses: u32,
    pub uses: u32,
    pub expires_at: String,
    pub revoked: u8,
    pub created_at: String,
}

pub async fn create(
    client: &Client,
    token: &str,
    label: &str,
    max_uses: u32,
    expires_at: Option<DateTime<Utc>>,
) -> Result<()> {
    let row = EnrollRow {
        token_hash: sha256_hex(token),
        label: label.to_string(),
        max_uses,
        uses: 0,
        expires_at,
        revoked: 0,
    };
    let mut inserter = client.insert::<EnrollRow>("enrollment_tokens").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}

pub async fn list(client: &Client) -> Result<Vec<EnrollView>> {
    let bytes = client
        .query(
            "SELECT token_hash, label, max_uses, uses, \
             toString(expires_at) AS expires_at, revoked, \
             toString(created_at) AS created_at \
             FROM enrollment_tokens FINAL \
             ORDER BY created_at DESC",
        )
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;

    let mut out = Vec::new();
    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        out.push(EnrollView {
            token_hash: v["token_hash"].as_str().unwrap_or_default().to_string(),
            label: v["label"].as_str().unwrap_or_default().to_string(),
            max_uses: v["max_uses"].as_u64().unwrap_or(0) as u32,
            uses: v["uses"].as_u64().unwrap_or(0) as u32,
            expires_at: v["expires_at"].as_str().unwrap_or_default().to_string(),
            revoked: v["revoked"].as_u64().unwrap_or(0) as u8,
            created_at: v["created_at"].as_str().unwrap_or_default().to_string(),
        });
    }
    Ok(out)
}

pub async fn consume(client: &Client, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let hash = sha256_hex(token);

    let bytes = match client
        .query(
            "SELECT label, max_uses, uses, \
             toString(expires_at) AS expires_at, revoked \
             FROM enrollment_tokens FINAL WHERE token_hash = ? LIMIT 1",
        )
        .bind(&hash)
        .fetch_bytes("JSONEachRow")
    {
        Ok(c) => {
            let mut c = c;
            match c.collect().await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("enroll consume collect failed: {e}");
                    return false;
                }
            }
        }
        Err(e) => {
            tracing::warn!("enroll consume query failed: {e}");
            return false;
        }
    };

    let Some(v) = bytes
        .split(|&b| b == b'\n')
        .find(|l| !l.is_empty())
        .and_then(|l| serde_json::from_slice::<serde_json::Value>(l).ok())
    else {
        return false;
    };

    if v["revoked"].as_u64().unwrap_or(0) != 0 {
        return false;
    }
    let max_uses = v["max_uses"].as_u64().unwrap_or(0) as u32;
    let uses = v["uses"].as_u64().unwrap_or(0) as u32;
    if max_uses != 0 && uses >= max_uses {
        return false;
    }
    let expires_raw = v["expires_at"].as_str().unwrap_or_default();
    if !expires_raw.is_empty() && expires_raw != "1970-01-01 00:00:00" {
        if let Ok(exp) = NaiveDateTime::parse_from_str(expires_raw.trim(), "%Y-%m-%d %H:%M:%S") {
            if exp.and_utc() <= Utc::now() {
                return false;
            }
        }
    }

    let expires_at = if expires_raw.is_empty() || expires_raw == "1970-01-01 00:00:00" {
        None
    } else {
        NaiveDateTime::parse_from_str(expires_raw.trim(), "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|n| n.and_utc())
    };

    let row = EnrollRow {
        token_hash: hash,
        label: v["label"].as_str().unwrap_or_default().to_string(),
        max_uses,
        uses: uses + 1,
        expires_at,
        revoked: 0,
    };
    match client.insert::<EnrollRow>("enrollment_tokens").await {
        Ok(mut inserter) => {
            if let Err(e) = inserter.write(&row).await.and(inserter.end().await) {
                tracing::warn!("enroll consume increment failed: {e}");
            }
        }
        Err(e) => tracing::warn!("enroll consume insert failed: {e}"),
    }

    true
}

pub async fn revoke(client: &Client, token_hash: &str) -> Result<()> {
    let bytes = client
        .query(
            "SELECT label, max_uses, uses, toString(expires_at) AS expires_at \
             FROM enrollment_tokens FINAL WHERE token_hash = ? LIMIT 1",
        )
        .bind(token_hash)
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;

    let Some(v) = bytes
        .split(|&b| b == b'\n')
        .find(|l| !l.is_empty())
        .and_then(|l| serde_json::from_slice::<serde_json::Value>(l).ok())
    else {
        return Ok(());
    };

    let expires_raw = v["expires_at"].as_str().unwrap_or_default();
    let expires_at = if expires_raw.is_empty() || expires_raw == "1970-01-01 00:00:00" {
        None
    } else {
        NaiveDateTime::parse_from_str(expires_raw.trim(), "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|n| n.and_utc())
    };

    let row = EnrollRow {
        token_hash: token_hash.to_string(),
        label: v["label"].as_str().unwrap_or_default().to_string(),
        max_uses: v["max_uses"].as_u64().unwrap_or(0) as u32,
        uses: v["uses"].as_u64().unwrap_or(0) as u32,
        expires_at,
        revoked: 1,
    };
    let mut inserter = client.insert::<EnrollRow>("enrollment_tokens").await?;
    inserter.write(&row).await?;
    inserter.end().await?;
    Ok(())
}
