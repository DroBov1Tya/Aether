use anyhow::Result;
use serde_json::Value;

pub fn parse_json_each_row(bytes: &[u8]) -> Result<Vec<Value>> {
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
