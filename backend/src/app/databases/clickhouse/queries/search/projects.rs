use anyhow::Result;
use clickhouse::Client;
use serde_json::Value;

use super::parse_json_each_row;

pub async fn list_projects(client: &Client) -> Result<Vec<Value>> {
    let sql = r#"
        SELECT
            project,
            uniqExact(target) AS hosts,
            max(last_seen) AS last_seen
        FROM (
            SELECT project, target, max(scanned_at) AS last_seen FROM scan_results_nmap GROUP BY project, target
            UNION ALL
            SELECT project, target, max(scanned_at) AS last_seen FROM scan_results_rustscan GROUP BY project, target
            UNION ALL
            SELECT project, target, max(scanned_at) AS last_seen FROM scan_results_whatweb GROUP BY project, target
        )
        WHERE project != 'global'
        GROUP BY project
        ORDER BY last_seen DESC
    "#;
    let bytes = client
        .query(sql)
        .fetch_bytes("JSONEachRow")?
        .collect()
        .await?;
    parse_json_each_row(&bytes)
}
