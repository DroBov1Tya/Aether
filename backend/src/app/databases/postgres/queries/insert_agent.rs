use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn insert(
    pool: &PgPool,
    id: Uuid,
    ip: &str,
    hostname: &str,
    version: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO agents (id, ip, name, version)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (id) DO UPDATE
            SET last_seen_at = now(),
                ip = EXCLUDED.ip,
                version = EXCLUDED.version
        "#,
    )
    .bind(id)
    .bind(ip)
    .bind(hostname)
    .bind(version)
    .execute(pool)
    .await?;

    Ok(())
}
