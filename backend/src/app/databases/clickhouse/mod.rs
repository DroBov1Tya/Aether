use anyhow::Result;

pub mod queries;

pub fn new(url: &str, user: &str, password: &str) -> Result<clickhouse::Client> {
    let client = clickhouse::Client::default()
        .with_url(url)
        .with_user(user)
        .with_password(password)
        .with_compression(clickhouse::Compression::None)
        .with_database("aether");

    Ok(client)
}
