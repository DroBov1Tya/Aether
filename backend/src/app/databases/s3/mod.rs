use anyhow::{Context, Result};
use s3::bucket::Bucket;
use s3::bucket_ops::BucketConfiguration;
use s3::creds::Credentials;
use s3::region::Region;

pub mod queries;

pub async fn new(
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    bucket_name: &str,
) -> Result<Bucket> {
    let credentials = Credentials::new(Some(access_key), Some(secret_key), None, None, None)?;

    let region = Region::Custom {
        region: "us-east-1".to_string(),
        endpoint: endpoint.to_string(),
    };

    let bucket = Bucket::new(bucket_name, region.clone(), credentials.clone())?.with_path_style();

    match bucket.exists().await {
        Ok(true) => {
            tracing::info!("✅ S3 bucket '{}' already exists", bucket_name);
        }
        Ok(false) | Err(_) => {
            tracing::info!("⏳ Ensuring S3 bucket '{}' exists...", bucket_name);

            // 👇 ИСПОЛЬЗУЕМ СПЕЦИАЛЬНЫЙ МЕТОД 👇
            Bucket::create_with_path_style(
                bucket_name,
                region,
                credentials,
                BucketConfiguration::default(),
            )
            .await
            .context(format!(
                "Failed to create or verify S3 bucket '{}'. Check time sync and credentials.",
                bucket_name
            ))?;

            tracing::info!("✅ S3 bucket '{}' is ready", bucket_name);
        }
    }

    Ok(*bucket)
}
