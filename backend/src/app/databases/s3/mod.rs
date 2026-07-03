use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;

pub mod queries;

pub async fn new(
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    bucket_name: &str,
) -> Option<Bucket> {
    let credentials = match Credentials::new(Some(access_key), Some(secret_key), None, None, None) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("S3 credentials error: {e}, S3 disabled");
            return None;
        }
    };

    let region = Region::Custom {
        region: "us-east-1".to_string(),
        endpoint: endpoint.to_string(),
    };

    match Bucket::new(bucket_name, region, credentials) {
        Ok(b) => {
            tracing::info!("S3 bucket '{}' configured (assumed to exist)", bucket_name);
            Some(*b.with_path_style())
        }
        Err(e) => {
            tracing::warn!("S3 Bucket::new error: {e}, S3 disabled");
            None
        }
    }
}
