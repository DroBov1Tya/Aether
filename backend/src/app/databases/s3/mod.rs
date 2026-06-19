use anyhow::Result;
use s3::Bucket;
use s3::creds::Credentials;
use s3::region::Region;

pub mod queries;

pub fn new(
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    bucket_name: &str,
) -> Result<Bucket> {
    let credentials = Credentials::new(Some(access_key), Some(secret_key), None, None, None)?;

    let region = Region::Custom {
        region: "auto".to_string(),
        endpoint: endpoint.to_string(),
    };

    let bucket = Bucket::new(bucket_name, region, credentials)?.with_path_style();

    Ok(*bucket)
}
