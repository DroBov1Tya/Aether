use anyhow::Result;
use s3::bucket::Bucket;

pub async fn get_object(bucket: &Bucket, key: &str) -> Result<Vec<u8>> {
    let response = bucket.get_object(key).await?;
    Ok(response.as_slice().to_vec())
}
