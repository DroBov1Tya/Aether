use anyhow::Result;
use s3::bucket::Bucket;

pub async fn get_object(bucket: &Bucket, key: &str) -> Result<Vec<u8>> {
    let response = bucket.get_object(key).await?;
    let status = response.status_code();
    if status < 200 || status >= 300 {
        anyhow::bail!("S3 get_object returned status {} for key '{}'", status, key);
    }
    Ok(response.as_slice().to_vec())
}
