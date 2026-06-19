use anyhow::Result;
use s3::bucket::Bucket;

pub async fn upload(
    bucket: &Bucket,
    target: &str,
    port: u16,
    image_bytes: &[u8],
) -> Result<String> {
    let key = format!("screenshots/{}/{}.png", target, port);

    bucket.put_object(&key, image_bytes).await?;

    Ok(key)
}
