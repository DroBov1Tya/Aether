use anyhow::Result;
use s3::bucket::Bucket;

pub async fn upload(
    bucket: &Bucket,
    target: &str,
    port: u16,
    image_bytes: &[u8],
) -> Result<String> {
    let key = format!("screenshots/{}/{}.png", target, port);

    let resp = bucket.put_object(&key, image_bytes).await?;
    let status = resp.status_code();
    if status < 200 || status >= 300 {
        anyhow::bail!("S3 put_object returned status {} for key '{}'", status, key);
    }

    Ok(key)
}
