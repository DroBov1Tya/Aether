use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct ExternalReq {
    pub status: String,
    pub target: String,
    pub body: String,
    pub version: &'static str,
}

pub async fn post_json<T: Serialize + std::fmt::Debug>(
    url: &str,
    body: &T,
    api_key: &str,
) -> anyhow::Result<reqwest::Response> {
    let cfg = crate::config::cfg();

    for proxy_url in &cfg.proxies {
        let client_result = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .proxy(reqwest::Proxy::all(proxy_url)?)
            .build();

        if let Ok(client) = client_result {
            let res = client
                .post(url)
                .header("X-API-KEY", api_key)
                .json(body)
                .send()
                .await;

            match res {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::debug!(proxy = %proxy_url, error = %e, "Proxy request failed, trying next");
                }
            }
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let response = client
        .post(url)
        .header("X-API-KEY", api_key)
        .json(body)
        .send()
        .await?;

    Ok(response)
}
