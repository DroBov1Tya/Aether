use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CheckoutReq {
    pub status: String,
    pub target: String,
    #[serde(deserialize_with = "parse_body")]
    pub body: Value,
    pub version: String,
}

fn parse_body<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(serde_json::from_str(&s).unwrap_or(Value::String(s)))
}
