use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct CheckoutReq {
    pub target: String,
    #[serde(deserialize_with = "parse_body")]
    pub body: Value,
}

fn parse_body<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(serde_json::from_str(&s).unwrap_or(Value::String(s)))
}
