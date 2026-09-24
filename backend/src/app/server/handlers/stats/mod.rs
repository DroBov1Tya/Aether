pub mod geo;
pub mod ports;
pub mod services;
pub mod summary;
pub mod technologies;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct TopParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    25
}
