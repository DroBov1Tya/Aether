pub mod aggregated;
pub mod dns;
pub mod domain;
pub mod header;
pub mod image;
pub mod ip;
pub mod port;
pub mod protocol;
pub mod service;
pub mod ssl;
pub mod technology;
pub mod title;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct QParam {
    pub q: String,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
    #[serde(default = "default_project")]
    pub project: String,
}

#[derive(Deserialize)]
pub struct PortParam {
    pub q: u16,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
    #[serde(default = "default_project")]
    pub project: String,
}

fn default_page() -> u32 {
    1
}
fn default_per_page() -> u32 {
    50
}
pub fn default_project() -> String {
    "global".to_string()
}

impl QParam {
    pub fn offset(&self) -> u32 {
        self.per_page * (self.page.saturating_sub(1))
    }
}

impl PortParam {
    pub fn offset(&self) -> u32 {
        self.per_page * (self.page.saturating_sub(1))
    }
}
