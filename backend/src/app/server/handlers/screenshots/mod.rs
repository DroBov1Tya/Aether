pub mod count;
pub mod thumbnails;

pub use count::list_screenshots_count;
pub use thumbnails::list_screenshots_thumbnails;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ScreenshotListParams {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

impl ScreenshotListParams {
    fn offset(&self) -> u32 {
        let pp = self.per_page.unwrap_or(20);
        let pg = self.page.unwrap_or(1);
        pp * (pg.saturating_sub(1))
    }
}
