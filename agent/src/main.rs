use anyhow::Result;

mod app;
mod config;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    config::init_logger();

    let app = app::Application::build().await?;

    app.run().await?;

    Ok(())
}
