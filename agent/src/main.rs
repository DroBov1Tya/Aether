use anyhow::Result;

mod app;
mod cli;
mod config;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    config::init_logger();

    if let Some(cli) = cli::parse() {
        cli::run(cli).await?;
        return Ok(());
    }

    let app = app::Application::build().await?;

    app.run().await?;

    Ok(())
}
