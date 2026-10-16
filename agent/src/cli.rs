use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

use clap::{Parser, Subcommand};
use colored::Colorize;

use crate::app;
use crate::app::scan::{self, PipelineOpts, ScanSettings};
use crate::app::tools::proxy;
use crate::app::tools::sink::{LocalReport, Sink};

#[derive(Parser, Debug)]
#[command(name = "aether", about = "Aether standalone headless recon")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Scan(ScanArgs),
}

#[derive(Parser, Debug)]
pub struct ScanArgs {
    pub targets: Vec<String>,
    #[arg(long, default_value = "./aether-recon")]
    pub out: String,
    #[arg(long = "proxy")]
    pub proxy: Vec<String>,
    #[arg(long, default_value_t = false)]
    pub portscan: bool,
    #[arg(long, default_value_t = false)]
    pub aggressive: bool,
    #[arg(long = "deep-tls", default_value_t = false)]
    pub deep_tls: bool,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub screenshots: bool,
    #[arg(long, default_value_t = 3)]
    pub concurrency: usize,
}

pub fn parse() -> Option<Cli> {
    let mut args = std::env::args();
    let _bin = args.next();
    match args.next().as_deref() {
        Some("scan") => Cli::try_parse().ok(),
        _ => None,
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    let Command::Scan(args) = cli.command;

    if args.targets.is_empty() {
        anyhow::bail!("no targets given; usage: aether scan <target...> [--out DIR]");
    }

    config_init();
    let cfg = crate::config::cfg();

    let out_dir = PathBuf::from(&args.out);
    tokio::fs::create_dir_all(&out_dir).await?;
    let shots_dir = out_dir.join("screenshots");
    tokio::fs::create_dir_all(&shots_dir).await?;

    let report = Arc::new(Mutex::new(LocalReport::default()));
    let sink = Sink::Local(Arc::clone(&report));
    let pool = proxy::local_pool(cfg, &args.proxy);
    if !pool.is_empty() {
        tracing::info!("proxy pool: {} entries", pool.len());
    }

    let portscan = args.portscan || args.aggressive;
    let opts = PipelineOpts {
        portscan,
        deep_tls: args.deep_tls,
        screenshots: args.screenshots,
        cooldown_secs: 0,
        screenshot_dir: shots_dir.to_string_lossy().to_string(),
    };

    let state = app::minimal_state();

    let mut expanded: Vec<String> = Vec::new();
    for t in &args.targets {
        for h in scan::expand_target(t) {
            expanded.push(h);
        }
    }

    eprintln!(
        "{} {} target(s), portscan={}, deep_tls={}, screenshots={}, concurrency={}",
        "▶ aether scan:".bold().cyan(),
        expanded.len(),
        portscan,
        args.deep_tls,
        args.screenshots,
        args.concurrency,
    );

    let limiter = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let mut handles = Vec::new();
    for target in expanded {
        let state = Arc::clone(&state);
        let sink = sink.clone();
        let pool = pool.clone();
        let opts = opts.clone();
        let limiter = Arc::clone(&limiter);
        handles.push(tokio::spawn(async move {
            let _permit = limiter.acquire().await.ok();
            let settings = ScanSettings::default();
            let ok = scan::run_pipeline_with(&state, &target, None, &settings, &sink, &pool, opts).await;
            tracing::info!("target {} done ok={}", target, ok);
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    let guard = report.lock().await;
    let uid = uuid::Uuid::new_v4().to_string();
    let report_path = out_dir.join(format!("aether-recon-{uid}.json"));
    let json = serde_json::to_string_pretty(&guard.to_json())?;
    tokio::fs::write(&report_path, json).await?;

    copy_screenshots(&guard.screenshots, &shots_dir).await;

    println!("{}", guard.summary());
    println!(
        "{} {}",
        "✔ report written:".bold().green(),
        report_path.display()
    );

    Ok(())
}

fn config_init() {
    crate::config::init();
}

async fn copy_screenshots(paths: &[String], dest: &Path) {
    for p in paths {
        let src = Path::new(p);
        if src.starts_with(dest) {
            continue;
        }
        if let Some(name) = src.file_name() {
            let target = dest.join(name);
            if let Err(e) = tokio::fs::copy(src, &target).await {
                tracing::debug!(src = %p, err = %e, "screenshot copy failed");
            }
        }
    }
}
