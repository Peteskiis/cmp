mod app;
mod crypto_mgr;
mod db;
mod net;
mod ui;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "cmp", about = "CMP encrypted messaging client")]
struct Cli {
    /// Your username
    #[arg(long)]
    user: String,

    /// Server WebSocket URL
    #[arg(long, default_value = "ws://127.0.0.1:3000/ws")]
    server: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();

    let cli = Cli::parse();

    app::run(&cli.user, &cli.server).await
}
