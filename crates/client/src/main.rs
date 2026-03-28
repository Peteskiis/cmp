mod app;
mod crypto_mgr;
mod db;
mod net;
mod ui;

use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "cmp", about = "CMP encrypted messaging client")]
struct Cli {
    /// Your username (saved as default for next time)
    #[arg(long)]
    user: Option<String>,

    /// Server WebSocket URL
    #[arg(long, default_value = "ws://127.0.0.1:3000/ws")]
    server: String,
}

fn default_user_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home).join(".cmp").join(".default_user")
}

fn load_default_user() -> Option<String> {
    std::fs::read_to_string(default_user_path())
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

#[allow(clippy::cognitive_complexity)] // cfg blocks inflate the metric
fn save_default_user(user: &str) {
    let path = default_user_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!("failed to create config directory: {e}");
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            {
                tracing::warn!("failed to set config directory permissions: {e}");
                return;
            }
        }
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        if let Err(e) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(user.as_bytes()))
        {
            tracing::warn!("failed to save default user: {e}");
        }
    }
    #[cfg(not(unix))]
    if let Err(e) = std::fs::write(&path, user) {
        tracing::warn!("failed to save default user: {e}");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();

    let cli = Cli::parse();

    let user = match cli.user {
        Some(u) => u,
        None => load_default_user()
            .ok_or_else(|| anyhow::anyhow!("no default user. Run with: cmp --user <username>"))?,
    };

    // Validate before persisting — reject invalid usernames like "../foo"
    protocol::UserId::new(&user)?;
    save_default_user(&user);

    app::run(&user, &cli.server).await
}
