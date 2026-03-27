use std::net::SocketAddr;

use tokio::signal;
use tokio_rusqlite::Connection;
use tracing::info;
use tracing_subscriber::EnvFilter;

use server::state::AppState;

const DEFAULT_BIND: &str = "127.0.0.1:3000";
const DEFAULT_DB_PATH: &str = "cmp-server.db";
const DEFAULT_SERVER_ID: &str = "cmp-server-1";
const GC_INTERVAL_SECS: u64 = 3600;
const GC_MAX_AGE_DAYS: u32 = 30;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bind_addr: SocketAddr = std::env::var("CMP_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.to_owned())
        .parse()?;

    let db_path = std::env::var("CMP_DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.to_owned());
    let server_id = std::env::var("CMP_SERVER_ID").unwrap_or_else(|_| DEFAULT_SERVER_ID.to_owned());

    let conn = Connection::open(&db_path).await?;
    server::db::schema::initialize(&conn).await?;

    let state = AppState::new(conn.clone(), server_id);
    spawn_gc_task(conn);

    let app = server::build_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!("listening on {bind_addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("server shut down");
    Ok(())
}

fn spawn_gc_task(conn: Connection) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(GC_INTERVAL_SECS));
        loop {
            interval.tick().await;
            match server::db::queue::gc_old_messages(&conn, GC_MAX_AGE_DAYS).await {
                Ok(n) if n > 0 => info!(deleted = n, "message queue GC"),
                Ok(_) => {}
                Err(e) => tracing::warn!("message queue GC error: {e}"),
            }
        }
    });
}

#[allow(clippy::cognitive_complexity)]
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!("failed to install Ctrl+C handler: {e}");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("shutdown signal received");
}
