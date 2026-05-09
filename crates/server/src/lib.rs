pub(crate) mod connection;
pub mod db;
pub(crate) mod handlers;
pub mod state;
pub(crate) mod ws;

use axum::Router;
use axum::routing::get;
use tokio_rusqlite::Connection;

use state::AppState;

/// Build the axum router with the given state.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { "CMP relay — WebSocket endpoint at /ws\n" }))
        .route("/health", get(|| async { "OK\n" }))
        .route("/ws", get(ws::ws_upgrade))
        .with_state(state)
}

/// Start a server on the given listener with an in-memory DB (for tests).
pub async fn start_server(
    listener: tokio::net::TcpListener,
    server_id: &str,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let conn = Connection::open(":memory:").await?;
    db::schema::initialize(&conn).await?;

    let state = AppState::new(conn, server_id.to_owned());
    let app = build_router(state);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    Ok(handle)
}
