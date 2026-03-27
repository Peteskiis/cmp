use std::sync::Arc;

use tokio_rusqlite::Connection;

use crate::connection::ConnectionRegistry;

/// Shared server state, passed to all handlers via axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    pub db: Connection,
    pub connections: Arc<ConnectionRegistry>,
    pub server_id: String,
}

impl AppState {
    pub fn new(db: Connection, server_id: String) -> Self {
        Self {
            db,
            connections: Arc::new(ConnectionRegistry::new()),
            server_id,
        }
    }
}
