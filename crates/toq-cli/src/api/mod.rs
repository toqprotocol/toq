//! Local API server for SDK integration.
//!
//! Exposes an HTTP API on localhost (configurable) that SDKs and tooling
//! use to interact with the daemon. The daemon handles all protocol
//! complexity; this API is the bridge to application code.

mod handlers;
mod state;
mod types;

pub use state::ApiState;

use axum::Router;
use axum::routing::{get, post};

use crate::api::handlers::*;

pub const DEFAULT_API_ADDRESS: &str = "127.0.0.1:9010";

pub fn router(state: ApiState) -> Router {
    Router::new()
        // Daemon
        .route("/v1/health", get(health_check))
        .route("/v1/status", get(get_status))
        .route("/v1/daemon/shutdown", post(shutdown_daemon))
        .route("/v1/logs", get(get_logs).delete(clear_logs))
        .route("/v1/diagnostics", get(run_diagnostics))
        // Peers
        .route("/v1/peers", get(list_peers))
        .route(
            "/v1/peers/{public_key}/block",
            post(block_peer).delete(unblock_peer),
        )
        // Config
        .route("/v1/config", get(get_config).patch(update_config))
        // Agent card
        .route("/v1/card", get(get_agent_card))
        // Keys
        .route("/v1/keys/rotate", post(rotate_keys))
        .with_state(state)
}

/// Start the local API server.
pub async fn serve(state: ApiState, address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = address.parse::<std::net::SocketAddr>()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("local API listening on {addr}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
