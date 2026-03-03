//! Local API server for SDK integration.
//!
//! Exposes an HTTP API on localhost that SDKs and tooling use to
//! interact with the daemon. Internal plumbing between the SDK
//! and the daemon on the same machine.

mod handlers;
mod state;
pub mod types;

pub use state::ApiState;

use axum::Router;
use axum::routing::{get, post};

use crate::api::handlers::*;

pub const DEFAULT_API_ADDRESS: &str = "127.0.0.1:9010";

pub fn router(state: ApiState) -> Router {
    Router::new()
        // Messages
        .route("/v1/messages", post(send_message).get(stream_messages))
        .route("/v1/messages/{id}/cancel", post(cancel_message))
        .route("/v1/messages/stream", post(send_streaming_message))
        // Threads
        .route("/v1/threads/{thread_id}", get(get_thread))
        // Peers
        .route("/v1/peers", get(list_peers))
        .route(
            "/v1/peers/{public_key}/block",
            post(block_peer).delete(unblock_peer),
        )
        // Discovery
        .route("/v1/discover", get(discover_dns))
        .route("/v1/discover/local", get(discover_local))
        // Approvals
        .route("/v1/approvals", get(list_approvals))
        .route("/v1/approvals/{id}", post(resolve_approval))
        // Connections
        .route("/v1/connections", get(list_connections))
        // Daemon
        .route("/v1/health", get(health_check))
        .route("/v1/status", get(get_status))
        .route("/v1/daemon/shutdown", post(shutdown_daemon))
        .route("/v1/logs", get(get_logs).delete(clear_logs))
        .route("/v1/diagnostics", get(run_diagnostics))
        .route("/v1/upgrade/check", get(check_upgrade))
        // Keys
        .route("/v1/keys/rotate", post(rotate_keys))
        // Backup
        .route("/v1/backup/export", post(export_backup))
        .route("/v1/backup/import", post(import_backup))
        // Config
        .route("/v1/config", get(get_config).patch(update_config))
        // Agent card
        .route("/v1/card", get(get_agent_card))
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
