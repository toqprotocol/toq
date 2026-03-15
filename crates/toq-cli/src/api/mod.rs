//! Local API server for SDK integration.
//!
//! Exposes an HTTP API on localhost that SDKs and tooling use to
//! interact with the daemon. Internal plumbing between the SDK
//! and the daemon on the same machine.

mod handlers;
pub mod state;
pub mod types;

pub use state::ApiState;

use axum::Router;
use axum::routing::{get, post};

use crate::api::handlers::*;

pub fn router(state: ApiState, a2a_enabled: bool) -> Router {
    let mut app = local_routes().with_state(state.clone());

    if a2a_enabled {
        app = app.merge(a2a_routes(state));
    }

    app
}

/// Routes only accessible from remote connections (A2A endpoints).
/// Returns an empty router when A2A is disabled, ensuring remote
/// connections cannot reach any local API routes.
pub fn remote_router(state: ApiState, a2a_enabled: bool) -> Router {
    if a2a_enabled {
        a2a_routes(state)
    } else {
        Router::new()
    }
}

/// Local-only API routes (`/v1/*`). Only served to loopback connections.
fn local_routes() -> Router<ApiState> {
    Router::new()
        // Messages
        .route("/v1/messages", post(send_message).get(stream_messages))
        // Stream API
        .route("/v1/stream/start", post(stream_start))
        .route("/v1/stream/chunk", post(stream_chunk))
        .route("/v1/stream/end", post(stream_end))
        // Threads
        .route("/v1/threads/{thread_id}", get(get_thread))
        // Peers
        .route("/v1/peers", get(list_peers))
        .route(
            "/v1/peers/{public_key}/block",
            post(block_peer).delete(unblock_peer),
        )
        // Block/unblock with JSON body (new)
        .route("/v1/block", post(block_rule).delete(unblock_rule))
        // Discovery
        .route("/v1/discover", get(discover_dns))
        .route("/v1/discover/local", get(discover_local))
        // Approvals
        .route("/v1/approvals", get(list_approvals))
        .route("/v1/approvals/{id}", post(resolve_approval))
        .route("/v1/approvals/{id}/revoke", post(revoke_approval))
        // Approve/revoke with JSON body (new)
        .route("/v1/approve", post(approve_rule))
        .route("/v1/revoke", post(revoke_rule))
        // Permissions
        .route("/v1/permissions", get(list_permissions))
        // Ping
        .route("/v1/ping", post(ping_agent))
        // History
        .route("/v1/messages/history", get(message_history))
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
        // Handlers
        .route("/v1/handlers", get(list_handlers).post(add_handler))
        .route("/v1/handlers/reload", post(reload_handlers))
        .route("/v1/handlers/stop", post(stop_handler))
        .route(
            "/v1/handlers/{name}",
            axum::routing::delete(remove_handler).put(update_handler),
        )
}

/// A2A routes accessible from any connection.
fn a2a_routes(state: ApiState) -> Router {
    let a2a_rpc = Router::new()
        .route("/a2a", post(crate::a2a::handlers::jsonrpc_handler))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::a2a::handlers::auth_middleware,
        ));

    Router::new()
        .route(
            "/.well-known/agent-card.json",
            get(crate::a2a::handlers::agent_card_handler),
        )
        .merge(a2a_rpc)
        .with_state(state)
}

/// Header read timeout for HTTP connections. Prevents slowloris attacks
/// where an attacker sends partial headers to hold connections open.
const HTTP_HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Serve a single HTTP connection through the API router.
/// Uses HTTP/1.1 only to prevent HTTP/2 multiplexing from bypassing
/// the connection-level rate limiter.
pub async fn serve_connection(app: Router, tcp: tokio::net::TcpStream) {
    let io = hyper_util::rt::TokioIo::new(tcp);
    let service = hyper::service::service_fn(move |req| {
        let mut app = app.clone();
        async move {
            use tower::Service;
            app.call(req).await
        }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HTTP_HEADER_READ_TIMEOUT)
        .serve_connection(io, service)
        .await;
}
