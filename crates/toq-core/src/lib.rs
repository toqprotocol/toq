pub mod adapter;
pub mod card;
pub mod compress;
pub mod config;
pub mod connection;
pub mod constants;
pub mod crypto;
pub mod delivery;
pub mod discovery;
pub mod e2e;
pub mod envelope;
pub mod error;
pub mod error_catalog;
pub mod framing;
pub mod handler;
pub mod handshake;
pub mod keystore;
pub mod messaging;
pub mod negotiation;
pub mod policy;
pub mod ratelimit;
pub mod replay;
pub mod server;
pub mod session;
pub mod streaming;
pub mod transport;
pub mod types;

/// Generate an ISO 8601 UTC timestamp for the current time.
pub fn now_utc() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}
