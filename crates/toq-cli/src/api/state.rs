//! Shared state for the local API server.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::Mutex;

use toq_core::config::Config;
use toq_core::crypto::Keypair;
use toq_core::types::Address;

/// Shared state accessible by all API handlers.
#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Mutex<Config>>,
    pub keypair: Arc<Keypair>,
    pub address: Arc<Address>,
    pub active_connections: Arc<AtomicUsize>,
    pub total_messages: Arc<AtomicUsize>,
    pub shutdown_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}
