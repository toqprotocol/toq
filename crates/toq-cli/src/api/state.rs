//! Shared state for the local API server.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::{Mutex, RwLock, broadcast};

use toq_core::config::Config;
use toq_core::crypto::Keypair;
use toq_core::policy::PolicyEngine;
use toq_core::session::SessionStore;
use toq_core::types::Address;

use crate::api::types::IncomingMessage;

/// Channel capacity for incoming message broadcast.
const MESSAGE_CHANNEL_CAPACITY: usize = 256;

/// An active outbound stream connection.
pub struct ActiveStream {
    pub stream: toq_core::server::ClientTlsStream,
    pub peer_address: Address,
    pub peer_public_key: toq_core::crypto::PublicKey,
    pub sequence: u64,
    pub thread_id: Option<String>,
}

/// Shared state accessible by all API handlers.
#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Mutex<Config>>,
    pub keypair: Arc<RwLock<Keypair>>,
    pub address: Arc<Address>,
    pub active_connections: Arc<AtomicUsize>,
    pub total_messages: Arc<AtomicUsize>,
    pub error_count: Arc<AtomicUsize>,
    pub shutdown_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    pub message_tx: broadcast::Sender<IncomingMessage>,
    pub policy: Arc<Mutex<PolicyEngine>>,
    pub sessions: Arc<Mutex<SessionStore>>,
    pub active_streams: Arc<Mutex<std::collections::HashMap<String, ActiveStream>>>,
}

impl ApiState {
    pub fn new(
        config: Config,
        keypair: Keypair,
        address: Address,
        active_connections: Arc<AtomicUsize>,
        total_messages: Arc<AtomicUsize>,
        error_count: Arc<AtomicUsize>,
        policy: Arc<Mutex<PolicyEngine>>,
        sessions: Arc<Mutex<SessionStore>>,
    ) -> Self {
        let (message_tx, _) = broadcast::channel(MESSAGE_CHANNEL_CAPACITY);
        Self {
            config: Arc::new(Mutex::new(config)),
            keypair: Arc::new(RwLock::new(keypair)),
            address: Arc::new(address),
            active_connections,
            total_messages,
            error_count,
            shutdown_tx: Arc::new(Mutex::new(None)),
            message_tx,
            policy,
            sessions,
            active_streams: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}
