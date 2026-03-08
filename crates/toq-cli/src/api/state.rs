//! Shared state for the local API server.

use std::collections::VecDeque;
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

/// Default max messages kept in history.
const DEFAULT_HISTORY_LIMIT: usize = 1000;

/// Path to the message history file.
pub fn history_path() -> std::path::PathBuf {
    crate::dirs_path().join("messages.jsonl")
}

/// Ring buffer of recent messages with JSONL persistence.
pub struct MessageHistory {
    messages: VecDeque<IncomingMessage>,
    limit: usize,
}

impl MessageHistory {
    pub fn new(limit: usize) -> Self {
        Self {
            messages: VecDeque::with_capacity(limit),
            limit,
        }
    }

    /// Load recent messages from the JSONL file on startup.
    pub fn load_from_file(limit: usize) -> Self {
        let mut history = Self::new(limit);
        let path = history_path();
        if let Ok(contents) = std::fs::read_to_string(&path) {
            for line in contents.lines().rev().take(limit) {
                if let Ok(msg) = serde_json::from_str::<IncomingMessage>(line) {
                    history.messages.push_front(msg);
                }
            }
        }
        history
    }

    /// Store a message (in memory + append to file).
    pub fn push(&mut self, msg: &IncomingMessage) {
        if self.messages.len() >= self.limit {
            self.messages.pop_front();
        }
        self.messages.push_back(msg.clone());
        // Append to JSONL file (best-effort)
        if let Ok(line) = serde_json::to_string(msg) {
            let path = history_path();
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .and_then(|mut f| {
                    use std::io::Write;
                    writeln!(f, "{line}")
                });
        }
    }

    /// Query messages with optional filters.
    pub fn query(
        &self,
        limit: usize,
        from: Option<&str>,
        since: Option<&str>,
    ) -> Vec<IncomingMessage> {
        self.messages
            .iter()
            .rev()
            .filter(|m| {
                if let Some(f) = from
                    && !m.from.contains(f)
                {
                    return false;
                }
                if let Some(s) = since
                    && m.timestamp.as_str() < s
                {
                    return false;
                }
                true
            })
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }
}

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
    pub messages_in: Arc<AtomicUsize>,
    pub messages_out: Arc<AtomicUsize>,
    pub error_count: Arc<AtomicUsize>,
    pub shutdown_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    pub message_tx: broadcast::Sender<IncomingMessage>,
    pub policy: Arc<Mutex<PolicyEngine>>,
    pub sessions: Arc<Mutex<SessionStore>>,
    pub active_streams: Arc<Mutex<std::collections::HashMap<String, ActiveStream>>>,
    pub history: Arc<Mutex<MessageHistory>>,
}

/// Parameters for constructing [`ApiState`].
pub struct ApiStateParams {
    pub config: Config,
    pub keypair: Keypair,
    pub address: Address,
    pub active_connections: Arc<AtomicUsize>,
    pub messages_in: Arc<AtomicUsize>,
    pub messages_out: Arc<AtomicUsize>,
    pub error_count: Arc<AtomicUsize>,
    pub policy: Arc<Mutex<PolicyEngine>>,
    pub sessions: Arc<Mutex<SessionStore>>,
}

impl ApiState {
    pub fn new(p: ApiStateParams) -> Self {
        let (message_tx, _) = broadcast::channel(MESSAGE_CHANNEL_CAPACITY);
        let limit = p
            .config
            .message_history_limit
            .unwrap_or(DEFAULT_HISTORY_LIMIT);
        let history = MessageHistory::load_from_file(limit);
        Self {
            config: Arc::new(Mutex::new(p.config)),
            keypair: Arc::new(RwLock::new(p.keypair)),
            address: Arc::new(p.address),
            active_connections: p.active_connections,
            messages_in: p.messages_in,
            messages_out: p.messages_out,
            error_count: p.error_count,
            shutdown_tx: Arc::new(Mutex::new(None)),
            message_tx,
            policy: p.policy,
            sessions: p.sessions,
            active_streams: Arc::new(Mutex::new(std::collections::HashMap::new())),
            history: Arc::new(Mutex::new(history)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::IncomingMessage;

    fn make_msg(from: &str, text: &str, ts: &str) -> IncomingMessage {
        IncomingMessage {
            id: uuid::Uuid::new_v4().to_string(),
            msg_type: "message.send".into(),
            from: from.into(),
            body: Some(serde_json::json!({"text": text})),
            thread_id: None,
            reply_to: None,
            content_type: None,
            timestamp: ts.into(),
        }
    }

    #[test]
    fn history_push_and_query() {
        let mut h = MessageHistory::new(10);
        h.push(&make_msg(
            "toq://host/alice",
            "hello",
            "2026-03-08T01:00:00Z",
        ));
        h.push(&make_msg("toq://host/bob", "world", "2026-03-08T02:00:00Z"));
        let msgs = h.query(10, None, None);
        assert_eq!(msgs.len(), 2);
        assert!(msgs[0].from.contains("alice"));
        assert!(msgs[1].from.contains("bob"));
    }

    #[test]
    fn history_respects_limit() {
        let mut h = MessageHistory::new(5);
        for i in 0..10 {
            h.push(&make_msg(
                "toq://host/alice",
                &format!("msg {i}"),
                "2026-03-08T01:00:00Z",
            ));
        }
        // Ring buffer should only keep last 5
        assert_eq!(h.query(100, None, None).len(), 5);
    }

    #[test]
    fn history_filter_by_from() {
        let mut h = MessageHistory::new(10);
        h.push(&make_msg(
            "toq://host/alice",
            "from alice",
            "2026-03-08T01:00:00Z",
        ));
        h.push(&make_msg(
            "toq://host/bob",
            "from bob",
            "2026-03-08T02:00:00Z",
        ));
        h.push(&make_msg(
            "toq://host/alice",
            "alice again",
            "2026-03-08T03:00:00Z",
        ));
        let msgs = h.query(10, Some("alice"), None);
        assert_eq!(msgs.len(), 2);
        assert!(msgs.iter().all(|m| m.from.contains("alice")));
    }

    #[test]
    fn history_filter_by_since() {
        let mut h = MessageHistory::new(10);
        h.push(&make_msg("toq://host/alice", "old", "2026-03-08T01:00:00Z"));
        h.push(&make_msg("toq://host/alice", "new", "2026-03-08T03:00:00Z"));
        let msgs = h.query(10, None, Some("2026-03-08T02:00:00Z"));
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].body.as_ref().unwrap().to_string().contains("new"));
    }

    #[test]
    fn history_query_limit() {
        let mut h = MessageHistory::new(10);
        for i in 0..5 {
            h.push(&make_msg(
                "toq://host/alice",
                &format!("msg {i}"),
                "2026-03-08T01:00:00Z",
            ));
        }
        let msgs = h.query(2, None, None);
        assert_eq!(msgs.len(), 2);
    }
}
