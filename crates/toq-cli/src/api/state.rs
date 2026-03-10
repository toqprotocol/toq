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

/// Path to handler log directory.
pub fn handler_log_dir() -> std::path::PathBuf {
    crate::dirs_path()
        .join(toq_core::constants::LOGS_DIR)
        .join(toq_core::constants::HANDLER_LOGS_DIR)
}

/// Tracks a running handler process.
struct ActiveProcess {
    pid: std::sync::Arc<std::sync::atomic::AtomicU32>,
    abort: tokio::task::AbortHandle,
}

/// Manages handler dispatch, process tracking, and logging.
pub struct HandlerManager {
    handlers: toq_core::config::HandlersFile,
    active: std::collections::HashMap<String, Vec<ActiveProcess>>,
}

impl HandlerManager {
    pub fn new(handlers: toq_core::config::HandlersFile) -> Self {
        let _ = std::fs::create_dir_all(handler_log_dir());
        Self {
            handlers,
            active: std::collections::HashMap::new(),
        }
    }

    pub fn handlers_file_mut(&mut self) -> &mut toq_core::config::HandlersFile {
        &mut self.handlers
    }

    /// Save current handlers to disk.
    pub fn save(&self) -> Result<(), toq_core::error::Error> {
        self.handlers.save(&toq_core::config::HandlersFile::path())
    }

    /// Dispatch a message to all matching handlers.
    pub fn dispatch(
        &mut self,
        msg: &IncomingMessage,
        from_key: Option<&toq_core::crypto::PublicKey>,
    ) {
        let matching: Vec<toq_core::config::HandlerEntry> = self
            .handlers
            .handlers
            .iter()
            .filter(|h| toq_core::handler::matches_handler(h, &msg.from, from_key, &msg.msg_type))
            .cloned()
            .collect();

        for handler in matching {
            self.spawn_handler(&handler, msg);
        }
    }

    fn spawn_handler(&mut self, handler: &toq_core::config::HandlerEntry, msg: &IncomingMessage) {
        let json = match serde_json::to_string(msg) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("handler {}: failed to serialize message: {e}", handler.name);
                return;
            }
        };

        let name = handler.name.clone();
        let command = handler.command.clone();
        let from = msg.from.clone();
        let text = msg
            .body
            .as_ref()
            .and_then(|b| b.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let thread_id = msg.thread_id.clone().unwrap_or_default();
        let msg_type = msg.msg_type.clone();
        let msg_id = msg.id.clone();
        let log_dir = handler_log_dir();

        // Shared slot for the child PID so the outer scope can read it.
        let child_pid = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let child_pid_inner = child_pid.clone();

        let task = tokio::spawn(async move {
            let mut child = match tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&command)
                .env("TOQ_FROM", &from)
                .env("TOQ_TEXT", &text)
                .env("TOQ_THREAD_ID", &thread_id)
                .env("TOQ_TYPE", &msg_type)
                .env("TOQ_ID", &msg_id)
                .env("TOQ_HANDLER", &name)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("handler {name}: failed to spawn: {e}");
                    return;
                }
            };

            // Record child PID for tracking
            let pid = child.id().unwrap_or(0);
            child_pid_inner.store(pid, std::sync::atomic::Ordering::Relaxed);

            // Write message JSON to stdin
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                let _ = stdin.write_all(json.as_bytes()).await;
                drop(stdin);
            }

            let output = match child.wait_with_output().await {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!("handler {name}: wait failed: {e}");
                    return;
                }
            };

            // Log output to handler-specific log file
            let log_path = log_dir.join(format!("handler-{name}.log"));
            let ts = toq_core::now_utc();
            let mut log_lines = String::new();
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                log_lines.push_str(&format!("[{ts} pid:{pid}] {line}\n"));
            }
            for line in String::from_utf8_lossy(&output.stderr).lines() {
                log_lines.push_str(&format!("[{ts} pid:{pid}:stderr] {line}\n"));
            }
            if !output.status.success() {
                log_lines.push_str(&format!(
                    "[{ts} pid:{pid}] exited with status {}\n",
                    output.status
                ));
            }
            if !log_lines.is_empty() {
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)
                    .and_then(|mut f| {
                        use std::io::Write;
                        f.write_all(log_lines.as_bytes())
                    });
            }
        });

        let abort = task.abort_handle();
        self.active
            .entry(handler.name.clone())
            .or_default()
            .push(ActiveProcess {
                pid: child_pid,
                abort,
            });
    }

    /// Clean up finished processes from tracking.
    pub fn reap(&mut self) {
        for procs in self.active.values_mut() {
            procs.retain(|p| !p.abort.is_finished());
        }
        self.active.retain(|_, v| !v.is_empty());
    }

    /// Stop all active processes for a handler.
    pub fn stop(&mut self, name: &str) -> usize {
        if let Some(procs) = self.active.remove(name) {
            let count = procs.len();
            for p in procs {
                p.abort.abort();
            }
            count
        } else {
            0
        }
    }

    /// Stop a specific process by PID.
    pub fn stop_pid(&mut self, name: &str, pid: u32) -> bool {
        if let Some(procs) = self.active.get_mut(name)
            && let Some(idx) = procs
                .iter()
                .position(|p| p.pid.load(std::sync::atomic::Ordering::Relaxed) == pid)
        {
            let p = procs.remove(idx);
            p.abort.abort();
            return true;
        }
        false
    }

    /// List all handlers with active process counts.
    pub fn list(&mut self) -> Vec<HandlerStatus> {
        self.reap();
        self.handlers
            .handlers
            .iter()
            .map(|h| HandlerStatus {
                name: h.name.clone(),
                command: h.command.clone(),
                enabled: h.enabled,
                active: self.active.get(&h.name).map_or(0, |v| v.len()),
                filter_from: h.filter_from.clone(),
                filter_key: h.filter_key.clone(),
                filter_type: h.filter_type.clone(),
            })
            .collect()
    }
}

/// Handler info for listing.
pub struct HandlerStatus {
    pub name: String,
    pub command: String,
    pub enabled: bool,
    pub active: usize,
    pub filter_from: Vec<String>,
    pub filter_key: Vec<String>,
    pub filter_type: Vec<String>,
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
    pub handler_manager: Arc<Mutex<HandlerManager>>,
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
        let handlers =
            toq_core::config::HandlersFile::load(&toq_core::config::HandlersFile::path())
                .unwrap_or_default();
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
            handler_manager: Arc::new(Mutex::new(HandlerManager::new(handlers))),
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
