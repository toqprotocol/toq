//! Request and response types for the local API.

use serde::{Deserialize, Serialize};

// ── Messages ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Recipient {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub to: Recipient,
    pub body: Option<serde_json::Value>,
    pub thread_id: Option<String>,
    pub reply_to: Option<String>,
    pub content_type: Option<String>,
    #[serde(default)]
    pub close_thread: bool,
}

impl Recipient {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Recipient::Single(s) => vec![s],
            Recipient::Multiple(v) => v,
        }
    }

    pub fn is_single(&self) -> bool {
        matches!(self, Recipient::Single(_))
    }
}

#[derive(Debug, Serialize)]
pub struct SendMessageResponse {
    pub id: String,
    pub status: &'static str,
    pub thread_id: String,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct MultiSendResult {
    pub to: String,
    pub id: String,
    pub thread_id: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MultiSendResponse {
    pub results: Vec<MultiSendResult>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingMessage {
    pub id: String,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub timestamp: String,
}

// ── Threads ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ThreadResponse {
    pub thread_id: String,
    pub messages: Vec<IncomingMessage>,
}

// ── Status ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: &'static str,
    pub address: String,
    pub connection_mode: String,
    pub active_connections: usize,
    pub messages_in: usize,
    pub messages_out: usize,
    pub error_count: usize,
    pub backpressure_active: bool,
    pub version: &'static str,
    pub public_key: String,
}

// ── Peers ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PeerEntry {
    pub public_key: String,
    pub address: String,
    pub status: String,
    pub last_seen: String,
}

#[derive(Debug, Serialize)]
pub struct PeersResponse {
    pub peers: Vec<PeerEntry>,
}

// ── Discovery ───────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DiscoveredAgent {
    pub address: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct DiscoverResponse {
    pub agents: Vec<DiscoveredAgent>,
}

// ── Approvals ───────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ApprovalEntry {
    pub id: String,
    pub public_key: String,
    pub address: String,
    pub requested_at: String,
}

#[derive(Debug, Serialize)]
pub struct ApprovalsResponse {
    pub approvals: Vec<ApprovalEntry>,
}

// ── Connections ─────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ConnectionEntry {
    pub session_id: String,
    pub peer_address: String,
    pub peer_public_key: String,
    pub connected_at: String,
    pub messages_exchanged: u64,
}

#[derive(Debug, Serialize)]
pub struct ConnectionsResponse {
    pub connections: Vec<ConnectionEntry>,
}

// ── Config ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub config: serde_json::Value,
}

// ── Agent Card ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AgentCardResponse {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub public_key: String,
    pub protocol_version: String,
    pub capabilities: Vec<String>,
    pub accept_files: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_message_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_mode: Option<String>,
}

// ── Logs ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct LogsResponse {
    pub entries: Vec<LogEntry>,
}

// ── Diagnostics ─────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DiagnosticCheck {
    pub name: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiagnosticsResponse {
    pub checks: Vec<DiagnosticCheck>,
    pub issues: usize,
}

#[derive(Debug, Serialize)]
pub struct UpgradeCheckResponse {
    pub current_version: &'static str,
    pub up_to_date: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
}

// ── Keys ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct KeyRotationResponse {
    pub old_public_key: String,
    pub new_public_key: String,
    pub rotation_proof: String,
}

// ── Backup ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BackupExportRequest {
    pub passphrase: String,
}

#[derive(Debug, Serialize)]
pub struct BackupExportResponse {
    pub data: String,
}

#[derive(Debug, Deserialize)]
pub struct BackupImportRequest {
    pub passphrase: String,
    pub data: String,
}

// ── Shutdown ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ShutdownRequest {
    #[serde(default = "default_graceful")]
    pub graceful: bool,
}

fn default_graceful() -> bool {
    true
}

// ── Error ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: ApiErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub code: &'static str,
    pub message: String,
}

pub const ERR_INVALID_REQUEST: &str = "invalid_request";
pub const ERR_INVALID_ADDRESS: &str = "invalid_address";
pub const ERR_NOT_FOUND: &str = "not_found";
pub const ERR_NOT_REACHABLE: &str = "not_reachable";
pub const ERR_DELIVERY_TIMEOUT: &str = "delivery_timeout";
pub const ERR_MESSAGE_TOO_LARGE: &str = "message_too_large";
pub const ERR_INVALID_CONFIG: &str = "invalid_config";
pub const ERR_INVALID_PASSPHRASE: &str = "invalid_passphrase";

pub const STATUS_QUEUED: &str = "queued";
pub const STATUS_DELIVERED: &str = "delivered";
pub const STATUS_FAILED: &str = "failed";

// ── History ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<usize>,
    pub from: Option<String>,
    pub since: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HistoryResponse {
    pub messages: Vec<IncomingMessage>,
}

// ── Streaming ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StreamStartRequest {
    pub to: String,
    pub thread_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StreamStartResponse {
    pub stream_id: String,
    pub thread_id: String,
}

#[derive(Debug, Deserialize)]
pub struct StreamChunkRequest {
    pub stream_id: String,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct StreamChunkResponse {
    pub chunk_id: String,
}

#[derive(Debug, Deserialize)]
pub struct StreamEndRequest {
    pub stream_id: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub close_thread: bool,
}

/// GitHub releases API URL for upgrade checks.
pub const RELEASES_API_URL: &str = "https://api.github.com/repos/toqprotocol/toq/releases/latest";
pub const RELEASES_FALLBACK_URL: &str = "https://github.com/toqprotocol/toq/releases";
