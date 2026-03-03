//! Request and response types for the local API.

use serde::{Deserialize, Serialize};

// ── Status ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: &'static str,
    pub address: String,
    pub connection_mode: String,
    pub active_connections: usize,
    pub total_messages: usize,
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

// ── Keys ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct KeyRotationResponse {
    pub old_public_key: String,
    pub new_public_key: String,
    pub rotation_proof: String,
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
pub const ERR_INVALID_CONFIG: &str = "invalid_config";

// ── Shutdown ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ShutdownRequest {
    #[serde(default = "default_graceful")]
    pub graceful: bool,
}

fn default_graceful() -> bool {
    true
}
