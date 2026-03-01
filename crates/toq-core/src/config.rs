use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::Error;

/// toq configuration, loaded from `~/.toq/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub agent_name: String,
    pub port: u16,
    pub connection_mode: String,
    pub verbosity: String,
    pub log_level: String,
    pub accept_files: bool,
    pub max_file_size: usize,
    pub max_message_size: usize,
    pub max_connections: usize,
    pub max_threads_per_connection: usize,
    pub max_message_queue: usize,
    pub max_pending_approvals: usize,
    pub handshake_timeout: u64,
    pub negotiation_timeout: u64,
    pub ack_timeout: u64,
    pub heartbeat_interval: u64,
    pub heartbeat_timeout: u64,
    pub session_resume_timeout: u64,
    pub graceful_shutdown_timeout: u64,
    pub log_retention_days: u32,
    pub log_max_size_mb: u32,
    pub thread_cleanup_days: u32,
    pub mdns_enabled: bool,
    pub adapter: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent_name: "agent".into(),
            port: 9009,
            connection_mode: "approval".into(),
            verbosity: "non-technical".into(),
            log_level: "warn".into(),
            accept_files: false,
            max_file_size: 10_485_760,
            max_message_size: 1_048_576,
            max_connections: 1000,
            max_threads_per_connection: 100,
            max_message_queue: 10000,
            max_pending_approvals: 100,
            handshake_timeout: 5,
            negotiation_timeout: 5,
            ack_timeout: 10,
            heartbeat_interval: 30,
            heartbeat_timeout: 90,
            session_resume_timeout: 300,
            graceful_shutdown_timeout: 60,
            log_retention_days: 30,
            log_max_size_mb: 500,
            thread_cleanup_days: 30,
            mdns_enabled: false,
            adapter: "http".into(),
        }
    }
}

impl Config {
    /// Default config file path: `~/.toq/config.toml`
    pub fn default_path() -> PathBuf {
        dirs_path().join("config.toml")
    }

    /// Load config from a TOML file. Returns defaults if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self, Error> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path).map_err(|e| Error::Io(e.to_string()))?;
        toml::from_str(&contents).map_err(|e| Error::Io(e.to_string()))
    }

    /// Save config to a TOML file.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
        }
        let contents = toml::to_string_pretty(self).map_err(|e| Error::Io(e.to_string()))?;
        std::fs::write(path, contents).map_err(|e| Error::Io(e.to_string()))
    }
}

/// The `~/.toq/` directory path.
pub fn dirs_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".toq")
}
