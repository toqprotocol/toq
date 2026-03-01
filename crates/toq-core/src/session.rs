use std::collections::HashMap;
use std::time::Instant;

use crate::constants::SESSION_RESUME_TIMEOUT;
use crate::crypto::PublicKey;

/// Tracks active sessions and handles duplicate connection detection.
pub struct SessionStore {
    sessions: HashMap<String, SessionRecord>,
    active_peers: HashMap<[u8; 32], ActivePeer>,
}

struct SessionRecord {
    peer_key: [u8; 32],
    created_at: Instant,
    last_sequence: u64,
}

struct ActivePeer {
    session_id: String,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            active_peers: HashMap::new(),
        }
    }

    /// Register a new active session.
    pub fn register(&mut self, session_id: &str, peer_key: &PublicKey) {
        let key_bytes = *peer_key.as_bytes();
        self.sessions.insert(
            session_id.to_string(),
            SessionRecord {
                peer_key: key_bytes,
                created_at: Instant::now(),
                last_sequence: 0,
            },
        );
        self.active_peers.insert(
            key_bytes,
            ActivePeer {
                session_id: session_id.to_string(),
            },
        );
    }

    /// Check if a session resume is valid. Returns the last sequence number if valid.
    pub fn validate_resume(&self, session_id: &str, peer_key: &PublicKey) -> Option<u64> {
        let record = self.sessions.get(session_id)?;
        if record.peer_key != *peer_key.as_bytes() {
            return None;
        }
        if record.created_at.elapsed() > SESSION_RESUME_TIMEOUT {
            return None;
        }
        Some(record.last_sequence)
    }

    /// Update the last seen sequence for a session.
    pub fn update_sequence(&mut self, session_id: &str, sequence: u64) {
        if let Some(record) = self.sessions.get_mut(session_id) {
            record.last_sequence = sequence;
        }
    }

    /// Remove a session (on graceful disconnect).
    pub fn remove(&mut self, session_id: &str) {
        if let Some(record) = self.sessions.remove(session_id) {
            self.active_peers.remove(&record.peer_key);
        }
    }

    /// Check for duplicate connection. Returns the old session ID if a duplicate exists.
    /// The caller should close the old connection and keep the new one.
    pub fn check_duplicate(&self, peer_key: &PublicKey) -> Option<String> {
        self.active_peers
            .get(peer_key.as_bytes())
            .map(|p| p.session_id.clone())
    }

    /// Expire old sessions past the resume window.
    pub fn expire(&mut self) {
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, r)| r.created_at.elapsed() > SESSION_RESUME_TIMEOUT)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.remove(&id);
        }
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
