use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::constants::MAX_PENDING_APPROVALS;
use crate::crypto::PublicKey;

/// Connection mode.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConnectionMode {
    Open,
    Allowlist,
    #[default]
    Approval,
    DnsVerified,
}

/// Policy decision for an incoming connection.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Accept the connection immediately.
    Accept,
    /// Hold the connection pending owner approval.
    PendingApproval,
    /// Reject the connection silently.
    Reject,
}

/// Manages connection policy: blocklist, allowlist, approvals.
pub struct PolicyEngine {
    mode: ConnectionMode,
    blocklist: HashSet<Vec<u8>>,
    allowlist: HashSet<Vec<u8>>,
    approved: HashSet<Vec<u8>>,
    pending: HashMap<Vec<u8>, Instant>,
}

impl PolicyEngine {
    pub fn new(mode: ConnectionMode) -> Self {
        Self {
            mode,
            blocklist: HashSet::new(),
            allowlist: HashSet::new(),
            approved: HashSet::new(),
            pending: HashMap::new(),
        }
    }

    /// Check whether an incoming connection should be accepted, held, or rejected.
    pub fn check(&self, key: &PublicKey) -> PolicyDecision {
        let key_bytes = key.as_bytes().to_vec();

        // Blocking takes precedence over everything.
        if self.blocklist.contains(&key_bytes) {
            return PolicyDecision::Reject;
        }

        match self.mode {
            ConnectionMode::Open => PolicyDecision::Accept,
            ConnectionMode::Allowlist => {
                if self.allowlist.contains(&key_bytes) {
                    PolicyDecision::Accept
                } else {
                    PolicyDecision::Reject
                }
            }
            ConnectionMode::Approval => {
                if self.approved.contains(&key_bytes) {
                    PolicyDecision::Accept
                } else if self.pending.len() >= MAX_PENDING_APPROVALS {
                    PolicyDecision::Reject
                } else {
                    PolicyDecision::PendingApproval
                }
            }
            ConnectionMode::DnsVerified => {
                // DNS verification is handled externally. Reject by default here.
                PolicyDecision::Reject
            }
        }
    }

    pub fn block(&mut self, key: &PublicKey) {
        self.blocklist.insert(key.as_bytes().to_vec());
        // Also remove from allowlist and approved if present.
        let kb = key.as_bytes().to_vec();
        self.allowlist.remove(&kb);
        self.approved.remove(&kb);
    }

    pub fn unblock(&mut self, key: &PublicKey) {
        self.blocklist.remove(key.as_bytes().as_slice());
    }

    pub fn is_blocked(&self, key: &PublicKey) -> bool {
        self.blocklist.contains(key.as_bytes().as_slice())
    }

    pub fn allow(&mut self, key: &PublicKey) {
        self.allowlist.insert(key.as_bytes().to_vec());
    }

    pub fn approve(&mut self, key: &PublicKey) {
        let kb = key.as_bytes().to_vec();
        self.pending.remove(&kb);
        self.approved.insert(kb);
    }

    pub fn deny(&mut self, key: &PublicKey) {
        self.pending.remove(key.as_bytes().as_slice());
    }

    pub fn add_pending(&mut self, key: &PublicKey) {
        self.pending.insert(key.as_bytes().to_vec(), Instant::now());
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn mode(&self) -> &ConnectionMode {
        &self.mode
    }
}
