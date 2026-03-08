use std::collections::{HashMap, HashSet};

use crate::constants::MAX_PENDING_APPROVALS;
use crate::crypto::PublicKey;
use crate::keystore::{PeerStatus, PeerStore};

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

/// Info about a pending approval request, returned by `list_pending`.
pub struct PendingApproval {
    pub public_key: Vec<u8>,
    pub address: String,
    pub requested_at: String,
}

/// Manages connection policy: blocklist, allowed peers, approvals.
pub struct PolicyEngine {
    mode: ConnectionMode,
    blocklist: HashSet<Vec<u8>>,
    allowed: HashSet<Vec<u8>>,
    pending: HashMap<Vec<u8>, PendingInfo>,
}

struct PendingInfo {
    address: String,
    requested_at: String,
}

impl PolicyEngine {
    pub fn new(mode: ConnectionMode) -> Self {
        Self {
            mode,
            blocklist: HashSet::new(),
            allowed: HashSet::new(),
            pending: HashMap::new(),
        }
    }

    /// Populate policy state from the persisted peer store.
    /// Blocked peers go into the blocklist. Approved peers go into the
    /// allowed set. Pending peers are restored into the pending queue.
    pub fn load_from_peer_store(&mut self, store: &PeerStore) {
        for (key_str, record) in &store.peers {
            let Ok(pk) = PublicKey::from_encoded(key_str) else {
                continue;
            };
            let kb = pk.as_bytes().to_vec();
            match record.status {
                PeerStatus::Blocked => {
                    self.blocklist.insert(kb);
                }
                PeerStatus::Approved => {
                    self.allowed.insert(kb);
                }
                PeerStatus::Pending => {
                    self.pending.insert(
                        kb,
                        PendingInfo {
                            address: record.address.clone(),
                            requested_at: record.first_seen.clone(),
                        },
                    );
                }
            }
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
                if self.allowed.contains(&key_bytes) {
                    PolicyDecision::Accept
                } else {
                    PolicyDecision::Reject
                }
            }
            ConnectionMode::Approval => {
                if self.allowed.contains(&key_bytes) {
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
        let kb = key.as_bytes().to_vec();
        self.blocklist.insert(kb.clone());
        self.allowed.remove(&kb);
    }

    pub fn unblock(&mut self, key: &PublicKey) {
        self.blocklist.remove(key.as_bytes().as_slice());
    }

    pub fn is_blocked(&self, key: &PublicKey) -> bool {
        self.blocklist.contains(key.as_bytes().as_slice())
    }

    pub fn allow(&mut self, key: &PublicKey) {
        self.allowed.insert(key.as_bytes().to_vec());
    }

    pub fn approve(&mut self, key: &PublicKey) {
        let kb = key.as_bytes().to_vec();
        self.pending.remove(&kb);
        self.allowed.insert(kb);
    }

    pub fn revoke(&mut self, key: &PublicKey) {
        let kb = key.as_bytes().to_vec();
        self.allowed.remove(&kb);
    }

    pub fn deny(&mut self, key: &PublicKey) {
        self.pending.remove(key.as_bytes().as_slice());
    }

    pub fn add_pending(&mut self, key: &PublicKey, address: &str) {
        self.pending.insert(
            key.as_bytes().to_vec(),
            PendingInfo {
                address: address.to_string(),
                requested_at: crate::now_utc(),
            },
        );
    }

    pub fn list_pending(&self) -> Vec<PendingApproval> {
        self.pending
            .iter()
            .map(|(key, info)| PendingApproval {
                public_key: key.clone(),
                address: info.address.clone(),
                requested_at: info.requested_at.clone(),
            })
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Write all policy state back to a peer store for persistence.
    pub fn sync_to_peer_store(&self, store: &mut PeerStore) {
        for kb in &self.blocklist {
            if let Some(pk) = PublicKey::from_bytes(kb) {
                let addr = store
                    .get(&pk)
                    .map(|r| r.address.clone())
                    .unwrap_or_default();
                store.upsert(&pk, &addr, PeerStatus::Blocked);
            }
        }
        for kb in &self.allowed {
            if let Some(pk) = PublicKey::from_bytes(kb) {
                let addr = store
                    .get(&pk)
                    .map(|r| r.address.clone())
                    .unwrap_or_default();
                store.upsert(&pk, &addr, PeerStatus::Approved);
            }
        }
        for (kb, info) in &self.pending {
            if let Some(pk) = PublicKey::from_bytes(kb) {
                store.upsert(&pk, &info.address, PeerStatus::Pending);
            }
        }
    }

    pub fn mode(&self) -> &ConnectionMode {
        &self.mode
    }
}
