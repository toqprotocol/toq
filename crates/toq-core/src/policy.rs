use std::collections::HashMap;

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

/// A permission rule that can match by public key or address pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionRule {
    /// Match by exact public key bytes.
    Key(Vec<u8>),
    /// Match by exact or wildcarded address (e.g. `toq://host/name`, `toq://*/name`, `toq://*`).
    Address(String),
}

impl PermissionRule {
    /// Check whether this rule matches the given key and address.
    pub fn matches(&self, key: &PublicKey, address: &str) -> bool {
        match self {
            PermissionRule::Key(k) => k == key.as_bytes(),
            PermissionRule::Address(pattern) => address_matches(pattern, address),
        }
    }
}

/// Match a toq address against a pattern with `*` wildcards.
///
/// Supported patterns:
/// - `toq://*` matches everything
/// - `toq://host/*` matches any agent on that host
/// - `toq://*/name` matches that agent name on any host
/// - `toq://host/name` exact match
fn address_matches(pattern: &str, address: &str) -> bool {
    let pat = pattern.strip_prefix("toq://").unwrap_or(pattern);
    let addr = address.strip_prefix("toq://").unwrap_or(address);

    // `toq://*` or just `*` matches everything
    if pat == "*" {
        return true;
    }

    let (pat_host, pat_name) = match pat.split_once('/') {
        Some((h, n)) => (h, n),
        None => (pat, "*"),
    };
    let (addr_host, addr_name) = match addr.split_once('/') {
        Some((h, n)) => (h, n),
        None => return false,
    };

    let host_ok = pat_host == "*" || pat_host == addr_host;
    let name_ok = pat_name == "*" || pat_name == addr_name;
    host_ok && name_ok
}

/// Info about a pending approval request, returned by `list_pending`.
pub struct PendingApproval {
    pub public_key: Vec<u8>,
    pub address: String,
    pub requested_at: String,
}

/// Manages connection policy: blocked rules, approved rules, pending approvals.
pub struct PolicyEngine {
    mode: ConnectionMode,
    blocked: Vec<PermissionRule>,
    approved: Vec<PermissionRule>,
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
            blocked: Vec::new(),
            approved: Vec::new(),
            pending: HashMap::new(),
        }
    }

    /// Populate policy state from the persisted peer store.
    /// Blocked peers become key-based block rules. Approved peers become
    /// key-based approve rules. Pending peers are restored into the pending queue.
    pub fn load_from_peer_store(&mut self, store: &PeerStore) {
        for (key_str, record) in &store.peers {
            let Ok(pk) = PublicKey::from_encoded(key_str) else {
                continue;
            };
            let kb = pk.as_bytes().to_vec();
            match record.status {
                PeerStatus::Blocked => {
                    let rule = PermissionRule::Key(kb);
                    if !self.blocked.contains(&rule) {
                        self.blocked.push(rule);
                    }
                }
                PeerStatus::Approved => {
                    let rule = PermissionRule::Key(kb);
                    if !self.approved.contains(&rule) {
                        self.approved.push(rule);
                    }
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
    pub fn check(&self, key: &PublicKey, address: &str) -> PolicyDecision {
        // Block rules take precedence over everything.
        if self.blocked.iter().any(|r| r.matches(key, address)) {
            return PolicyDecision::Reject;
        }

        // Approve rules override connection mode.
        if self.approved.iter().any(|r| r.matches(key, address)) {
            return PolicyDecision::Accept;
        }

        match self.mode {
            ConnectionMode::Open => PolicyDecision::Accept,
            ConnectionMode::Allowlist => PolicyDecision::Reject,
            ConnectionMode::Approval => {
                if self.pending.len() >= MAX_PENDING_APPROVALS {
                    PolicyDecision::Reject
                } else {
                    PolicyDecision::PendingApproval
                }
            }
            ConnectionMode::DnsVerified => PolicyDecision::Reject,
        }
    }

    /// Add a block rule. If the target was approved, remove the matching approve rule.
    pub fn block(&mut self, rule: PermissionRule) {
        // Remove matching approve rules for key-based blocks.
        if let PermissionRule::Key(ref kb) = rule {
            self.approved.retain(|r| {
                if let PermissionRule::Key(ak) = r {
                    ak != kb
                } else {
                    true
                }
            });
        }
        if !self.blocked.contains(&rule) {
            self.blocked.push(rule);
        }
    }

    /// Remove a block rule.
    pub fn unblock(&mut self, rule: &PermissionRule) {
        self.blocked.retain(|r| r != rule);
    }

    /// Check if a key matches any block rule.
    pub fn is_blocked(&self, key: &PublicKey) -> bool {
        // Check key-based block rules (address not available here).
        self.blocked.iter().any(|r| match r {
            PermissionRule::Key(k) => k == key.as_bytes(),
            PermissionRule::Address(_) => false,
        })
    }

    /// Add an approve rule (for pre-approving by key, address, or wildcard).
    pub fn approve(&mut self, rule: PermissionRule) {
        // If approving by key, also remove from pending.
        if let PermissionRule::Key(ref kb) = rule {
            self.pending.remove(kb);
        }
        if !self.approved.contains(&rule) {
            self.approved.push(rule);
        }
    }

    /// Approve a pending request by key (moves from pending to approved).
    pub fn approve_pending(&mut self, key: &PublicKey) {
        let kb = key.as_bytes().to_vec();
        self.pending.remove(&kb);
        let rule = PermissionRule::Key(kb);
        if !self.approved.contains(&rule) {
            self.approved.push(rule);
        }
    }

    /// Remove an approve rule.
    pub fn revoke(&mut self, rule: &PermissionRule) {
        self.approved.retain(|r| r != rule);
    }

    /// Deny a pending request (removes from pending without approving).
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

    /// List all approved rules.
    pub fn list_approved(&self) -> &[PermissionRule] {
        &self.approved
    }

    /// List all blocked rules.
    pub fn list_blocked(&self) -> &[PermissionRule] {
        &self.blocked
    }

    /// Write all policy state back to a peer store for persistence.
    /// Only key-based rules are persisted (address rules are in config).
    pub fn sync_to_peer_store(&self, store: &mut PeerStore) {
        for rule in &self.blocked {
            if let PermissionRule::Key(kb) = rule
                && let Some(pk) = PublicKey::from_bytes(kb)
            {
                let addr = store
                    .get(&pk)
                    .map(|r| r.address.clone())
                    .unwrap_or_default();
                store.upsert(&pk, &addr, PeerStatus::Blocked);
            }
        }
        for rule in &self.approved {
            if let PermissionRule::Key(kb) = rule
                && let Some(pk) = PublicKey::from_bytes(kb)
            {
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
