use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

use crate::constants::{ACK_TIMEOUT, DEDUP_WINDOW, MAX_RETRIES, RETRY_DELAYS};

/// Tracks outbound messages awaiting acks and manages retry scheduling.
pub struct DeliveryTracker {
    pending: HashMap<Uuid, PendingMessage>,
}

struct PendingMessage {
    sent_at: Instant,
    retries: usize,
}

impl DeliveryTracker {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Record that a message was sent and is awaiting an ack.
    pub fn track(&mut self, id: Uuid) {
        self.pending.insert(
            id,
            PendingMessage {
                sent_at: Instant::now(),
                retries: 0,
            },
        );
    }

    /// Record that an ack was received. Returns true if the message was pending.
    pub fn ack(&mut self, id: &Uuid) -> bool {
        self.pending.remove(id).is_some()
    }

    /// Return message IDs that need retry (ack timeout exceeded).
    pub fn needs_retry(&mut self) -> Vec<Uuid> {
        let now = Instant::now();
        let mut retries = Vec::new();

        for (id, msg) in &self.pending {
            let timeout = if msg.retries == 0 {
                ACK_TIMEOUT
            } else {
                RETRY_DELAYS[msg.retries.min(RETRY_DELAYS.len()) - 1]
            };
            if now.duration_since(msg.sent_at) >= timeout {
                retries.push(*id);
            }
        }
        retries
    }

    /// Mark a message as retried. Returns false if max retries exceeded (undeliverable).
    pub fn record_retry(&mut self, id: &Uuid) -> bool {
        if let Some(msg) = self.pending.get_mut(id) {
            msg.retries += 1;
            msg.sent_at = Instant::now();
            msg.retries <= MAX_RETRIES
        } else {
            false
        }
    }

    /// Remove and return IDs of messages that exceeded max retries.
    pub fn drain_undeliverable(&mut self) -> Vec<Uuid> {
        let failed: Vec<Uuid> = self
            .pending
            .iter()
            .filter(|(_, msg)| msg.retries > MAX_RETRIES)
            .map(|(id, _)| *id)
            .collect();
        for id in &failed {
            self.pending.remove(id);
        }
        failed
    }
}

impl Default for DeliveryTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks recently seen message IDs for deduplication.
pub struct DedupSet {
    seen: HashMap<Uuid, Instant>,
}

impl DedupSet {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// Check if a message ID is a duplicate. Returns true if already seen.
    /// If not seen, records it and returns false.
    pub fn is_duplicate(&mut self, id: &Uuid) -> bool {
        self.evict();
        if self.seen.contains_key(id) {
            return true;
        }
        self.seen.insert(*id, Instant::now());
        false
    }

    /// Remove entries older than the dedup window.
    fn evict(&mut self) {
        let cutoff = Instant::now() - DEDUP_WINDOW;
        self.seen.retain(|_, ts| *ts > cutoff);
    }
}

impl Default for DedupSet {
    fn default() -> Self {
        Self::new()
    }
}
