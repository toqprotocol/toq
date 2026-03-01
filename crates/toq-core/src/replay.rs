/// Per-connection sequence counter for replay prevention.
/// Rejects any envelope with a sequence number <= the highest seen.
pub struct SequenceTracker {
    highest_seen: Option<u64>,
}

impl SequenceTracker {
    pub fn new() -> Self {
        Self { highest_seen: None }
    }

    /// Check and record a sequence number. Returns true if valid (strictly increasing).
    pub fn check(&mut self, sequence: u64) -> bool {
        match self.highest_seen {
            Some(prev) if sequence <= prev => false,
            _ => {
                self.highest_seen = Some(sequence);
                true
            }
        }
    }

    /// Reset to a specific value (used during session resume).
    pub fn reset(&mut self, last_acknowledged: u64) {
        self.highest_seen = Some(last_acknowledged);
    }

    pub fn highest(&self) -> Option<u64> {
        self.highest_seen
    }
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}
