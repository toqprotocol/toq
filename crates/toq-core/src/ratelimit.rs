use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Simple sliding-window rate limiter per IP address.
pub struct RateLimiter {
    max_per_second: usize,
    windows: HashMap<IpAddr, Vec<Instant>>,
}

impl RateLimiter {
    pub fn new(max_per_second: usize) -> Self {
        Self {
            max_per_second,
            windows: HashMap::new(),
        }
    }

    /// Check if a request from this IP is allowed. Returns true if under the limit.
    pub fn check(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = self.windows.entry(ip).or_default();

        // Remove entries older than 1 second.
        window.retain(|t| now.duration_since(*t).as_secs() < 1);

        if window.len() >= self.max_per_second {
            return false;
        }
        window.push(now);
        true
    }

    /// Clear all tracked state.
    pub fn clear(&mut self) {
        self.windows.clear();
    }
}
