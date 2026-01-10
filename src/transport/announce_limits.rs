use alloc::collections::BTreeMap;
use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use tokio::time::Duration;
use tokio::time::Instant;

use crate::hash::AddressHash;

/// Maximum number of timestamps to keep in history for rate calculation
const MAX_TIMESTAMP_HISTORY: usize = 100;

/// How long to keep timestamps in history (1 hour)
const TIMESTAMP_HISTORY_WINDOW: Duration = Duration::from_secs(3600);

pub struct AnnounceRateLimit {
    pub target: Duration,
    pub grace: u32,
    pub penalty: Option<Duration>,
}

impl Default for AnnounceRateLimit {
    fn default() -> Self {
        Self {
            target: Duration::from_secs(3600),
            grace: 10,
            penalty: Some(Duration::from_secs(7200)),
        }
    }
}

/// Rate information for external display/queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateInfo {
    /// Destination address hash (hex string)
    pub destination: String,
    /// Unix timestamp of last announce (None if never heard)
    pub last_announce: Option<f64>,
    /// History of announce timestamps (unix timestamps)
    pub timestamps: Vec<f64>,
    /// Number of rate violations
    pub violations: u32,
    /// Unix timestamp when block expires (None if not blocked)
    pub blocked_until: Option<f64>,
}

struct AnnounceLimitEntry {
    rate_limit: Option<AnnounceRateLimit>,
    violations: u32,
    last_announce: Instant,
    blocked_until: Instant,
    /// History of announce timestamps for rate calculation
    timestamp_history: VecDeque<Instant>,
    /// When this entry was created (for unix timestamp calculation)
    created_at: std::time::SystemTime,
}

impl AnnounceLimitEntry {
    pub fn new(rate_limit: Option<AnnounceRateLimit>) -> Self {
        Self {
            rate_limit,
            violations: 0,
            last_announce: Instant::now(),
            blocked_until: Instant::now(),
            timestamp_history: VecDeque::with_capacity(MAX_TIMESTAMP_HISTORY),
            created_at: std::time::SystemTime::now(),
        }
    }

    /// Record an announce and check for rate limiting
    pub fn handle_announce(&mut self) -> Option<Duration> {
        let mut is_blocked = false;
        let now = Instant::now();

        // Add to timestamp history
        self.timestamp_history.push_back(now);

        // Trim old timestamps beyond the history window
        let cutoff = now.checked_sub(TIMESTAMP_HISTORY_WINDOW).unwrap_or(now);
        while let Some(&oldest) = self.timestamp_history.front() {
            if oldest < cutoff {
                self.timestamp_history.pop_front();
            } else {
                break;
            }
        }

        // Limit history size
        while self.timestamp_history.len() > MAX_TIMESTAMP_HISTORY {
            self.timestamp_history.pop_front();
        }

        if let Some(ref rate_limit) = self.rate_limit {
            if now < self.blocked_until {
                self.blocked_until = now + rate_limit.target;
                if let Some(penalty) = rate_limit.penalty {
                    self.blocked_until += penalty;
                }
                is_blocked = true;
            } else {
                let next_allowed = self.last_announce + rate_limit.target;
                if now < next_allowed {
                    self.violations += 1;
                    if self.violations >= rate_limit.grace {
                        self.violations = 0;
                        self.blocked_until = now + rate_limit.target;
                        is_blocked = true;
                    }
                }
            }
        }

        self.last_announce = now;

        if is_blocked {
            Some(self.blocked_until - now)
        } else {
            None
        }
    }

    /// Get rate info for this entry
    pub fn get_rate_info(&self, destination: AddressHash) -> RateInfo {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let instant_now = Instant::now();

        // Convert last_announce to unix timestamp
        let last_announce_unix = if self.last_announce <= instant_now {
            let elapsed = self.last_announce.elapsed().as_secs_f64();
            Some(now - elapsed)
        } else {
            None
        };

        // Convert timestamp history to unix timestamps
        let timestamps: Vec<f64> = self
            .timestamp_history
            .iter()
            .map(|ts| {
                let elapsed = ts.elapsed().as_secs_f64();
                now - elapsed
            })
            .collect();

        // Convert blocked_until to unix timestamp if currently blocked
        let blocked_until_unix = if self.blocked_until > instant_now {
            let remaining = (self.blocked_until - instant_now).as_secs_f64();
            Some(now + remaining)
        } else {
            None
        };

        RateInfo {
            destination: format!("{}", destination),
            last_announce: last_announce_unix,
            timestamps,
            violations: self.violations,
            blocked_until: blocked_until_unix,
        }
    }

    /// Calculate announces per hour based on timestamp history
    pub fn announces_per_hour(&self) -> f64 {
        if self.timestamp_history.is_empty() {
            return 0.0;
        }

        let now = Instant::now();
        let cutoff = now.checked_sub(TIMESTAMP_HISTORY_WINDOW).unwrap_or(now);

        // Count timestamps within the last hour
        let count = self
            .timestamp_history
            .iter()
            .filter(|&&ts| ts >= cutoff)
            .count();

        // Calculate time span
        if count <= 1 {
            return count as f64;
        }

        // Get oldest and newest in range
        let relevant: Vec<_> = self
            .timestamp_history
            .iter()
            .filter(|&&ts| ts >= cutoff)
            .collect();

        if relevant.len() < 2 {
            return count as f64;
        }

        let oldest = *relevant.first().unwrap();
        let newest = *relevant.last().unwrap();
        let span = (*newest - *oldest).as_secs_f64();

        if span < 1.0 {
            return count as f64;
        }

        // Normalize to hourly rate
        (count as f64 / span) * 3600.0
    }
}

pub struct AnnounceLimits {
    limits: BTreeMap<AddressHash, AnnounceLimitEntry>,
}

impl AnnounceLimits {
    pub fn new() -> Self {
        Self {
            limits: BTreeMap::new(),
        }
    }

    /// Check and record an announce, returning block duration if rate limited
    pub fn check(&mut self, destination: &AddressHash) -> Option<Duration> {
        if let Some(entry) = self.limits.get_mut(destination) {
            return entry.handle_announce();
        }

        // Create new entry and record this announce
        let mut entry = AnnounceLimitEntry::new(Default::default());
        let result = entry.handle_announce();
        self.limits.insert(destination.clone(), entry);

        result
    }

    /// Get rate information for all tracked destinations
    pub fn get_rate_table(&self) -> Vec<RateInfo> {
        self.limits
            .iter()
            .map(|(dest, entry)| entry.get_rate_info(*dest))
            .collect()
    }

    /// Get rate information for a specific destination
    pub fn get_rate_info(&self, destination: &AddressHash) -> Option<RateInfo> {
        self.limits
            .get(destination)
            .map(|entry| entry.get_rate_info(*destination))
    }

    /// Get the number of tracked destinations
    pub fn len(&self) -> usize {
        self.limits.len()
    }

    /// Check if no destinations are being tracked
    pub fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }

    /// Remove entries that haven't been heard from in a while
    pub fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.limits
            .retain(|_, entry| entry.last_announce.elapsed() <= max_age);
    }
}

impl Default for AnnounceLimits {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a zero AddressHash for testing
    fn zero_address_hash() -> AddressHash {
        AddressHash::new_from_slice(&[0u8; 16])
    }

    #[test]
    fn test_rate_info() {
        let mut limits = AnnounceLimits::new();
        let dest = zero_address_hash();

        // First check creates the entry
        limits.check(&dest);

        // Get rate info
        let rate_table = limits.get_rate_table();
        assert_eq!(rate_table.len(), 1);

        let info = &rate_table[0];
        assert!(info.last_announce.is_some());
        assert_eq!(info.timestamps.len(), 1);
        assert_eq!(info.violations, 0);
        assert!(info.blocked_until.is_none());
    }

    #[test]
    fn test_timestamp_history() {
        let mut limits = AnnounceLimits::new();
        let dest = zero_address_hash();

        // Make multiple announces
        for _ in 0..5 {
            limits.check(&dest);
        }

        let info = limits.get_rate_info(&dest).unwrap();
        assert_eq!(info.timestamps.len(), 5);
    }
}
