use alloc::collections::BTreeMap;
use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use tokio::time::Duration;
use tokio::time::Instant;

use crate::hash::AddressHash;

/// Maximum number of timestamps to keep in history.
/// Matches Python's Transport.MAX_RATE_TIMESTAMPS = 16.
const MAX_RATE_TIMESTAMPS: usize = 16;

pub struct AnnounceRateLimit {
    pub target: Duration,
    pub grace: u32,
    pub penalty: Duration,
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
    /// Current violation count — decremented when compliant, matching Python behavior
    violations: u32,
    /// Last announce time (None if this is the first announce)
    last_announce: Option<Instant>,
    /// When the block expires (None if not blocked)
    blocked_until: Option<Instant>,
    /// History of announce timestamps for rate info queries
    timestamp_history: VecDeque<Instant>,
}

impl AnnounceLimitEntry {
    pub fn new(rate_limit: Option<AnnounceRateLimit>) -> Self {
        Self {
            rate_limit,
            violations: 0,
            last_announce: None,
            blocked_until: None,
            timestamp_history: VecDeque::with_capacity(MAX_RATE_TIMESTAMPS),
        }
    }

    /// Record an announce and check for rate limiting.
    /// Returns Some(duration) if blocked, None if accepted.
    ///
    /// Matches Python Transport.py lines ~1691–1719:
    /// - Inter-arrival time compared against target
    /// - Violations increment when too fast, decrement (saturating) when on time
    /// - Block triggers when violations > grace (strict >)
    /// - blocked_until = last + target + penalty (not now-based)
    /// - No state changes while blocked (no extension)
    /// - last_announce only updated on accepted announces
    pub fn handle_announce(&mut self) -> Option<Duration> {
        let now = Instant::now();

        // Record timestamp, cap at MAX_RATE_TIMESTAMPS (no time-based pruning).
        self.timestamp_history.push_back(now);
        while self.timestamp_history.len() > MAX_RATE_TIMESTAMPS {
            self.timestamp_history.pop_front();
        }

        let rate_limit = match self.rate_limit {
            Some(ref rl) => rl,
            None => {
                // No rate limit configured — always accept, update last for info queries.
                self.last_announce = Some(now);
                return None;
            }
        };

        // First announce: accept unconditionally (Python: new entry gets last=now).
        let last = match self.last_announce {
            Some(last) => last,
            None => {
                self.last_announce = Some(now);
                return None;
            }
        };

        // Python: current_rate = now - rate_entry["last"]
        let current_rate = now.duration_since(last);

        // Python: if now > rate_entry["blocked_until"]:
        let is_blocked = if self.blocked_until.map_or(true, |b| now > b) {
            // Not currently blocked — evaluate rate compliance.
            if current_rate < rate_limit.target {
                // Too fast — increment violations
                self.violations += 1;
            } else {
                // On time — decrement violations (Python: max(0, violations - 1))
                self.violations = self.violations.saturating_sub(1);
            }

            // Python: if rate_violations > grace (note: strict >, not >=)
            if self.violations > rate_limit.grace {
                // Python: blocked_until = last + target + penalty
                self.blocked_until = Some(last + rate_limit.target + rate_limit.penalty);
                true
            } else {
                // Accepted — only update last_announce on accept
                self.last_announce = Some(now);
                false
            }
        } else {
            // Still blocked — no extension, no state changes
            true
        };

        if is_blocked {
            self.blocked_until.and_then(|b| b.checked_duration_since(now))
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
        let last_announce_unix = self.last_announce.and_then(|last| {
            if last <= instant_now {
                Some(now - last.elapsed().as_secs_f64())
            } else {
                None
            }
        });

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
        let blocked_until_unix = self.blocked_until.and_then(|blocked| {
            if blocked > instant_now {
                let remaining = (blocked - instant_now).as_secs_f64();
                Some(now + remaining)
            } else {
                None
            }
        });

        RateInfo {
            destination: format!("{}", destination),
            last_announce: last_announce_unix,
            timestamps,
            violations: self.violations,
            blocked_until: blocked_until_unix,
        }
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

    /// Check and record an announce, returning block duration if rate limited.
    ///
    /// When `rate_limit` is `None`, the entry tracks timestamps for rate info
    /// queries but never blocks — matching Python behavior where interfaces
    /// without `announce_rate_target` set do not rate-limit.
    ///
    /// Refreshes the rate_limit on existing entries so that interface config
    /// changes take effect immediately (Python reads rate params fresh each call).
    pub fn check(
        &mut self,
        destination: &AddressHash,
        rate_limit: Option<AnnounceRateLimit>,
    ) -> Option<Duration> {
        if let Some(entry) = self.limits.get_mut(destination) {
            // Refresh rate limit from current interface config
            entry.rate_limit = rate_limit;
            return entry.handle_announce();
        }

        // Create new entry with the provided rate limit (or None for no limiting)
        let mut entry = AnnounceLimitEntry::new(rate_limit);
        let result = entry.handle_announce();
        self.limits.insert(*destination, entry);

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
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.limits.len()
    }

    /// Check if no destinations are being tracked
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }

    /// Remove entries that haven't been heard from in a while
    #[allow(dead_code)]
    pub fn cleanup_stale(&mut self, max_age: Duration) {
        self.limits.retain(|_, entry| {
            entry
                .last_announce
                .map(|last| last.elapsed() <= max_age)
                .unwrap_or(true) // Keep entries that haven't announced yet
        });
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

        // First check creates the entry (no rate limit)
        limits.check(&dest, None);

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

        // Make multiple announces (no rate limit — should never block)
        for _ in 0..5 {
            assert!(limits.check(&dest, None).is_none());
        }

        let info = limits.get_rate_info(&dest).unwrap();
        assert_eq!(info.timestamps.len(), 5);
    }

    #[test]
    fn test_no_rate_limit_never_blocks() {
        let mut limits = AnnounceLimits::new();
        let dest = zero_address_hash();

        // With no rate limit, rapid announces should never be blocked
        for _ in 0..100 {
            assert!(limits.check(&dest, None).is_none());
        }
    }

    #[test]
    fn test_timestamp_history_capped_at_max() {
        let mut limits = AnnounceLimits::new();
        let dest = zero_address_hash();

        // Make more announces than MAX_RATE_TIMESTAMPS
        for _ in 0..20 {
            limits.check(&dest, None);
        }

        let info = limits.get_rate_info(&dest).unwrap();
        assert_eq!(info.timestamps.len(), MAX_RATE_TIMESTAMPS);
    }

    #[test]
    fn test_with_rate_limit_blocks_after_grace() {
        let mut limits = AnnounceLimits::new();
        let dest = zero_address_hash();

        let rate_limit = || {
            Some(AnnounceRateLimit {
                target: Duration::from_secs(3600),
                grace: 2,
                penalty: Duration::from_secs(7200),
            })
        };

        // First announce: creates entry, no block
        assert!(limits.check(&dest, rate_limit()).is_none());

        // Rapid announce: violation 1 (under grace of 2)
        assert!(limits.check(&dest, rate_limit()).is_none());

        // Rapid announce: violation 2 = grace threshold, but Python uses strict >
        // so violations=2 with grace=2 does NOT block yet
        assert!(limits.check(&dest, rate_limit()).is_none());

        // Rapid announce: violation 3 > grace of 2, should block
        let blocked = limits.check(&dest, rate_limit());
        assert!(blocked.is_some());
    }

    #[test]
    fn test_violation_decrement_when_compliant() {
        // Verify that violations decrement when inter-arrival time meets target.
        let mut entry = AnnounceLimitEntry::new(Some(AnnounceRateLimit {
            target: Duration::from_millis(10),
            grace: 5,
            penalty: Duration::from_secs(60),
        }));

        // First announce — accepted
        assert!(entry.handle_announce().is_none());

        // Rapid announce — violation 1
        assert!(entry.handle_announce().is_none());
        assert_eq!(entry.violations, 1);

        // Wait for target to elapse, then announce — should decrement
        std::thread::sleep(Duration::from_millis(15));
        assert!(entry.handle_announce().is_none());
        assert_eq!(entry.violations, 0);
    }

    #[test]
    fn test_no_block_extension() {
        // Announces while blocked should NOT extend blocked_until.
        let mut entry = AnnounceLimitEntry::new(Some(AnnounceRateLimit {
            target: Duration::from_millis(100),
            grace: 0, // Block on first violation
            penalty: Duration::from_millis(200),
        }));

        // First announce — accepted
        assert!(entry.handle_announce().is_none());

        // Second announce — rapid, violations=1 > grace=0, blocked
        let blocked = entry.handle_announce();
        assert!(blocked.is_some());

        let original_blocked_until = entry.blocked_until.unwrap();

        // Another announce while blocked — blocked_until must NOT change
        let still_blocked = entry.handle_announce();
        assert!(still_blocked.is_some());
        assert_eq!(entry.blocked_until.unwrap(), original_blocked_until);
    }

    #[test]
    fn test_last_announce_not_updated_when_blocked() {
        let mut entry = AnnounceLimitEntry::new(Some(AnnounceRateLimit {
            target: Duration::from_millis(100),
            grace: 0,
            penalty: Duration::from_millis(200),
        }));

        // First announce — accepted, sets last_announce
        assert!(entry.handle_announce().is_none());
        let last_after_accept = entry.last_announce.unwrap();

        // Rapid announce — triggers block
        assert!(entry.handle_announce().is_some());

        // last_announce should NOT have been updated (block path doesn't update it)
        assert_eq!(entry.last_announce.unwrap(), last_after_accept);

        // Another announce while blocked — still should not update
        assert!(entry.handle_announce().is_some());
        assert_eq!(entry.last_announce.unwrap(), last_after_accept);
    }

    #[test]
    fn test_rate_limit_updated_on_existing_entry() {
        let mut limits = AnnounceLimits::new();
        let dest = zero_address_hash();

        // First call with no rate limit — always accepts
        assert!(limits.check(&dest, None).is_none());

        // Second call changes to a rate limit — should now evaluate rate
        let rate_limit = Some(AnnounceRateLimit {
            target: Duration::from_secs(3600),
            grace: 0,
            penalty: Duration::from_secs(7200),
        });

        // This is a rapid announce with grace=0, so violation=1 > 0 => blocked
        let result = limits.check(&dest, rate_limit);
        assert!(result.is_some());
    }

    #[test]
    fn test_blocked_until_uses_last_plus_target_plus_penalty() {
        // Verify blocked_until = last + target + penalty (not now + target).
        let mut entry = AnnounceLimitEntry::new(Some(AnnounceRateLimit {
            target: Duration::from_millis(100),
            grace: 0,
            penalty: Duration::from_millis(200),
        }));

        // First announce — accepted
        assert!(entry.handle_announce().is_none());
        let last = entry.last_announce.unwrap();

        // Second announce — triggers block
        assert!(entry.handle_announce().is_some());

        // blocked_until should be last + target + penalty = last + 300ms
        let expected = last + Duration::from_millis(300);
        let actual = entry.blocked_until.unwrap();

        // Allow small tolerance for timing
        let diff = if actual > expected {
            actual - expected
        } else {
            expected - actual
        };
        assert!(
            diff < Duration::from_millis(5),
            "blocked_until should be last + target + penalty, diff={:?}",
            diff
        );
    }
}
