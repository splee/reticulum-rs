//! Constants for resource transfer system.
//!
//! This module contains all the constants used by the resource transfer system,
//! including window sizes, timeouts, and protocol values.

/// Length of the map hash for each part
pub const MAPHASH_LEN: usize = 4;
/// Length of the random hash prepended to data
pub const RANDOM_HASH_SIZE: usize = 4;

/// The initial window size at beginning of transfer
pub const WINDOW_INITIAL: usize = 4;
/// Absolute minimum window size during transfer
pub const WINDOW_MIN: usize = 2;
/// The maximum window size for transfers on slow links
pub const WINDOW_MAX_SLOW: usize = 10;
/// The maximum window size for transfers on very slow links
pub const WINDOW_MAX_VERY_SLOW: usize = 4;
/// The maximum window size for transfers on fast links
pub const WINDOW_MAX_FAST: usize = 75;
/// Global maximum window (for calculating maps and guard segments)
pub const WINDOW_MAX: usize = WINDOW_MAX_FAST;

/// Minimum allowed flexibility of window size
pub const WINDOW_FLEXIBILITY: usize = 4;

/// Fast rate threshold rounds before using fast window size
pub const FAST_RATE_THRESHOLD: usize = WINDOW_MAX_SLOW - WINDOW_INITIAL - 2;
/// Very slow rate threshold rounds before capping window
pub const VERY_SLOW_RATE_THRESHOLD: usize = 2;

/// Rate threshold for fast links (bytes per second) - 50 Kbps
pub const RATE_FAST: f64 = (50.0 * 1000.0) / 8.0;
/// Rate threshold for very slow links (bytes per second) - 2 Kbps
pub const RATE_VERY_SLOW: f64 = (2.0 * 1000.0) / 8.0;

/// Maximum efficient size for a single resource segment (about 1 MB)
/// Capped at 16777215 (0xFFFFFF) to fit in 3 bytes in advertisements
pub const MAX_EFFICIENT_SIZE: usize = 1024 * 1024 - 1;

/// Maximum metadata size (about 16 MB)
pub const METADATA_MAX_SIZE: usize = 16 * 1024 * 1024 - 1;

/// Maximum size to auto-compress before sending
pub const AUTO_COMPRESS_MAX_SIZE: usize = 64 * 1024 * 1024;

/// Response max grace time
pub const RESPONSE_MAX_GRACE_TIME: f64 = 10.0;

/// Part timeout factor
pub const PART_TIMEOUT_FACTOR: f64 = 4.0;
/// Part timeout factor after RTT is known
pub const PART_TIMEOUT_FACTOR_AFTER_RTT: f64 = 2.0;
/// Proof timeout factor
pub const PROOF_TIMEOUT_FACTOR: f64 = 3.0;

/// Maximum retries for resource transfer
pub const MAX_RETRIES: u32 = 16;
/// Maximum retries for advertisement
pub const MAX_ADV_RETRIES: u32 = 4;

/// Sender grace time
pub const SENDER_GRACE_TIME: f64 = 10.0;
/// Processing grace time
pub const PROCESSING_GRACE: f64 = 1.0;
/// Retry grace time
pub const RETRY_GRACE_TIME: f64 = 0.25;
/// Per-retry delay
pub const PER_RETRY_DELAY: f64 = 0.5;

/// Watchdog max sleep time
pub const WATCHDOG_MAX_SLEEP: f64 = 1.0;

/// Hashmap status indicators
pub const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;
