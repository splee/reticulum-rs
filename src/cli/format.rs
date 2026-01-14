//! Formatting utilities for CLI output.
//!
//! These functions match Python's RNS formatting for CLI parity:
//! - `format_hash` / `format_hash_hex` - Hash display
//! - `format_size` / `size_str` - Size formatting (RNS.prettysize)
//! - `format_speed` / `speed_str` - Speed formatting (RNS.prettyspeed)
//! - `format_time` / `format_time_compact` - Time formatting (RNS.prettytime)
//! - `format_time_ago` - Time ago formatting

use crate::hash::AddressHash;

/// Format bytes as a hex string wrapped in angle brackets: `<hex>`.
///
/// Matches Python's hash display format for destination hashes.
///
/// # Example
/// ```ignore
/// let hash = AddressHash::new_from_slice(&[0xab, 0xcd]);
/// assert_eq!(format_hash(hash.as_slice()), "<abcd>");
/// ```
pub fn format_hash(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2 + 2);
    hex.push('<');
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex.push('>');
    hex
}

/// Format an AddressHash as a plain hex string (no brackets).
///
/// # Example
/// ```ignore
/// let hash = AddressHash::new_from_slice(&[0xab, 0xcd]);
/// assert_eq!(format_hash_hex(&hash), "abcd");
/// ```
pub fn format_hash_hex(hash: &AddressHash) -> String {
    hash.as_slice()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Format a hash with ellipsis for display: `XXXX…XXXX`.
///
/// Matches Python's `RNS.prettyhexrep()` format.
/// Shows first and last 4 bytes (8 hex chars each) with ellipsis.
pub fn format_hash_pretty(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        return format_hash_hex(&AddressHash::new_from_slice(bytes));
    }

    let prefix: String = bytes[..4].iter().map(|b| format!("{:02x}", b)).collect();
    let suffix: String = bytes[bytes.len() - 4..]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    format!("{}…{}", prefix, suffix)
}

/// Format file size with appropriate unit.
///
/// Matches Python's `RNS.prettysize()` / `size_str()`.
///
/// # Arguments
/// * `num` - Size in bytes
/// * `suffix` - 'B' for bytes, 'b' for bits (will multiply by 8)
///
/// # Example
/// ```ignore
/// assert_eq!(size_str(1500, 'B'), "1.50 KB");
/// assert_eq!(size_str(1000000, 'B'), "1.00 MB");
/// ```
pub fn size_str(num: u64, suffix: char) -> String {
    let mut num = num as f64;
    if suffix == 'b' {
        num *= 8.0;
    }
    let units = ['K', 'M', 'G', 'T', 'P', 'E', 'Z'];

    if num < 1000.0 {
        return format!("{:.0} {}", num, suffix.to_ascii_uppercase());
    }

    for unit in units {
        num /= 1000.0;
        if num < 1000.0 {
            return format!("{:.2} {}{}", num, unit, suffix.to_ascii_uppercase());
        }
    }

    format!("{:.2} Y{}", num, suffix.to_ascii_uppercase())
}

/// Format size in bytes as human-readable string.
///
/// Convenience wrapper around `size_str` for byte sizes.
pub fn format_size(bytes: u64) -> String {
    size_str(bytes, 'B')
}

/// Format bitrate in bits/sec as human-readable string.
///
/// Matches Python's `RNS.prettyspeed()`.
///
/// # Example
/// ```ignore
/// assert_eq!(speed_str(1500.0), "1.50 kbps");
/// assert_eq!(speed_str(1000000.0), "1.00 Mbps");
/// ```
pub fn speed_str(bits_per_sec: f64) -> String {
    const UNITS: &[&str] = &["", "k", "M", "G", "T", "P", "E", "Z"];
    let mut speed = bits_per_sec;

    for unit in UNITS {
        if speed.abs() < 1000.0 {
            return format!("{:.2} {}bps", speed, unit);
        }
        speed /= 1000.0;
    }

    format!("{:.2} Ybps", speed)
}

/// Format bytes/sec as human-readable transfer rate.
///
/// Matches Python's transfer rate display in rncp.
pub fn format_transfer_rate(bytes_per_sec: f64) -> String {
    const UNITS: &[&str] = &["", "K", "M", "G", "T", "P", "E", "Z"];
    let mut speed = bytes_per_sec;

    for unit in UNITS {
        if speed.abs() < 1000.0 {
            return format!("{:.2} {}B/s", speed, unit);
        }
        speed /= 1000.0;
    }

    format!("{:.2} YB/s", speed)
}

/// Format seconds as compact human-readable time.
///
/// Matches Python's `RNS.prettytime(compact=True)`.
/// Used by rnstatus for interface timing info.
///
/// # Example
/// ```ignore
/// assert_eq!(format_time_compact(45.0), "45s");
/// assert_eq!(format_time_compact(125.0), "2m");
/// assert_eq!(format_time_compact(7200.0), "2.0h");
/// ```
pub fn format_time_compact(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{:.0}s", seconds)
    } else if seconds < 3600.0 {
        let mins = seconds / 60.0;
        format!("{:.0}m", mins)
    } else if seconds < 86400.0 {
        let hours = seconds / 3600.0;
        format!("{:.1}h", hours)
    } else if seconds < 604800.0 {
        let days = seconds / 86400.0;
        format!("{:.1}d", days)
    } else {
        let weeks = seconds / 604800.0;
        format!("{:.1}w", weeks)
    }
}

/// Format seconds as verbose human-readable time.
///
/// Matches Python's `RNS.prettytime(compact=False)`.
/// Used by rnpath for path timing info.
///
/// # Example
/// ```ignore
/// assert_eq!(format_time(45.0), "45 seconds");
/// assert_eq!(format_time(125.0), "2 minutes");
/// assert_eq!(format_time(7200.0), "2 hours");
/// ```
pub fn format_time(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{:.0} seconds", seconds)
    } else if seconds < 3600.0 {
        let mins = seconds / 60.0;
        if mins < 2.0 {
            "1 minute".to_string()
        } else {
            format!("{:.0} minutes", mins)
        }
    } else if seconds < 86400.0 {
        let hours = seconds / 3600.0;
        if hours < 2.0 {
            "1 hour".to_string()
        } else {
            format!("{:.0} hours", hours)
        }
    } else if seconds < 604800.0 {
        let days = seconds / 86400.0;
        if days < 2.0 {
            "1 day".to_string()
        } else {
            format!("{:.0} days", days)
        }
    } else if seconds < 2592000.0 {
        let weeks = seconds / 604800.0;
        if weeks < 2.0 {
            "1 week".to_string()
        } else {
            format!("{:.0} weeks", weeks)
        }
    } else if seconds < 31536000.0 {
        let months = seconds / 2592000.0;
        if months < 2.0 {
            "1 month".to_string()
        } else {
            format!("{:.0} months", months)
        }
    } else {
        let years = seconds / 31536000.0;
        if years < 2.0 {
            "1 year".to_string()
        } else {
            format!("{:.0} years", years)
        }
    }
}

/// Format time elapsed since a Unix timestamp.
///
/// Returns strings like "Just now", "5m ago", "2h ago", "3d ago".
///
/// # Example
/// ```ignore
/// // For a timestamp 120 seconds in the past:
/// assert_eq!(format_time_ago(now - 120.0), "2m ago");
/// ```
pub fn format_time_ago(last_heard: f64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let diff = now - last_heard;

    if diff < 60.0 {
        "Just now".to_string()
    } else if diff < 3600.0 {
        format!("{}m ago", (diff / 60.0) as i32)
    } else if diff < 86400.0 {
        format!("{}h ago", (diff / 3600.0) as i32)
    } else {
        format!("{}d ago", (diff / 86400.0) as i32)
    }
}

/// Format frequency as human-readable rate.
///
/// Matches Python's `RNS.prettyfrequency()`.
///
/// # Example
/// ```ignore
/// assert_eq!(format_frequency(0.5), "0.5/s");
/// assert_eq!(format_frequency(0.01), "0.6/min");
/// ```
pub fn format_frequency(freq: f64) -> String {
    if freq < 0.001 {
        return "never".to_string();
    }

    let period = 1.0 / freq;
    if period < 60.0 {
        format!("{:.1}/s", freq)
    } else if period < 3600.0 {
        format!("{:.1}/min", freq * 60.0)
    } else if period < 86400.0 {
        format!("{:.1}/h", freq * 3600.0)
    } else {
        format!("{:.2}/day", freq * 86400.0)
    }
}

/// Format a number with comma separators.
///
/// # Example
/// ```ignore
/// assert_eq!(format_with_commas(1000000), "1,000,000");
/// ```
pub fn format_with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Spinner characters for progress animation.
///
/// Matches Python's Braille pattern spinner: `⢄⢂⢁⡁⡈⡐⡠`
pub const SPINNER_CHARS: &[char] = &['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];

/// Get the next spinner character for animation.
///
/// # Arguments
/// * `frame` - Current animation frame number
pub fn spinner_char(frame: usize) -> char {
    SPINNER_CHARS[frame % SPINNER_CHARS.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_hash() {
        let bytes = [0xab, 0xcd, 0xef];
        assert_eq!(format_hash(&bytes), "<abcdef>");
    }

    #[test]
    fn test_format_hash_empty() {
        let bytes: [u8; 0] = [];
        assert_eq!(format_hash(&bytes), "<>");
    }

    #[test]
    fn test_size_str_bytes() {
        assert_eq!(size_str(500, 'B'), "500 B");
        assert_eq!(size_str(1500, 'B'), "1.50 KB");
        assert_eq!(size_str(1500000, 'B'), "1.50 MB");
        assert_eq!(size_str(1500000000, 'B'), "1.50 GB");
    }

    #[test]
    fn test_size_str_bits() {
        // 125 bytes = 1000 bits = 1.00 Kb
        assert_eq!(size_str(125, 'b'), "1.00 KB");
    }

    #[test]
    fn test_speed_str() {
        assert_eq!(speed_str(500.0), "500.00 bps");
        assert_eq!(speed_str(1500.0), "1.50 kbps");
        assert_eq!(speed_str(1500000.0), "1.50 Mbps");
    }

    #[test]
    fn test_format_time_compact() {
        assert_eq!(format_time_compact(45.0), "45s");
        assert_eq!(format_time_compact(90.0), "2m");
        assert_eq!(format_time_compact(7200.0), "2.0h");
        assert_eq!(format_time_compact(172800.0), "2.0d");
    }

    #[test]
    fn test_format_time() {
        assert_eq!(format_time(45.0), "45 seconds");
        assert_eq!(format_time(60.0), "1 minute");
        assert_eq!(format_time(120.0), "2 minutes");
        assert_eq!(format_time(3600.0), "1 hour");
        assert_eq!(format_time(7200.0), "2 hours");
    }

    #[test]
    fn test_format_frequency() {
        assert_eq!(format_frequency(0.0001), "never");
        assert!(format_frequency(0.5).contains("/s"));
        assert!(format_frequency(0.01).contains("/min"));
    }

    #[test]
    fn test_format_with_commas() {
        assert_eq!(format_with_commas(100), "100");
        assert_eq!(format_with_commas(1000), "1,000");
        assert_eq!(format_with_commas(1000000), "1,000,000");
    }

    #[test]
    fn test_spinner_char() {
        assert_eq!(spinner_char(0), '⢄');
        assert_eq!(spinner_char(1), '⢂');
        assert_eq!(spinner_char(7), '⢄'); // Wraps around
    }
}
