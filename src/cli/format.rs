//! Formatting utilities for CLI output.
//!
//! These functions match Python's RNS formatting for CLI parity:
//! - `format_hash` / `format_hash_hex` - Hash display
//! - `format_size` / `size_str` - Size formatting (RNS.prettysize)
//! - `format_speed` / `speed_str` - Speed formatting (RNS.prettyspeed)
//! - `format_time` / `format_time_compact` - Time formatting (RNS.prettytime)
//! - `format_time_ago` - Time ago formatting (RNS.Utilities.rnpath.pretty_date)
//! - `format_frequency` - Frequency formatting (RNS.prettyfrequency)

use crate::hash::AddressHash;

/// Format bytes as a hex string wrapped in angle brackets: `<hex>`.
///
/// Matches Python's hash display format for destination hashes.
///
/// # Example
/// ```
/// use reticulum::cli::format::format_hash;
/// assert_eq!(format_hash(&[0xab, 0xcd]), "<abcd>");
/// assert_eq!(format_hash(&[0xde, 0xad, 0xbe, 0xef]), "<deadbeef>");
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
/// ```
/// use reticulum::cli::format::format_hash_hex;
/// use reticulum::hash::AddressHash;
/// let hash = AddressHash::new([0xab; 16]);
/// assert_eq!(format_hash_hex(&hash), "abababababababababababababababab");
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
/// ```
/// use reticulum::cli::format::size_str;
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

    // No space before Y, matching Python's "%.2f%s%s" format
    format!("{:.2}Y{}", num, suffix.to_ascii_uppercase())
}

/// Format size in bytes as human-readable string.
///
/// Convenience wrapper around `size_str` for byte sizes.
pub fn format_size(bytes: u64) -> String {
    size_str(bytes, 'B')
}

/// Format bitrate in bits/sec as human-readable string.
///
/// Matches Python's `speed_str()` in `RNS/Utilities/rnstatus.py`.
/// Uses `%3.2f` formatting for parity with Python.
///
/// # Example
/// ```
/// use reticulum::cli::format::speed_str;
/// assert_eq!(speed_str(1500.0), "1.50 kbps");
/// assert_eq!(speed_str(1000000.0), "1.00 Mbps");
/// ```
pub fn speed_str(bits_per_sec: f64) -> String {
    const UNITS: &[&str] = &["", "k", "M", "G", "T", "P", "E", "Z"];
    let mut speed = bits_per_sec;

    for unit in UNITS {
        if speed.abs() < 1000.0 {
            // Match Python's "%3.2f %s%s" format (min width 3, 2 decimals)
            return format!("{:>3.2} {}bps", speed, unit);
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

/// Join time components with `", "` between middle items and `" and "` before the last.
///
/// Returns `"0s"` if the components list is empty (input time was zero).
/// Matches Python's `prettytime()` join logic.
fn join_time_components(components: &[String]) -> String {
    if components.is_empty() {
        return "0s".to_string();
    }
    let mut result = String::new();
    for (i, c) in components.iter().enumerate() {
        if i > 0 && i < components.len() - 1 {
            result.push_str(", ");
        } else if i > 0 {
            result.push_str(" and ");
        }
        result.push_str(c);
    }
    result
}

/// Format a seconds value for verbose time display.
///
/// Integer-valued floats display without a decimal point (e.g., 45.0 → "45").
/// Fractional values display with up to 2 decimal places (e.g., 1.5 → "1.5").
fn format_seconds_value(seconds: f64) -> String {
    if seconds.fract() == 0.0 {
        return format!("{}", seconds as i64);
    }
    let s = format!("{:.2}", seconds);
    s.trim_end_matches('0').to_string()
}

/// Format seconds as compact human-readable time.
///
/// Matches Python's `RNS.prettytime(compact=True)`.
/// Decomposes into up to 2 non-zero components with abbreviated units,
/// joined with `", "` and `" and "`.
///
/// # Example
/// ```
/// use reticulum::cli::format::format_time_compact;
/// assert_eq!(format_time_compact(45.0), "45s");
/// assert_eq!(format_time_compact(3661.0), "1h and 1m");
/// assert_eq!(format_time_compact(90061.0), "1d and 1h");
/// ```
pub fn format_time_compact(seconds: f64) -> String {
    let neg = seconds < 0.0;
    let time = seconds.abs();

    let days = (time / 86400.0) as i64;
    let remainder = time % 86400.0;
    let hours = (remainder / 3600.0) as i64;
    let remainder = remainder % 3600.0;
    let minutes = (remainder / 60.0) as i64;
    // Truncate seconds to integer, matching Python's int(time)
    let secs = (remainder % 60.0) as i64;

    let mut components = Vec::new();
    let mut displayed = 0;

    if days > 0 && displayed < 2 {
        components.push(format!("{}d", days));
        displayed += 1;
    }
    if hours > 0 && displayed < 2 {
        components.push(format!("{}h", hours));
        displayed += 1;
    }
    if minutes > 0 && displayed < 2 {
        components.push(format!("{}m", minutes));
        displayed += 1;
    }
    if secs > 0 && displayed < 2 {
        components.push(format!("{}s", secs));
    }

    let result = join_time_components(&components);
    if neg {
        format!("-{}", result)
    } else {
        result
    }
}

/// Format seconds as verbose human-readable time.
///
/// Matches Python's `RNS.prettytime(verbose=True)`.
/// Decomposes into all non-zero components with verbose labels
/// (e.g., "days", "hours", "minutes", "seconds"), joined with
/// `", "` and `" and "`. Handles singular/plural forms.
///
/// # Example
/// ```
/// use reticulum::cli::format::format_time;
/// assert_eq!(format_time(90061.5), "1 day, 1 hour, 1 minute and 1.5 seconds");
/// assert_eq!(format_time(3661.0), "1 hour, 1 minute and 1 second");
/// assert_eq!(format_time(86400.0), "1 day");
/// ```
pub fn format_time(seconds: f64) -> String {
    let neg = seconds < 0.0;
    let time = seconds.abs();

    let days = (time / 86400.0) as i64;
    let remainder = time % 86400.0;
    let hours = (remainder / 3600.0) as i64;
    let remainder = remainder % 3600.0;
    let minutes = (remainder / 60.0) as i64;
    // Round seconds to 2 decimal places, matching Python's round(time, 2)
    let secs = ((remainder % 60.0) * 100.0).round() / 100.0;

    let mut components = Vec::new();

    if days > 0 {
        components.push(format!(
            "{} day{}",
            days,
            if days == 1 { "" } else { "s" }
        ));
    }
    if hours > 0 {
        components.push(format!(
            "{} hour{}",
            hours,
            if hours == 1 { "" } else { "s" }
        ));
    }
    if minutes > 0 {
        components.push(format!(
            "{} minute{}",
            minutes,
            if minutes == 1 { "" } else { "s" }
        ));
    }
    if secs > 0.0 {
        let secs_str = format_seconds_value(secs);
        components.push(format!(
            "{} second{}",
            secs_str,
            if secs == 1.0 { "" } else { "s" }
        ));
    }

    let result = join_time_components(&components);
    if neg {
        format!("-{}", result)
    } else {
        result
    }
}

/// Format time elapsed since a Unix timestamp.
///
/// Matches Python's `pretty_date()` from `RNS/Utilities/rnpath.py`.
/// Returns verbose human-readable strings without an "ago" suffix.
///
/// # Example
/// ```
/// use reticulum::cli::format::format_time_ago;
/// use std::time::{SystemTime, UNIX_EPOCH};
/// let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
/// assert_eq!(format_time_ago(now - 30.0), "30 seconds");
/// assert_eq!(format_time_ago(now - 300.0), "5 minutes");
/// ```
pub fn format_time_ago(last_heard: f64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let diff = now - last_heard;

    if diff < 0.0 {
        return String::new();
    }

    let day_diff = (diff / 86400.0) as i64;
    let second_diff = (diff % 86400.0) as i64;

    if day_diff == 0 {
        if second_diff < 10 {
            return format!("{} seconds", second_diff);
        }
        if second_diff < 60 {
            return format!("{} seconds", second_diff);
        }
        if second_diff < 120 {
            return "1 minute".to_string();
        }
        if second_diff < 3600 {
            return format!("{} minutes", second_diff / 60);
        }
        if second_diff < 7200 {
            return "an hour".to_string();
        }
        if second_diff < 86400 {
            return format!("{} hours", second_diff / 3600);
        }
    }
    if day_diff == 1 {
        return "1 day".to_string();
    }
    if day_diff < 7 {
        return format!("{} days", day_diff);
    }
    if day_diff < 31 {
        return format!("{} weeks", day_diff / 7);
    }
    if day_diff < 365 {
        return format!("{} months", day_diff / 30);
    }
    format!("{} years", day_diff / 365)
}

/// Format frequency as human-readable Hz string.
///
/// Matches Python's `RNS.prettyfrequency()`.
/// Scales by 1e6 and iterates through µ/m/ /K/M/G/T/P/E/Z units with "Hz" suffix.
///
/// # Example
/// ```
/// use reticulum::cli::format::format_frequency;
/// assert_eq!(format_frequency(1.0), "1.00 Hz");
/// assert_eq!(format_frequency(1000.0), "1.00 KHz");
/// ```
pub fn format_frequency(hz: f64) -> String {
    let mut num = hz * 1e6;
    let units = ["µ", "m", "", "K", "M", "G", "T", "P", "E", "Z"];

    for unit in units {
        if num.abs() < 1000.0 {
            return format!("{:.2} {}Hz", num, unit);
        }
        num /= 1000.0;
    }

    // No space before Y, matching Python's "%.2f%s%s" format
    format!("{:.2}YHz", num)
}

/// Format a number with comma separators.
///
/// # Example
/// ```
/// use reticulum::cli::format::format_with_commas;
/// assert_eq!(format_with_commas(1000000), "1,000,000");
/// assert_eq!(format_with_commas(1234567890), "1,234,567,890");
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
        // Zero
        assert_eq!(format_time_compact(0.0), "0s");
        // Seconds only
        assert_eq!(format_time_compact(45.0), "45s");
        // Minutes and seconds (2-component cap)
        assert_eq!(format_time_compact(90.0), "1m and 30s");
        assert_eq!(format_time_compact(3661.0), "1h and 1m");
        // Single larger units
        assert_eq!(format_time_compact(7200.0), "2h");
        assert_eq!(format_time_compact(172800.0), "2d");
        // Days + hours (capped at 2)
        assert_eq!(format_time_compact(90061.0), "1d and 1h");
        // Negative
        assert_eq!(format_time_compact(-45.0), "-45s");
        assert_eq!(format_time_compact(-3661.0), "-1h and 1m");
    }

    #[test]
    fn test_format_time() {
        // Zero
        assert_eq!(format_time(0.0), "0s");
        // Seconds only
        assert_eq!(format_time(1.0), "1 second");
        assert_eq!(format_time(45.0), "45 seconds");
        assert_eq!(format_time(1.5), "1.5 seconds");
        // Minutes
        assert_eq!(format_time(60.0), "1 minute");
        assert_eq!(format_time(120.0), "2 minutes");
        // Minutes and seconds
        assert_eq!(format_time(61.0), "1 minute and 1 second");
        assert_eq!(format_time(125.0), "2 minutes and 5 seconds");
        // Hours
        assert_eq!(format_time(3600.0), "1 hour");
        assert_eq!(format_time(7200.0), "2 hours");
        // Hours, minutes, seconds
        assert_eq!(
            format_time(3661.0),
            "1 hour, 1 minute and 1 second"
        );
        // Days
        assert_eq!(format_time(86400.0), "1 day");
        assert_eq!(format_time(172800.0), "2 days");
        // All components
        assert_eq!(
            format_time(90061.0),
            "1 day, 1 hour, 1 minute and 1 second"
        );
        assert_eq!(
            format_time(90061.5),
            "1 day, 1 hour, 1 minute and 1.5 seconds"
        );
        // Negative
        assert_eq!(format_time(-45.0), "-45 seconds");
        assert_eq!(
            format_time(-3661.0),
            "-1 hour, 1 minute and 1 second"
        );
    }

    #[test]
    fn test_format_time_ago() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        // Same day
        assert_eq!(format_time_ago(now - 5.0), "5 seconds");
        assert_eq!(format_time_ago(now - 30.0), "30 seconds");
        assert_eq!(format_time_ago(now - 90.0), "1 minute");
        assert_eq!(format_time_ago(now - 300.0), "5 minutes");
        assert_eq!(format_time_ago(now - 5400.0), "an hour");
        assert_eq!(format_time_ago(now - 10800.0), "3 hours");

        // Multiple days
        assert_eq!(format_time_ago(now - 86400.0), "1 day");
        assert_eq!(format_time_ago(now - 172800.0), "2 days");
        assert_eq!(format_time_ago(now - 604800.0), "1 weeks");
        assert_eq!(format_time_ago(now - 2592000.0), "4 weeks");

        // Future timestamp
        assert_eq!(format_time_ago(now + 100.0), "");
    }

    #[test]
    fn test_format_frequency() {
        assert_eq!(format_frequency(0.000001), "1.00 µHz");
        assert_eq!(format_frequency(0.001), "1.00 mHz");
        assert_eq!(format_frequency(1.0), "1.00 Hz");
        assert_eq!(format_frequency(1000.0), "1.00 KHz");
        assert_eq!(format_frequency(1000000.0), "1.00 MHz");
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
