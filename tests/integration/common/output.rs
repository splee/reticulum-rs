//! Output parsing utilities for integration tests.
//!
//! Parses the KEY=VALUE output format used by test helper scripts.
//! This format allows test verification by checking for specific markers
//! in process output.

use std::collections::HashMap;

/// Parsed test output containing KEY=VALUE fields.
///
/// The Python and Rust test helpers output structured data in the format:
/// ```text
/// DESTINATION_HASH=abc123
/// ANNOUNCE_SENT=1
/// LINK_ACTIVATED=def456
/// ```
///
/// This struct parses and provides access to these fields.
#[derive(Debug, Clone)]
pub struct TestOutput {
    /// Map of field names to their values (supports multiple values per key).
    fields: HashMap<String, Vec<String>>,
    /// The raw output string.
    raw: String,
}

impl TestOutput {
    /// Parse output string into structured fields.
    ///
    /// Extracts all lines matching the pattern `KEY=VALUE` where:
    /// - KEY is uppercase letters, numbers, and underscores
    /// - VALUE is everything after the `=` until end of line
    pub fn parse(output: &str) -> Self {
        let mut fields: HashMap<String, Vec<String>> = HashMap::new();

        for line in output.lines() {
            let line = line.trim();
            if let Some(eq_pos) = line.find('=') {
                let key = &line[..eq_pos];
                let value = &line[eq_pos + 1..];

                // Only accept keys that look like our markers (uppercase with underscores)
                if !key.is_empty()
                    && key
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                {
                    fields
                        .entry(key.to_string())
                        .or_default()
                        .push(value.to_string());
                }
            }
        }

        Self {
            fields,
            raw: output.to_string(),
        }
    }

    /// Get the first value for a field, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).and_then(|v| v.first().map(|s| s.as_str()))
    }

    /// Get all values for a field (some fields appear multiple times).
    pub fn get_all(&self, key: &str) -> &[String] {
        self.fields.get(key).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Check if a field exists in the output.
    pub fn has(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// Get the destination hash if present.
    pub fn destination_hash(&self) -> Option<&str> {
        self.get("DESTINATION_HASH")
    }

    /// Check if a link was activated.
    pub fn link_activated(&self) -> bool {
        self.has("LINK_ACTIVATED")
    }

    /// Get the link ID if a link was activated.
    pub fn link_id(&self) -> Option<&str> {
        self.get("LINK_ACTIVATED")
    }

    /// Get the status field if present.
    pub fn status(&self) -> Option<&str> {
        self.get("STATUS")
    }

    /// Get the number of announces sent.
    pub fn announce_count(&self) -> Option<u32> {
        self.get_all("ANNOUNCE_SENT")
            .last()
            .and_then(|s| s.parse().ok())
    }

    /// Get raw output string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Check if output contains a specific string.
    pub fn contains(&self, pattern: &str) -> bool {
        self.raw.contains(pattern)
    }
}

/// Parse hop count from rnpath command output.
///
/// Looks for patterns like:
/// - "2 hops" or "2 hop"
/// - "hops: 2"
/// - "hop count: 2"
///
/// Returns None if no hop count could be parsed.
pub fn parse_hop_count(output: &str) -> Option<u32> {
    let output_lower = output.to_lowercase();

    // Pattern: "N hops" or "N hop"
    for word in output_lower.split_whitespace() {
        if word.starts_with("hop") {
            // Check previous word for number
            break;
        }
    }

    // Manual pattern matching since we don't have regex crate
    // Look for "N hop" pattern
    let words: Vec<&str> = output_lower.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        if word.starts_with("hop") {
            // Check if previous word is a number
            if i > 0 {
                if let Ok(n) = words[i - 1].parse::<u32>() {
                    return Some(n);
                }
            }
        }
        // Check for "hops:" or "hops :" followed by number
        if *word == "hops:" || word.starts_with("hops:") {
            let num_str = word.strip_prefix("hops:").unwrap_or("");
            if let Ok(n) = num_str.trim().parse::<u32>() {
                return Some(n);
            }
            // Check next word
            if i + 1 < words.len() {
                if let Ok(n) = words[i + 1].parse::<u32>() {
                    return Some(n);
                }
            }
        }
    }

    None
}

/// Determine if path output indicates the path is known.
///
/// Checks for indicators that a destination path exists in rnpath output.
pub fn is_path_known(output: &str) -> bool {
    let lower = output.to_lowercase();
    lower.contains("hop")
        || lower.contains("path")
        || lower.contains("known")
        || lower.contains("via")
}

/// Extract a field value from output lines.
///
/// Searches for a line starting with `key=` and returns the value after the `=`.
pub fn extract_field(output: &str, key: &str) -> Option<String> {
    TestOutput::parse(output).get(key).map(|s| s.to_string())
}

/// Wait for a specific field to appear in output.
///
/// Returns the value when found, or None if the pattern never appears in the full output.
pub fn find_field_value(output: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with(&prefix) {
            return Some(line[prefix.len()..].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_output() {
        let output = "DESTINATION_HASH=abc123\nANNOUNCE_SENT=1\n";
        let parsed = TestOutput::parse(output);

        assert_eq!(parsed.destination_hash(), Some("abc123"));
        assert_eq!(parsed.get("ANNOUNCE_SENT"), Some("1"));
    }

    #[test]
    fn test_parse_multiple_values() {
        let output = "ANNOUNCE_SENT=1\nANNOUNCE_SENT=2\nANNOUNCE_SENT=3\n";
        let parsed = TestOutput::parse(output);

        let announces = parsed.get_all("ANNOUNCE_SENT");
        assert_eq!(announces, &["1", "2", "3"]);
        assert_eq!(parsed.announce_count(), Some(3));
    }

    #[test]
    fn test_link_activated() {
        let output = "DESTINATION_HASH=abc\nLINK_ACTIVATED=link123\n";
        let parsed = TestOutput::parse(output);

        assert!(parsed.link_activated());
        assert_eq!(parsed.link_id(), Some("link123"));
    }

    #[test]
    fn test_ignores_non_marker_lines() {
        let output = "Some log message\nDESTINATION_HASH=abc123\nMore logs here\n";
        let parsed = TestOutput::parse(output);

        assert_eq!(parsed.destination_hash(), Some("abc123"));
        assert!(!parsed.has("Some"));
    }

    #[test]
    fn test_extract_field() {
        let output = "DESTINATION_HASH=abc123\nSTATUS=SHUTDOWN\n";
        assert_eq!(extract_field(output, "STATUS"), Some("SHUTDOWN".to_string()));
        assert_eq!(extract_field(output, "MISSING"), None);
    }
}
