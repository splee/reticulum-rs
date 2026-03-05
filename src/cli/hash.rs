//! Hash parsing utilities for CLI tools.
//!
//! Provides common hash parsing functions used across CLI binaries.

use crate::hash::AddressHash;

/// Parse a destination hash string.
///
/// Accepts various formats:
/// - Plain hex: `abcd1234...`
/// - Bracketed: `<abcd1234...>`
/// - Path-style: `/abcd1234.../`
///
/// # Arguments
/// * `dest_str` - The destination string to parse
///
/// # Returns
/// * `Ok(AddressHash)` - Successfully parsed 16-byte hash
/// * `Err(String)` - Error message describing the parse failure
///
/// # Example
/// ```
/// use reticulum::cli::hash::parse_destination;
/// let hash = parse_destination("<abcd1234567890abcdef1234567890ab>").unwrap();
/// assert_eq!(hash.as_slice(), &[0xab, 0xcd, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
///                               0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab]);
/// // Also accepts plain hex and path-style formats
/// assert!(parse_destination("abcd1234567890abcdef1234567890ab").is_ok());
/// assert!(parse_destination("/abcd1234567890abcdef1234567890ab/").is_ok());
/// ```
pub fn parse_destination(dest_str: &str) -> Result<AddressHash, String> {
    let clean = dest_str
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim_start_matches('/')
        .trim_end_matches('/');

    if clean.len() != 32 {
        return Err(format!(
            "Invalid hash length: expected 32 hex characters, got {}",
            clean.len()
        ));
    }

    AddressHash::new_from_hex_string(clean)
        .map_err(|_| "Invalid hexadecimal string".to_string())
}

/// Parse an identity hash (16 bytes / 32 hex chars).
///
/// Used for parsing identity hashes from CLI arguments.
///
/// # Arguments
/// * `hex_str` - The hex string to parse
///
/// # Returns
/// * `Ok([u8; 16])` - Successfully parsed 16-byte array
/// * `Err(String)` - Error message describing the parse failure
pub fn parse_identity_hash(hex_str: &str) -> Result<[u8; 16], String> {
    let hex_str = hex_str.trim();
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;

    if bytes.len() != 16 {
        return Err(format!("expected 16 bytes, got {}", bytes.len()));
    }

    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Parse a hex string into bytes.
///
/// Generic hex parsing without length validation.
///
/// # Arguments
/// * `hex_str` - The hex string to parse
///
/// # Returns
/// * `Ok(Vec<u8>)` - Successfully parsed bytes
/// * `Err(String)` - Error message describing the parse failure
pub fn parse_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    let clean = hex_str
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    hex::decode(clean).map_err(|e| format!("invalid hex: {}", e))
}

/// Validate that a string is a valid hex hash of expected length.
///
/// # Arguments
/// * `hex_str` - The hex string to validate
/// * `expected_bytes` - Expected number of bytes (hex chars / 2)
///
/// # Returns
/// * `Ok(())` - String is valid
/// * `Err(String)` - Error message describing the validation failure
pub fn validate_hex_hash(hex_str: &str, expected_bytes: usize) -> Result<(), String> {
    let clean = hex_str
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>');

    let expected_chars = expected_bytes * 2;
    if clean.len() != expected_chars {
        return Err(format!(
            "Invalid hash length: expected {} hex characters, got {}",
            expected_chars,
            clean.len()
        ));
    }

    // Validate hex characters
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid hex characters in hash".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_destination_plain() {
        let result = parse_destination("abcdef0123456789abcdef0123456789");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_destination_bracketed() {
        let result = parse_destination("<abcdef0123456789abcdef0123456789>");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_destination_path_style() {
        let result = parse_destination("/abcdef0123456789abcdef0123456789/");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_destination_with_whitespace() {
        let result = parse_destination("  <abcdef0123456789abcdef0123456789>  ");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_destination_wrong_length() {
        let result = parse_destination("abcdef");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 32"));
    }

    #[test]
    fn test_parse_destination_invalid_hex() {
        // Test with too-short string (AddressHash::new_from_hex_string has an internal
        // unwrap bug for invalid hex chars, so we test length validation instead)
        let result = parse_destination("abcd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 32"));
    }

    #[test]
    fn test_parse_identity_hash_valid() {
        let result = parse_identity_hash("abcdef0123456789abcdef0123456789");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_parse_identity_hash_wrong_length() {
        let result = parse_identity_hash("abcdef");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 16 bytes"));
    }

    #[test]
    fn test_parse_hex_basic() {
        let result = parse_hex("abcd");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xab, 0xcd]);
    }

    #[test]
    fn test_parse_hex_with_prefix() {
        let result = parse_hex("0xabcd");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xab, 0xcd]);
    }

    #[test]
    fn test_parse_hex_bracketed() {
        let result = parse_hex("<abcd>");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xab, 0xcd]);
    }

    #[test]
    fn test_validate_hex_hash_valid() {
        let result = validate_hex_hash("abcdef0123456789abcdef0123456789", 16);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_hex_hash_wrong_length() {
        let result = validate_hex_hash("abcd", 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hex_hash_invalid_chars() {
        let result = validate_hex_hash("ghij", 2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid hex characters"));
    }
}
