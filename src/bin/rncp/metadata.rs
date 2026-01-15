//! Metadata encoding and decoding for rncp file transfers.
//!
//! This module handles:
//! - Encoding/decoding filename metadata in msgpack format
//! - Parsing fetch request packets
//! - Creating request data packets
//! - Truncated hash computation for path matching

use reticulum::hash::Hash;
use rmpv::Value;

/// Create a truncated hash (10 bytes) of data.
///
/// Matches Python's `Identity.truncated_hash()` method.
pub fn truncated_hash(data: &[u8]) -> [u8; 10] {
    let full_hash = Hash::new_from_slice(data);
    let mut truncated = [0u8; 10];
    truncated.copy_from_slice(&full_hash.as_bytes()[..10]);
    truncated
}

/// Path hash for "fetch_file" request handler.
///
/// Returns the truncated hash of "fetch_file" used to identify fetch requests.
pub fn fetch_file_path_hash() -> [u8; 10] {
    truncated_hash(b"fetch_file")
}

/// Encode a filename as msgpack metadata.
///
/// Creates metadata in the format Python expects:
/// `{"name": filename.encode("utf-8")}` (note: bytes value, not string)
///
/// # Arguments
/// * `filename` - The filename to encode
///
/// # Returns
/// The msgpack-encoded metadata bytes
pub fn encode_filename_metadata(filename: &str) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.push(0x81); // fixmap with 1 element
    metadata.push(0xa4); // fixstr with 4 chars ("name" key is a string)
    metadata.extend_from_slice(b"name");
    // Value is bytes (bin format), not string
    let name_bytes = filename.as_bytes();
    if name_bytes.len() < 256 {
        metadata.push(0xc4); // bin 8
        metadata.push(name_bytes.len() as u8);
    } else {
        metadata.push(0xc5); // bin 16
        metadata.push((name_bytes.len() >> 8) as u8);
        metadata.push(name_bytes.len() as u8);
    }
    metadata.extend_from_slice(name_bytes);
    metadata
}

/// Extract filename and data from a resource payload.
///
/// Resource data format with metadata:
/// `[len_high, len_mid, len_low, ...metadata..., ...actual_data...]`
/// Metadata format (msgpack): `{"name": <bytes>}`
///
/// # Arguments
/// * `data` - The raw resource data
/// * `has_metadata` - Whether the data includes a metadata header
///
/// # Returns
/// A tuple of (optional filename, actual data without metadata header)
pub fn extract_filename_and_data(data: &[u8], has_metadata: bool) -> (Option<String>, Vec<u8>) {
    if !has_metadata || data.len() < 4 {
        return (None, data.to_vec());
    }

    // Extract metadata length (3-byte big-endian)
    let meta_len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

    if data.len() < 3 + meta_len {
        log::debug!("Data too short for metadata of length {}", meta_len);
        return (None, data.to_vec());
    }

    let metadata = &data[3..3 + meta_len];
    let actual_data = data[3 + meta_len..].to_vec();

    // Parse msgpack metadata
    let filename = parse_metadata_filename(metadata);

    (filename, actual_data)
}

/// Parse msgpack metadata and extract the "name" field.
///
/// # Arguments
/// * `metadata` - The msgpack-encoded metadata bytes
///
/// # Returns
/// The filename if found, sanitized to basename only
pub fn parse_metadata_filename(metadata: &[u8]) -> Option<String> {
    let value = rmpv::decode::read_value(&mut &metadata[..]).ok()?;

    // Look for "name" key in the map
    match value {
        Value::Map(entries) => {
            for (key, val) in entries {
                let key_str = match key {
                    Value::String(s) => s.as_str().map(|s| s.to_string()),
                    Value::Binary(b) => String::from_utf8(b.clone()).ok(),
                    _ => None,
                };

                if key_str.as_deref() == Some("name") {
                    // Extract filename from value
                    let filename = match val {
                        Value::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                        Value::String(s) => s.as_str().unwrap_or("").to_string(),
                        _ => continue,
                    };

                    // Sanitize: only keep the basename to prevent path traversal
                    let basename = std::path::Path::new(&filename)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("received_file")
                        .to_string();

                    return Some(basename);
                }
            }
            None
        }
        _ => None,
    }
}

/// Parse a fetch_file request and extract the file path.
///
/// Request format (msgpack): `[timestamp: f64, path_hash: bin10, data: bin]`
///
/// # Arguments
/// * `payload` - The raw request payload
///
/// # Returns
/// The file path if the request is valid
pub fn parse_fetch_request(payload: &[u8]) -> Option<String> {
    let value = rmpv::decode::read_value(&mut &payload[..]).ok()?;

    let arr = match value {
        Value::Array(a) if a.len() >= 3 => a,
        _ => return None,
    };

    // Verify this is a fetch_file request by checking path hash
    let expected_hash = fetch_file_path_hash();
    let path_hash = match &arr[1] {
        Value::Binary(b) if b.len() == 10 => b.as_slice(),
        _ => return None,
    };

    if path_hash != expected_hash {
        log::debug!(
            "Request path hash mismatch: expected {}, got {}",
            hex::encode(expected_hash),
            hex::encode(path_hash)
        );
        return None;
    }

    // Extract file path from data field
    let file_path = match &arr[2] {
        Value::Binary(b) => String::from_utf8_lossy(b).to_string(),
        Value::String(s) => s.as_str().unwrap_or("").to_string(),
        _ => return None,
    };

    Some(file_path)
}

/// Create a msgpack-encoded request packet data.
///
/// Format: `[timestamp: f64, path_hash: bin10, request_data: bin]`
///
/// # Arguments
/// * `path` - The request path (e.g., "fetch_file")
/// * `data` - The request data to include
///
/// # Returns
/// The msgpack-encoded request packet
pub fn create_request_data(path: &str, data: &[u8]) -> Vec<u8> {
    let path_hash = truncated_hash(path.as_bytes());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    // Manually encode msgpack array
    // Format: [timestamp (float64), path_hash (bin 10), data (bin)]
    let mut result = Vec::new();

    // Array with 3 elements (fixarray)
    result.push(0x93);

    // Timestamp as float64
    result.push(0xcb);
    result.extend_from_slice(&timestamp.to_be_bytes());

    // Path hash as bin 8 (10 bytes)
    result.push(0xc4);
    result.push(10);
    result.extend_from_slice(&path_hash);

    // Data as bin 8 or bin 16
    if data.len() < 256 {
        result.push(0xc4);
        result.push(data.len() as u8);
    } else {
        result.push(0xc5);
        result.extend_from_slice(&(data.len() as u16).to_be_bytes());
    }
    result.extend_from_slice(data);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncated_hash_length() {
        let hash = truncated_hash(b"test data");
        assert_eq!(hash.len(), 10);
    }

    #[test]
    fn test_truncated_hash_deterministic() {
        let hash1 = truncated_hash(b"test data");
        let hash2 = truncated_hash(b"test data");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_fetch_file_path_hash() {
        let hash = fetch_file_path_hash();
        assert_eq!(hash.len(), 10);
        // Should be consistent across calls
        let hash2 = fetch_file_path_hash();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_encode_filename_metadata() {
        let metadata = encode_filename_metadata("test.txt");
        // Should start with fixmap (0x81) and contain "name" key
        assert!(!metadata.is_empty());
        assert_eq!(metadata[0], 0x81); // fixmap with 1 element

        // Parse it back
        let filename = parse_metadata_filename(&metadata);
        assert_eq!(filename, Some("test.txt".to_string()));
    }

    #[test]
    fn test_extract_filename_no_metadata() {
        let data = b"raw file content".to_vec();
        let (filename, extracted) = extract_filename_and_data(&data, false);
        assert!(filename.is_none());
        assert_eq!(extracted, data);
    }

    #[test]
    fn test_parse_metadata_sanitizes_path() {
        // Create metadata with path traversal attempt
        let metadata = encode_filename_metadata("../../../etc/passwd");
        let filename = parse_metadata_filename(&metadata);
        // Should only return basename
        assert_eq!(filename, Some("passwd".to_string()));
    }

    #[test]
    fn test_create_request_data_structure() {
        let data = create_request_data("fetch_file", b"test_path");
        // Should start with fixarray(3)
        assert_eq!(data[0], 0x93);
        // Should contain float64 marker
        assert_eq!(data[1], 0xcb);
    }
}
