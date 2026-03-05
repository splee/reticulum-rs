//! Resource part management.
//!
//! This module contains the ResourcePart struct used for individual parts
//! of a resource transfer and related utilities.

use crate::hash::Hash;
use sha2::Digest;

use super::constants::{MAPHASH_LEN, RANDOM_HASH_SIZE};

/// A resource part ready for transmission
#[derive(Debug, Clone)]
pub struct ResourcePart {
    /// The data for this part
    pub data: Vec<u8>,
    /// The map hash for this part
    pub map_hash: [u8; MAPHASH_LEN],
    /// Whether this part has been sent
    pub sent: bool,
}

impl ResourcePart {
    /// Create a new resource part with the given data and random hash.
    /// Calculates the map hash automatically.
    pub fn new(data: Vec<u8>, random_hash: &[u8; RANDOM_HASH_SIZE]) -> Self {
        let map_hash = calculate_map_hash(&data, random_hash);
        Self {
            data,
            map_hash,
            sent: false,
        }
    }
}

/// Calculate the map hash for a part.
/// Format: full_hash(data + random_hash)[:MAPHASH_LEN]
pub fn calculate_map_hash(data: &[u8], random_hash: &[u8; RANDOM_HASH_SIZE]) -> [u8; MAPHASH_LEN] {
    let full_hash = Hash::new(
        Hash::generator()
            .chain_update(data)
            .chain_update(random_hash)
            .finalize()
            .into(),
    );
    let mut result = [0u8; MAPHASH_LEN];
    result.copy_from_slice(&full_hash.as_bytes()[..MAPHASH_LEN]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_part_creation() {
        let data = vec![0x42u8; 100];
        let random_hash = [0x12u8; RANDOM_HASH_SIZE];

        let part = ResourcePart::new(data.clone(), &random_hash);

        assert_eq!(part.data, data);
        assert!(!part.sent);
        assert_eq!(part.map_hash.len(), MAPHASH_LEN);
    }

    #[test]
    fn test_map_hash_calculation() {
        let random_hash = [0x12u8; RANDOM_HASH_SIZE];
        let data = b"test data for hashing";

        let hash1 = calculate_map_hash(data, &random_hash);
        let hash2 = calculate_map_hash(data, &random_hash);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Different data should produce different hash
        let different_data = b"different data";
        let hash3 = calculate_map_hash(different_data, &random_hash);
        assert_ne!(hash1, hash3);

        // Different random hash should produce different result
        let different_random = [0x34u8; RANDOM_HASH_SIZE];
        let hash4 = calculate_map_hash(data, &different_random);
        assert_ne!(hash1, hash4);
    }

    #[test]
    fn test_map_hash_length() {
        let data = b"some data";
        let random_hash = [0xAB; RANDOM_HASH_SIZE];

        let hash = calculate_map_hash(data, &random_hash);
        assert_eq!(hash.len(), MAPHASH_LEN);
    }
}
