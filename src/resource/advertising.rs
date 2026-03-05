//! Resource advertisement for announcing resources.
//!
//! This module handles the creation, packing, and unpacking of resource
//! advertisements that are sent to receivers before a transfer begins.

use crate::error::RnsError;

use super::constants::{MAPHASH_LEN, RANDOM_HASH_SIZE, WINDOW_MAX};
use crate::packet::{AES_BLOCK_SIZE, HEADER_MIN_SIZE, IFAC_MIN_SIZE, RETICULUM_MTU, TOKEN_OVERHEAD};
use super::status::ResourceFlags;

/// Resource advertisement for announcing a resource
#[derive(Debug, Clone)]
pub struct ResourceAdvertisement {
    /// Transfer size (after compression/encryption)
    pub transfer_size: usize,
    /// Total uncompressed data size
    pub data_size: usize,
    /// Number of parts
    pub num_parts: usize,
    /// Resource hash
    pub hash: [u8; 32],
    /// Random hash
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    /// Original hash (for multi-segment)
    pub original_hash: [u8; 32],
    /// Segment index (1-based)
    pub segment_index: usize,
    /// Total segments
    pub total_segments: usize,
    /// Request ID (for request/response pattern)
    pub request_id: Option<[u8; 16]>,
    /// Resource flags
    pub flags: ResourceFlags,
    /// Hashmap (first segment only)
    pub hashmap: Vec<u8>,
}

impl ResourceAdvertisement {
    /// Overhead in bytes for advertisement packet
    pub const OVERHEAD: usize = 134;

    /// Maximum hashmap entries that fit in an advertisement
    pub const HASHMAP_MAX_LEN: usize = {
        // Match Python: floor((Link.MDU - OVERHEAD)/MAPHASH_LEN)
        // Link.MDU = floor((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD)/AES_BLOCKSIZE)*AES_BLOCKSIZE - 1
        let base = (RETICULUM_MTU - IFAC_MIN_SIZE - HEADER_MIN_SIZE - TOKEN_OVERHEAD) / AES_BLOCK_SIZE;
        let link_mdu = base * AES_BLOCK_SIZE - 1;
        (link_mdu - Self::OVERHEAD) / MAPHASH_LEN
    };

    /// Collision guard size for hashmap
    pub const COLLISION_GUARD_SIZE: usize = 2 * WINDOW_MAX + Self::HASHMAP_MAX_LEN;

    /// Pack the advertisement into bytes using MessagePack map format
    pub fn pack(&self, segment: usize) -> Result<Vec<u8>, RnsError> {
        use std::collections::BTreeMap;

        // Calculate hashmap slice for this segment
        let hashmap_start = segment * Self::HASHMAP_MAX_LEN * MAPHASH_LEN;
        let hashmap_end =
            ((segment + 1) * Self::HASHMAP_MAX_LEN * MAPHASH_LEN).min(self.hashmap.len());

        let hashmap_slice = if hashmap_start < self.hashmap.len() {
            self.hashmap[hashmap_start..hashmap_end].to_vec()
        } else {
            vec![]
        };

        // Build a map that matches Python's dictionary structure
        let mut map: BTreeMap<String, rmpv::Value> = BTreeMap::new();
        map.insert(
            "t".to_string(),
            rmpv::Value::from(self.transfer_size as u64),
        );
        map.insert("d".to_string(), rmpv::Value::from(self.data_size as u64));
        map.insert("n".to_string(), rmpv::Value::from(self.num_parts as u64));
        map.insert("h".to_string(), rmpv::Value::Binary(self.hash.to_vec()));
        map.insert(
            "r".to_string(),
            rmpv::Value::Binary(self.random_hash.to_vec()),
        );
        map.insert(
            "o".to_string(),
            rmpv::Value::Binary(self.original_hash.to_vec()),
        );
        map.insert(
            "i".to_string(),
            rmpv::Value::from(self.segment_index as u64),
        );
        map.insert(
            "l".to_string(),
            rmpv::Value::from(self.total_segments as u64),
        );

        // Handle optional request_id
        if let Some(ref req_id) = self.request_id {
            map.insert("q".to_string(), rmpv::Value::Binary(req_id.to_vec()));
        } else {
            map.insert("q".to_string(), rmpv::Value::Nil);
        }

        map.insert(
            "f".to_string(),
            rmpv::Value::from(self.flags.to_byte() as u64),
        );
        map.insert("m".to_string(), rmpv::Value::Binary(hashmap_slice));

        // Serialize as map
        let value = rmpv::Value::Map(
            map.into_iter()
                .map(|(k, v)| (rmpv::Value::String(k.into()), v))
                .collect(),
        );

        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &value).map_err(|_| RnsError::InvalidArgument)?;

        Ok(buf)
    }

    /// Unpack an advertisement from bytes
    pub fn unpack(data: &[u8]) -> Result<Self, RnsError> {
        let value =
            rmpv::decode::read_value(&mut &data[..]).map_err(|_| RnsError::InvalidArgument)?;

        let map = match value {
            rmpv::Value::Map(m) => m,
            _ => return Err(RnsError::InvalidArgument),
        };

        // Helper to extract values from the map
        let get_value = |key: &str| -> Option<&rmpv::Value> {
            map.iter()
                .find(|(k, _)| match k {
                    rmpv::Value::String(s) => s.as_str() == Some(key),
                    _ => false,
                })
                .map(|(_, v)| v)
        };

        let get_u64 = |key: &str| -> Result<u64, RnsError> {
            get_value(key)
                .and_then(|v| v.as_u64())
                .ok_or(RnsError::InvalidArgument)
        };

        let get_bytes = |key: &str| -> Result<Vec<u8>, RnsError> {
            get_value(key)
                .and_then(|v| match v {
                    rmpv::Value::Binary(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or(RnsError::InvalidArgument)
        };

        let transfer_size = get_u64("t")? as usize;
        let data_size = get_u64("d")? as usize;
        let num_parts = get_u64("n")? as usize;

        let hash: [u8; 32] = get_bytes("h")?
            .try_into()
            .map_err(|_| RnsError::InvalidArgument)?;

        let random_hash: [u8; RANDOM_HASH_SIZE] = get_bytes("r")?
            .try_into()
            .map_err(|_| RnsError::InvalidArgument)?;

        let original_hash: [u8; 32] = get_bytes("o")?
            .try_into()
            .map_err(|_| RnsError::InvalidArgument)?;

        let segment_index = get_u64("i")? as usize;
        let total_segments = get_u64("l")? as usize;

        let request_id = get_value("q").and_then(|v| match v {
            rmpv::Value::Binary(b) if b.len() == 16 => {
                let arr: [u8; 16] = b.clone().try_into().ok()?;
                Some(arr)
            }
            rmpv::Value::Nil => None,
            _ => None,
        });

        let flags = ResourceFlags::from_byte(get_u64("f")? as u8);
        let hashmap = get_bytes("m")?;

        Ok(Self {
            transfer_size,
            data_size,
            num_parts,
            hash,
            random_hash,
            original_hash,
            segment_index,
            total_segments,
            request_id,
            flags,
            hashmap,
        })
    }

    /// Check if this is a request advertisement
    pub fn is_request(&self) -> bool {
        self.request_id.is_some() && self.flags.is_request
    }

    /// Check if this is a response advertisement
    pub fn is_response(&self) -> bool {
        self.request_id.is_some() && self.flags.is_response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advertisement_pack_unpack() {
        let adv = ResourceAdvertisement {
            transfer_size: 1024,
            data_size: 2048,
            num_parts: 5,
            hash: [1u8; 32],
            random_hash: [2u8; RANDOM_HASH_SIZE],
            original_hash: [3u8; 32],
            segment_index: 1,
            total_segments: 1,
            request_id: None,
            flags: ResourceFlags::default(),
            hashmap: vec![0u8; 20],
        };

        let packed = adv.pack(0).expect("pack advertisement");
        let unpacked = ResourceAdvertisement::unpack(&packed).expect("unpack advertisement");

        assert_eq!(adv.transfer_size, unpacked.transfer_size);
        assert_eq!(adv.data_size, unpacked.data_size);
        assert_eq!(adv.num_parts, unpacked.num_parts);
        assert_eq!(adv.hash, unpacked.hash);
        assert_eq!(adv.segment_index, unpacked.segment_index);
    }

    #[test]
    fn test_advertisement_with_request_id() {
        let adv = ResourceAdvertisement {
            transfer_size: 1024,
            data_size: 2048,
            num_parts: 5,
            hash: [1u8; 32],
            random_hash: [2u8; RANDOM_HASH_SIZE],
            original_hash: [3u8; 32],
            segment_index: 1,
            total_segments: 1,
            request_id: Some([0xAB; 16]),
            flags: ResourceFlags {
                is_request: true,
                ..ResourceFlags::default()
            },
            hashmap: vec![0u8; 20],
        };

        let packed = adv.pack(0).expect("pack advertisement");
        let unpacked = ResourceAdvertisement::unpack(&packed).expect("unpack advertisement");

        assert_eq!(adv.request_id, unpacked.request_id);
        assert!(unpacked.is_request());
        assert!(!unpacked.is_response());
    }

    #[test]
    fn test_advertisement_segment_handling() {
        // Create an advertisement with a larger hashmap
        let hashmap_size = ResourceAdvertisement::HASHMAP_MAX_LEN * MAPHASH_LEN * 2;
        let adv = ResourceAdvertisement {
            transfer_size: 1024,
            data_size: 2048,
            num_parts: 100,
            hash: [1u8; 32],
            random_hash: [2u8; RANDOM_HASH_SIZE],
            original_hash: [3u8; 32],
            segment_index: 1,
            total_segments: 2,
            request_id: None,
            flags: ResourceFlags::default(),
            hashmap: vec![0xAB; hashmap_size],
        };

        // Pack segment 0
        let packed0 = adv.pack(0).expect("pack segment 0");
        let unpacked0 = ResourceAdvertisement::unpack(&packed0).expect("unpack segment 0");

        // The unpacked hashmap should be the first segment only
        assert!(unpacked0.hashmap.len() <= ResourceAdvertisement::HASHMAP_MAX_LEN * MAPHASH_LEN);

        // Pack segment 1
        let packed1 = adv.pack(1).expect("pack segment 1");
        let unpacked1 = ResourceAdvertisement::unpack(&packed1).expect("unpack segment 1");

        // Both segments should have hashmap data
        assert!(!unpacked0.hashmap.is_empty());
        assert!(!unpacked1.hashmap.is_empty());
    }

    #[test]
    fn test_constants() {
        // Verify constants are reasonable
        assert!(ResourceAdvertisement::OVERHEAD > 0);
        assert!(ResourceAdvertisement::HASHMAP_MAX_LEN > 0);
        assert!(ResourceAdvertisement::COLLISION_GUARD_SIZE > ResourceAdvertisement::HASHMAP_MAX_LEN);
    }
}
