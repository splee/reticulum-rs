//! Reverse path table for storing packet hashes used to return proofs and replies.
//!
//! The reverse table maps packet hashes to their source interface, allowing
//! responses (like proofs) to be routed back to the original sender.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::hash::Hash;

/// Default expiry time for reverse table entries
pub const REVERSE_TABLE_EXPIRY: Duration = Duration::from_secs(300); // 5 minutes

/// Maximum entries in reverse table before cleanup
pub const REVERSE_TABLE_MAX_ENTRIES: usize = 50000;

/// Entry in the reverse path table
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    /// Timestamp when entry was created
    pub timestamp: Instant,
    /// Source receiving interface hash
    pub receiving_interface: AddressHash,
    /// Original packet hash
    pub packet_hash: Hash,
    /// Hops count from original packet
    pub hops: u8,
}

impl ReverseEntry {
    /// Create a new reverse entry
    pub fn new(receiving_interface: AddressHash, packet_hash: Hash, hops: u8) -> Self {
        Self {
            timestamp: Instant::now(),
            receiving_interface,
            packet_hash,
            hops,
        }
    }

    /// Check if entry has expired
    pub fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > REVERSE_TABLE_EXPIRY
    }
}

/// Reverse path table for tracking packet origins
#[derive(Debug, Default)]
pub struct ReverseTable {
    /// Map of packet hash -> reverse entry
    entries: HashMap<Hash, ReverseEntry>,
}

impl ReverseTable {
    /// Create a new empty reverse table
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert a new entry into the reverse table
    pub fn insert(&mut self, packet_hash: Hash, receiving_interface: AddressHash, hops: u8) {
        // Clean up if table is too large
        if self.entries.len() >= REVERSE_TABLE_MAX_ENTRIES {
            self.cleanup();
        }

        let entry = ReverseEntry::new(receiving_interface, packet_hash.clone(), hops);
        self.entries.insert(packet_hash, entry);
    }

    /// Look up an entry by packet hash
    pub fn get(&self, packet_hash: &Hash) -> Option<&ReverseEntry> {
        self.entries.get(packet_hash).filter(|e| !e.is_expired())
    }

    /// Remove an entry
    pub fn remove(&mut self, packet_hash: &Hash) -> Option<ReverseEntry> {
        self.entries.remove(packet_hash)
    }

    /// Check if an entry exists
    pub fn contains(&self, packet_hash: &Hash) -> bool {
        self.get(packet_hash).is_some()
    }

    /// Get the receiving interface for a packet hash
    pub fn receiving_interface(&self, packet_hash: &Hash) -> Option<AddressHash> {
        self.get(packet_hash).map(|e| e.receiving_interface.clone())
    }

    /// Clean up expired entries
    pub fn cleanup(&mut self) {
        self.entries.retain(|_, entry| !entry.is_expired());
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_table_insert_get() {
        let mut table = ReverseTable::new();

        let packet_hash = Hash::new([1u8; 32]);
        let iface_hash = AddressHash::new_from_slice(&[2u8; 32]);

        table.insert(packet_hash.clone(), iface_hash.clone(), 2);

        let entry = table.get(&packet_hash).expect("entry should exist");
        assert_eq!(entry.hops, 2);
        assert_eq!(entry.receiving_interface.as_slice(), iface_hash.as_slice());
    }

    #[test]
    fn test_reverse_table_remove() {
        let mut table = ReverseTable::new();
        let packet_hash = Hash::new([1u8; 32]);
        let iface_hash = AddressHash::new_from_slice(&[2u8; 32]);

        table.insert(packet_hash.clone(), iface_hash, 0);
        assert!(table.contains(&packet_hash));

        table.remove(&packet_hash);
        assert!(!table.contains(&packet_hash));
    }

    #[test]
    fn test_reverse_table_cleanup() {
        let mut table = ReverseTable::new();
        let packet_hash = Hash::new([1u8; 32]);
        let iface_hash = AddressHash::new_from_slice(&[2u8; 32]);

        table.insert(packet_hash.clone(), iface_hash, 0);
        assert_eq!(table.len(), 1);

        table.cleanup();
        // Entry shouldn't be expired yet
        assert_eq!(table.len(), 1);
    }
}
