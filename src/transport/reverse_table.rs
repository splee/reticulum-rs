//! Reverse path table for routing proofs back to their origin.
//!
//! The reverse table maps truncated packet hashes (AddressHash) to the pair of
//! interfaces (receiving + outbound) involved in forwarding a packet.  When a
//! proof arrives on the outbound interface it is routed back via the receiving
//! interface.
//!
//! Matches Python Transport.py: REVERSE_TIMEOUT, reverse_table entries
//! `[receiving_interface, outbound_interface, timestamp]`, and the proof routing
//! logic in `Transport.inbound()`.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::hash::AddressHash;

/// Expiry time for reverse table entries — 8 minutes (matches Python REVERSE_TIMEOUT = 8*60).
pub const REVERSE_TABLE_EXPIRY: Duration = Duration::from_secs(480);

/// Maximum entries in reverse table before forced cleanup.
pub const REVERSE_TABLE_MAX_ENTRIES: usize = 50000;

/// Entry in the reverse path table.
///
/// Mirrors Python's `[receiving_interface, outbound_interface, timestamp]`.
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    /// Timestamp when entry was created.
    pub timestamp: Instant,
    /// Interface the packet was received on (where the proof should be sent back).
    pub receiving_interface: AddressHash,
    /// Interface the packet was forwarded out on (where the proof should arrive).
    pub outbound_interface: AddressHash,
}

impl ReverseEntry {
    /// Create a new reverse entry with the current timestamp.
    pub fn new(receiving_interface: AddressHash, outbound_interface: AddressHash) -> Self {
        Self {
            timestamp: Instant::now(),
            receiving_interface,
            outbound_interface,
        }
    }

    /// Check if entry has expired (older than REVERSE_TABLE_EXPIRY).
    pub fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > REVERSE_TABLE_EXPIRY
    }
}

/// Reverse path table for tracking packet forwarding paths.
///
/// Keyed by the truncated packet hash (AddressHash, 16 bytes) — matching Python's
/// `packet.getTruncatedHash()`.  Proof lookups use `packet.destination` which is
/// also an AddressHash.
#[derive(Debug, Default)]
pub struct ReverseTable {
    entries: HashMap<AddressHash, ReverseEntry>,
}

impl ReverseTable {
    /// Create a new empty reverse table.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert a new entry mapping a truncated packet hash to its interface pair.
    pub fn insert(
        &mut self,
        key: AddressHash,
        receiving_interface: AddressHash,
        outbound_interface: AddressHash,
    ) {
        // Clean up if table is too large
        if self.entries.len() >= REVERSE_TABLE_MAX_ENTRIES {
            self.cleanup();
        }

        let entry = ReverseEntry::new(receiving_interface, outbound_interface);
        self.entries.insert(key, entry);
    }

    /// Look up a non-expired entry by truncated packet hash.
    pub fn get(&self, key: &AddressHash) -> Option<&ReverseEntry> {
        self.entries.get(key).filter(|e| !e.is_expired())
    }

    /// Remove and return an entry.
    pub fn remove(&mut self, key: &AddressHash) -> Option<ReverseEntry> {
        self.entries.remove(key)
    }

    /// Check if a non-expired entry exists for the given key.
    pub fn contains(&self, key: &AddressHash) -> bool {
        self.get(key).is_some()
    }

    /// Get the receiving interface for a given key (if the entry exists and is not expired).
    pub fn receiving_interface(&self, key: &AddressHash) -> Option<AddressHash> {
        self.get(key).map(|e| e.receiving_interface)
    }

    /// Remove all expired entries (older than REVERSE_TABLE_EXPIRY = 480s).
    pub fn cleanup(&mut self) {
        self.entries.retain(|_, entry| !entry.is_expired());
    }

    /// Remove entries where either interface is no longer active.
    ///
    /// Matches Python Transport.py lines 606-615: stale entry cleanup
    /// checks that both interfaces in the reverse entry are still online.
    pub fn cleanup_stale_interfaces(&mut self, active_interfaces: &HashSet<AddressHash>) {
        self.entries.retain(|_, entry| {
            active_interfaces.contains(&entry.receiving_interface)
                && active_interfaces.contains(&entry.outbound_interface)
        });
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty.
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

        let key = AddressHash::new_from_slice(&[1u8; 32]);
        let receiving = AddressHash::new_from_slice(&[2u8; 32]);
        let outbound = AddressHash::new_from_slice(&[3u8; 32]);

        table.insert(key, receiving, outbound);

        let entry = table.get(&key).expect("entry should exist");
        assert_eq!(entry.receiving_interface, receiving);
        assert_eq!(entry.outbound_interface, outbound);
    }

    #[test]
    fn test_reverse_table_remove() {
        let mut table = ReverseTable::new();
        let key = AddressHash::new_from_slice(&[1u8; 32]);
        let receiving = AddressHash::new_from_slice(&[2u8; 32]);
        let outbound = AddressHash::new_from_slice(&[3u8; 32]);

        table.insert(key, receiving, outbound);
        assert!(table.contains(&key));

        let entry = table.remove(&key).expect("entry should exist");
        assert_eq!(entry.receiving_interface, receiving);
        assert_eq!(entry.outbound_interface, outbound);
        assert!(!table.contains(&key));
    }

    #[test]
    fn test_reverse_table_cleanup() {
        let mut table = ReverseTable::new();
        let key = AddressHash::new_from_slice(&[1u8; 32]);
        let receiving = AddressHash::new_from_slice(&[2u8; 32]);
        let outbound = AddressHash::new_from_slice(&[3u8; 32]);

        table.insert(key, receiving, outbound);
        assert_eq!(table.len(), 1);

        table.cleanup();
        // Entry shouldn't be expired yet (just created)
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_reverse_table_cleanup_stale_interfaces() {
        let mut table = ReverseTable::new();
        let key1 = AddressHash::new_from_slice(&[1u8; 32]);
        let key2 = AddressHash::new_from_slice(&[4u8; 32]);
        let receiving = AddressHash::new_from_slice(&[2u8; 32]);
        let outbound = AddressHash::new_from_slice(&[3u8; 32]);
        let stale_iface = AddressHash::new_from_slice(&[5u8; 32]);

        // Entry with both interfaces active
        table.insert(key1, receiving, outbound);
        // Entry with a stale outbound interface
        table.insert(key2, receiving, stale_iface);

        let mut active = HashSet::new();
        active.insert(receiving);
        active.insert(outbound);
        // stale_iface is NOT in active set

        table.cleanup_stale_interfaces(&active);

        assert!(table.contains(&key1), "entry with active interfaces should remain");
        assert!(!table.contains(&key2), "entry with stale interface should be removed");
    }

    #[test]
    fn test_reverse_table_expiry_timeout_is_480s() {
        // Verify the constant matches Python's REVERSE_TIMEOUT = 8*60
        assert_eq!(REVERSE_TABLE_EXPIRY, Duration::from_secs(480));
    }
}
