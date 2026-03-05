//! Path management for the transport layer.
//!
//! This module provides a unified interface for path discovery, routing,
//! and path request deduplication. It combines the PathTable (for route storage)
//! with PathRequestTagCache (for deduplication) into a single coherent component.

use crate::hash::AddressHash;
use crate::iface::stats::InterfaceMode;
use crate::packet::Packet;

use super::path_request::PathRequestTagCache;
use super::path_table::{PathInfo, PathTable};

/// Unified path manager combining routing table and request deduplication.
///
/// PathManager is responsible for:
/// - Storing and querying routes to destinations (via PathTable)
/// - Deduplicating path requests (via PathRequestTagCache)
/// - Handling announce-based path updates
/// - Routing packets to their next hop
pub struct PathManager {
    /// Path table storing routes to destinations
    table: PathTable,
    /// Cache for deduplicating path requests
    request_tags: PathRequestTagCache,
}

impl PathManager {
    /// Create a new PathManager with empty routing table and request cache.
    pub fn new() -> Self {
        Self {
            table: PathTable::new(),
            request_tags: PathRequestTagCache::new(),
        }
    }

    // =========================================================================
    // Path Query Methods
    // =========================================================================

    /// Get the cached announce packet for a destination, if the path is still valid.
    ///
    /// Used for path responses — the announce packet persists in the path table
    /// for the lifetime of the path, unlike the announce_table which evicts entries
    /// after retransmission (~5-6s).
    pub fn get_announce_packet(&self, destination: &AddressHash) -> Option<&Packet> {
        self.table.get_announce_packet(destination)
    }

    /// Check if a path to the destination exists and is not expired.
    pub fn has_path(&self, destination: &AddressHash) -> bool {
        self.table.has_path(destination)
    }

    /// Get the number of hops to a destination, if path exists.
    pub fn hops_to(&self, destination: &AddressHash) -> Option<u8> {
        self.table.hops_to(destination)
    }

    /// Get the number of hops to a destination, or PATHFINDER_M (128) if unknown.
    pub fn hops_to_or_max(&self, destination: &AddressHash) -> u8 {
        self.table.hops_to_or_max(destination)
    }

    /// Mark a destination's path state as Unknown.
    pub fn mark_path_unknown_state(&mut self, dest: &AddressHash) -> bool {
        self.table.mark_path_unknown_state(dest)
    }

    /// Mark a destination's path state as Unresponsive.
    pub fn mark_path_unresponsive(&mut self, dest: &AddressHash) -> bool {
        self.table.mark_path_unresponsive(dest)
    }

    /// Mark a destination's path state as Responsive.
    pub fn mark_path_responsive(&mut self, dest: &AddressHash) -> bool {
        self.table.mark_path_responsive(dest)
    }

    /// Check if a destination's path is in Unresponsive state.
    pub fn path_is_unresponsive(&self, dest: &AddressHash) -> bool {
        self.table.path_is_unresponsive(dest)
    }

    /// Get the next hop address for a destination.
    pub fn next_hop(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.table.next_hop(destination)
    }

    /// Get the interface hash for the next hop.
    pub fn next_hop_iface(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.table.next_hop_iface(destination)
    }

    /// Get both next hop and interface for a destination.
    pub fn next_hop_full(&self, destination: &AddressHash) -> Option<(AddressHash, AddressHash)> {
        self.table.next_hop_full(destination)
    }

    /// Get all paths, optionally filtered by maximum hop count.
    pub fn get_paths(&self, max_hops: Option<u8>) -> Vec<PathInfo> {
        self.table.get_paths(max_hops)
    }

    /// Get the number of entries in the path table.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Check if the path table is empty.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    // =========================================================================
    // Path Modification Methods
    // =========================================================================

    /// Drop a specific path from the table.
    /// Returns true if the path existed and was removed.
    pub fn drop_path(&mut self, destination: &AddressHash) -> bool {
        self.table.drop_path(destination)
    }

    /// Drop all paths that route through a specific transport instance.
    /// Returns the number of paths dropped.
    pub fn drop_via(&mut self, transport_hash: &AddressHash) -> usize {
        self.table.drop_via(transport_hash)
    }

    /// Refresh the timestamp of an existing path entry.
    pub fn refresh(&mut self, destination: &AddressHash) {
        self.table.refresh(destination)
    }

    /// Remove expired path entries.
    /// Returns the number of entries removed.
    pub fn cleanup_expired(&mut self) -> usize {
        self.table.cleanup_expired()
    }

    // =========================================================================
    // Packet Handling Methods
    // =========================================================================

    /// Handle an outbound packet, adding routing headers if needed.
    ///
    /// Returns the (possibly modified) packet and the interface to send on,
    /// or None if no path is known.
    pub fn handle_packet(&self, packet: &Packet) -> (Packet, Option<AddressHash>) {
        self.table.handle_packet(packet)
    }

    /// Handle an inbound packet for forwarding.
    ///
    /// Looks up the next hop and modifies headers appropriately.
    /// If `lookup` is provided, uses that address instead of packet destination.
    pub fn handle_inbound_packet(
        &self,
        packet: &Packet,
        lookup: Option<AddressHash>,
    ) -> (Packet, Option<AddressHash>) {
        self.table.handle_inbound_packet(packet, lookup)
    }

    /// Process an announce packet and update the path table.
    ///
    /// The `iface_mode` parameter determines the path expiry duration:
    /// - AccessPoint: 1 day
    /// - Roaming: 6 hours
    /// - Full/others: 1 week
    ///
    /// Returns true if the path was updated, false if the announce was rejected.
    pub fn handle_announce(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
        iface_mode: InterfaceMode,
    ) -> bool {
        self.table.handle_announce(announce, transport_id, iface, iface_mode)
    }

    // =========================================================================
    // Path Request Deduplication
    // =========================================================================

    /// Check if a path request tag has been seen before.
    ///
    /// The unique_tag is a 32-byte value: destination_hash(16) + request_tag(16).
    pub fn has_seen_request(&self, unique_tag: &[u8; 32]) -> bool {
        self.request_tags.contains(unique_tag)
    }

    /// Mark a path request tag as seen to prevent duplicate processing.
    ///
    /// Uses FIFO eviction when cache is full.
    pub fn mark_request_seen(&mut self, unique_tag: [u8; 32]) {
        self.request_tags.insert(unique_tag)
    }

    /// Get the number of cached path request tags.
    pub fn request_tag_count(&self) -> usize {
        self.request_tags.len()
    }
}

impl Default for PathManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_address_hash() -> AddressHash {
        AddressHash::new_from_slice(&[0u8; 16])
    }

    #[test]
    fn test_path_manager_new() {
        let pm = PathManager::new();
        assert!(pm.is_empty());
        assert_eq!(pm.len(), 0);
        assert_eq!(pm.request_tag_count(), 0);
    }

    #[test]
    fn test_request_tag_deduplication() {
        let mut pm = PathManager::new();
        let tag = [0u8; 32];

        assert!(!pm.has_seen_request(&tag));
        pm.mark_request_seen(tag);
        assert!(pm.has_seen_request(&tag));
        assert_eq!(pm.request_tag_count(), 1);

        // Inserting same tag again shouldn't increase count
        pm.mark_request_seen(tag);
        assert_eq!(pm.request_tag_count(), 1);
    }

    #[test]
    fn test_path_queries_delegate_to_table() {
        let pm = PathManager::new();
        let dest = zero_address_hash();

        // All queries should work on empty table
        assert!(!pm.has_path(&dest));
        assert!(pm.hops_to(&dest).is_none());
        assert!(pm.next_hop(&dest).is_none());
        assert!(pm.next_hop_iface(&dest).is_none());
        assert!(pm.next_hop_full(&dest).is_none());
        assert!(pm.get_paths(None).is_empty());
    }
}
