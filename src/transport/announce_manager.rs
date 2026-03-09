//! Announce management for the transport layer.
//!
//! This module provides a unified interface for announce processing,
//! rate limiting, caching, and retransmission. It combines:
//! - AnnounceTable for storing announces pending retransmission
//! - AnnounceLimits for rate limiting to prevent announce floods
//! - Event distribution for notifying listeners of new announces

use std::time::Duration;

use tokio::sync::broadcast;

use crate::hash::AddressHash;
use crate::packet::Packet;

use super::announce_limits::{AnnounceLimits, AnnounceRateLimit, RateInfo};
use super::announce_table::AnnounceTable;
use super::AnnounceEvent;

/// Unified announce manager combining caching, rate limiting, and events.
///
/// AnnounceManager is responsible for:
/// - Rate limiting announces to prevent floods
/// - Caching announces for retransmission
/// - Distributing announce events to subscribers
pub struct AnnounceManager {
    /// Cache of announces pending retransmission
    table: AnnounceTable,
    /// Rate limiter for announce floods
    limits: AnnounceLimits,
    /// Event sender for announce notifications
    event_tx: broadcast::Sender<AnnounceEvent>,
}

impl AnnounceManager {
    /// Create a new AnnounceManager with the given event channel.
    pub fn new(event_tx: broadcast::Sender<AnnounceEvent>) -> Self {
        Self {
            table: AnnounceTable::new(),
            limits: AnnounceLimits::new(),
            event_tx,
        }
    }

    // =========================================================================
    // Rate Limiting
    // =========================================================================

    /// Check and record an announce for rate limiting.
    ///
    /// Returns the block duration if the announce is rate limited,
    /// or None if it should be processed normally.
    /// When `rate_limit` is `None`, no rate limiting applies (matching Python
    /// behavior for interfaces without `announce_rate_target`).
    pub fn check_rate_limit(
        &mut self,
        destination: &AddressHash,
        rate_limit: Option<AnnounceRateLimit>,
    ) -> Option<Duration> {
        self.limits.check(destination, rate_limit)
    }

    /// Get rate information for all tracked destinations.
    pub fn get_rate_table(&self) -> Vec<RateInfo> {
        self.limits.get_rate_table()
    }

    /// Get rate information for a specific destination.
    pub fn get_rate_info(&self, destination: &AddressHash) -> Option<RateInfo> {
        self.limits.get_rate_info(destination)
    }

    // =========================================================================
    // Announce Caching
    // =========================================================================

    /// Add an announce to the cache for potential retransmission.
    ///
    /// # Arguments
    /// * `announce` - The announce packet
    /// * `destination` - The destination hash from the announce
    /// * `received_from` - The interface/transport that sent this announce
    /// * `from_local_client` - True if announce came from a local IPC client
    pub fn add(
        &mut self,
        announce: &Packet,
        destination: AddressHash,
        received_from: AddressHash,
        from_local_client: bool,
    ) {
        self.table.add(announce, destination, received_from, from_local_client)
    }

    /// Get the cached announce packet for a destination, if available.
    ///
    /// Used for path responses to retrieve the announce to retransmit.
    pub fn get_announce_packet(&self, destination: &AddressHash) -> Option<&Packet> {
        self.table.get_announce_packet(destination)
    }

    /// Schedule a path response via the announce table with a grace period.
    ///
    /// The retransmit loop will pick this up after the grace period expires,
    /// allowing closer/directly-reachable peers to answer first.
    pub fn add_path_response(
        &mut self,
        packet: &Packet,
        destination: AddressHash,
        exclude_interface: AddressHash,
        hops: u8,
        grace: Duration,
    ) {
        self.table.add_path_response(packet, destination, exclude_interface, hops, grace)
    }

    /// Get a retransmit packet for a specific destination.
    ///
    /// Returns (received_from, packet) if a retransmit is ready.
    pub fn new_packet(
        &mut self,
        dest_hash: &AddressHash,
        transport_id: &AddressHash,
    ) -> Option<(AddressHash, Packet)> {
        self.table.new_packet(dest_hash, transport_id)
    }

    /// Get all announces that need retransmission.
    ///
    /// Returns a list of (received_from, packet) pairs.
    /// Announces that have exhausted their retries are removed from the cache.
    pub fn to_retransmit(&mut self, transport_id: &AddressHash) -> Vec<(AddressHash, Packet)> {
        self.table.to_retransmit(transport_id)
    }

    /// Clear all cached announces.
    pub fn clear(&mut self) {
        self.table.clear()
    }

    // =========================================================================
    // Event Distribution
    // =========================================================================

    /// Subscribe to announce events.
    pub fn subscribe(&self) -> broadcast::Receiver<AnnounceEvent> {
        self.event_tx.subscribe()
    }

    /// Emit an announce event to all subscribers.
    ///
    /// Returns Ok(num_receivers) on success, or Err (boxed) if no receivers.
    pub fn emit(&self, event: AnnounceEvent) -> Result<usize, Box<broadcast::error::SendError<AnnounceEvent>>> {
        let result = self.event_tx.send(event);
        match &result {
            Ok(count) => {
                log::debug!(
                    "announce_manager: emit sent to {} subscribers",
                    count
                );
            }
            Err(_) => {
                log::debug!(
                    "announce_manager: emit failed - no subscribers"
                );
            }
        }
        result.map_err(Box::new)
    }

    /// Get a clone of the event sender for passing to other components.
    pub fn event_sender(&self) -> broadcast::Sender<AnnounceEvent> {
        self.event_tx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_address_hash() -> AddressHash {
        AddressHash::new_from_slice(&[0u8; 16])
    }

    #[test]
    fn test_announce_manager_new() {
        let (tx, _rx) = broadcast::channel(16);
        let manager = AnnounceManager::new(tx);

        // Rate table should be empty initially
        assert!(manager.get_rate_table().is_empty());
    }

    #[test]
    fn test_rate_limit_tracking() {
        let (tx, _rx) = broadcast::channel(16);
        let mut manager = AnnounceManager::new(tx);
        let dest = zero_address_hash();

        // First check should not be rate limited (no rate limit configured)
        assert!(manager.check_rate_limit(&dest, None).is_none());

        // Should now have rate info
        let info = manager.get_rate_info(&dest);
        assert!(info.is_some());
    }

    #[test]
    fn test_clear() {
        let (tx, _rx) = broadcast::channel(16);
        let mut manager = AnnounceManager::new(tx);

        // Clear should work on empty manager
        manager.clear();
    }

    #[test]
    fn test_subscribe() {
        let (tx, _rx) = broadcast::channel(16);
        let manager = AnnounceManager::new(tx);

        // Should be able to subscribe
        let _receiver = manager.subscribe();
    }
}
