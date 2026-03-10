//! Link management for the transport layer.
//!
//! This module provides a unified interface for managing links, including:
//! - Outgoing links (we initiated the connection)
//! - Incoming links (they initiated the connection to us)
//! - Intermediate routing for multi-hop links (LinkTable)
//! - Link event distribution

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::broadcast;
use tokio::sync::Mutex;

use crate::destination::link::{LinkInner, LinkEventData, LinkId};
use crate::hash::AddressHash;
use crate::packet::Packet;

use super::link_table::LinkTable;

/// Unified link manager combining link storage and routing.
///
/// LinkManager is responsible for:
/// - Storing outgoing links we initiated
/// - Storing incoming links others initiated to us
/// - Intermediate routing state for multi-hop links
/// - Distributing link events to subscribers
pub struct LinkManager {
    /// Outgoing links (we initiated the connection)
    out_links: HashMap<AddressHash, Arc<Mutex<LinkInner>>>,
    /// Incoming links (they initiated to us)
    in_links: HashMap<AddressHash, Arc<Mutex<LinkInner>>>,
    /// Intermediate routing table for multi-hop links
    table: LinkTable,
    /// Event sender for incoming link notifications
    in_event_tx: broadcast::Sender<LinkEventData>,
}

impl LinkManager {
    /// Create a new LinkManager with the given event channel.
    pub fn new(in_event_tx: broadcast::Sender<LinkEventData>) -> Self {
        Self {
            out_links: HashMap::new(),
            in_links: HashMap::new(),
            table: LinkTable::new(),
            in_event_tx,
        }
    }

    // =========================================================================
    // Outgoing Links (we initiated)
    // =========================================================================

    /// Get an outgoing link by destination hash.
    pub(crate) fn get_out_link(&self, dest_hash: &AddressHash) -> Option<Arc<Mutex<LinkInner>>> {
        self.out_links.get(dest_hash).cloned()
    }

    /// Insert an outgoing link.
    pub(crate) fn insert_out_link(&mut self, dest_hash: AddressHash, link: Arc<Mutex<LinkInner>>) {
        self.out_links.insert(dest_hash, link);
    }

    /// Remove an outgoing link.
    pub(crate) fn remove_out_link(&mut self, dest_hash: &AddressHash) -> Option<Arc<Mutex<LinkInner>>> {
        self.out_links.remove(dest_hash)
    }

    /// Check if an outgoing link exists.
    pub fn has_out_link(&self, dest_hash: &AddressHash) -> bool {
        self.out_links.contains_key(dest_hash)
    }

    /// Get an iterator over all outgoing links.
    pub(crate) fn out_links(&self) -> impl Iterator<Item = (&AddressHash, &Arc<Mutex<LinkInner>>)> {
        self.out_links.iter()
    }

    /// Get all outgoing link values.
    pub(crate) fn out_link_values(&self) -> impl Iterator<Item = &Arc<Mutex<LinkInner>>> {
        self.out_links.values()
    }

    /// Get the number of outgoing links.
    pub fn out_links_len(&self) -> usize {
        self.out_links.len()
    }

    // =========================================================================
    // Incoming Links (they initiated)
    // =========================================================================

    /// Get an incoming link by link ID.
    pub(crate) fn get_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<LinkInner>>> {
        self.in_links.get(link_id).cloned()
    }

    /// Insert an incoming link.
    pub(crate) fn insert_in_link(&mut self, link_id: AddressHash, link: Arc<Mutex<LinkInner>>) {
        self.in_links.insert(link_id, link);
    }

    /// Remove an incoming link.
    pub(crate) fn remove_in_link(&mut self, link_id: &AddressHash) -> Option<Arc<Mutex<LinkInner>>> {
        self.in_links.remove(link_id)
    }

    /// Check if an incoming link exists.
    pub fn has_in_link(&self, link_id: &AddressHash) -> bool {
        self.in_links.contains_key(link_id)
    }

    /// Get an iterator over all incoming links.
    pub(crate) fn in_links(&self) -> impl Iterator<Item = (&AddressHash, &Arc<Mutex<LinkInner>>)> {
        self.in_links.iter()
    }

    /// Get all incoming link values.
    pub(crate) fn in_link_values(&self) -> impl Iterator<Item = &Arc<Mutex<LinkInner>>> {
        self.in_links.values()
    }

    /// Get the number of incoming links.
    pub fn in_links_len(&self) -> usize {
        self.in_links.len()
    }

    // =========================================================================
    // Link Table (intermediate routing)
    // =========================================================================

    /// Add an entry to the link table for intermediate routing.
    pub fn add_table_entry(
        &mut self,
        link_request: &Packet,
        destination: AddressHash,
        received_from: AddressHash,
        next_hop: AddressHash,
        iface: AddressHash,
        remaining_hops: u8,
        receiving_iface_bitrate: Option<u64>,
    ) {
        self.table.add(
            link_request,
            destination,
            received_from,
            next_hop,
            iface,
            remaining_hops,
            receiving_iface_bitrate,
        )
    }

    /// Get the original destination for a link (if validated).
    pub fn original_destination(&self, link_id: &LinkId) -> Option<AddressHash> {
        self.table.original_destination(link_id)
    }

    /// Handle a keepalive packet, returning the packet to forward if found.
    pub fn handle_keepalive(&self, packet: &Packet) -> Option<(Packet, AddressHash)> {
        self.table.handle_keepalive(packet)
    }

    /// Handle a proof packet, updating validation state and returning forward packet.
    pub fn handle_proof(&mut self, proof: &Packet) -> Option<(Packet, AddressHash)> {
        self.table.handle_proof(proof)
    }

    /// Remove stale entries from the link table.
    pub fn remove_stale(&mut self) {
        self.table.remove_stale()
    }

    // =========================================================================
    // Event Distribution
    // =========================================================================

    /// Subscribe to incoming link events.
    pub fn subscribe_in_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.in_event_tx.subscribe()
    }

    /// Get a clone of the incoming event sender.
    pub fn in_event_sender(&self) -> broadcast::Sender<LinkEventData> {
        self.in_event_tx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_address_hash() -> AddressHash {
        AddressHash::new_from_slice(&[0u8; 16])
    }

    #[test]
    fn test_link_manager_new() {
        let (tx, _rx) = broadcast::channel(16);
        let manager = LinkManager::new(tx);

        assert_eq!(manager.out_links_len(), 0);
        assert_eq!(manager.in_links_len(), 0);
    }

    #[test]
    fn test_out_link_operations() {
        let (tx, _rx) = broadcast::channel(16);
        let manager = LinkManager::new(tx);
        let dest = zero_address_hash();

        // Initially no link
        assert!(!manager.has_out_link(&dest));
        assert!(manager.get_out_link(&dest).is_none());
    }

    #[test]
    fn test_in_link_operations() {
        let (tx, _rx) = broadcast::channel(16);
        let mut manager = LinkManager::new(tx);
        let link_id = zero_address_hash();

        // Initially no link
        assert!(!manager.has_in_link(&link_id));
        assert!(manager.get_in_link(&link_id).is_none());
    }

    #[test]
    fn test_subscribe_events() {
        let (tx, _rx) = broadcast::channel(16);
        let manager = LinkManager::new(tx);

        // Should be able to subscribe
        let _receiver = manager.subscribe_in_events();
    }
}
