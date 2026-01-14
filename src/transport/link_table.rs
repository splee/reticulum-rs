use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::destination::link::LinkId;
use crate::hash::AddressHash;
use crate::packet::{Header, HeaderType, IfacFlag, Packet};

pub struct LinkEntry {
    #[allow(dead_code)]
    pub timestamp: Instant,
    pub proof_timeout: Instant,
    pub next_hop: AddressHash,
    #[allow(dead_code)]
    pub next_hop_iface: AddressHash,
    pub received_from: AddressHash,
    pub original_destination: AddressHash,
    #[allow(dead_code)]
    pub taken_hops: u8,
    pub remaining_hops: u8,
    pub validated: bool,
}

fn send_backwards(packet: &Packet, entry: &LinkEntry) -> (Packet, AddressHash) {
    let propagated = Packet {
        header: Header {
            ifac_flag: IfacFlag::Authenticated,
            header_type: HeaderType::Type2,
            propagation_type: packet.header.propagation_type,
            destination_type: packet.header.destination_type,
            packet_type: packet.header.packet_type,
            hops: packet.header.hops + 1,
        },
        ifac: None,
        destination: packet.destination,
        transport: Some(entry.next_hop),
        context: packet.context,
        data: packet.data,
    };

    (propagated, entry.received_from)
}

pub struct LinkTable(HashMap<LinkId, LinkEntry>);

impl LinkTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(
        &mut self,
        link_request: &Packet,
        destination: AddressHash,
        received_from: AddressHash,
        next_hop: AddressHash,
        iface: AddressHash,
    ) {
        let link_id = LinkId::from(link_request);

        if self.0.contains_key(&link_id) {
            return;
        }

        let now = Instant::now();
        let taken_hops = link_request.header.hops + 1;

        let entry = LinkEntry {
            timestamp: now,
            proof_timeout: now + Duration::from_secs(600), // TODO
            next_hop,
            next_hop_iface: iface,
            received_from,
            original_destination: destination,
            taken_hops,
            remaining_hops: 0,
            validated: false
        };

        self.0.insert(link_id, entry);
    }

    pub fn original_destination(&self, link_id: &LinkId) -> Option<AddressHash> {
        self.0.get(link_id).filter(|e| e.validated).map(|e| e.original_destination)
    }

    pub fn handle_keepalive(&self, packet: &Packet) -> Option<(Packet, AddressHash)> {
        self.0.get(&packet.destination).map(|entry| send_backwards(packet, entry))
    }

    pub fn handle_proof(&mut self, proof: &Packet) -> Option<(Packet, AddressHash)> {
        match self.0.get_mut(&proof.destination) {
            Some(entry) => {
                entry.remaining_hops = proof.header.hops;
                entry.validated = true;

                Some(send_backwards(proof, entry))
            },
            None => None
        }
    }

    pub fn remove_stale(&mut self) {
        let mut stale = vec![];
        let now = Instant::now();

        for (link_id, entry) in &self.0 {
            if entry.validated {
                // TODO remove active timed out links
            } else if entry.proof_timeout <= now {
                stale.push(*link_id);
            }
        }

        for link_id in stale {
            self.0.remove(&link_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        DestinationType, PacketContext, PacketDataBuffer, PacketType, PropagationType,
    };

    /// Create a test address hash with a specific byte pattern.
    fn test_address_hash(val: u8) -> AddressHash {
        AddressHash::new_from_slice(&[val; 16])
    }

    /// Create a minimal link request packet for testing.
    fn test_link_request_packet(hops: u8, data_byte: u8) -> Packet {
        // Create unique data to generate different LinkIds
        let data = PacketDataBuffer::new_from_slice(&[data_byte; 64]);

        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::LinkRequest,
                hops,
            },
            ifac: None,
            destination: test_address_hash(1),
            transport: None,
            context: PacketContext::None,
            data,
        }
    }

    /// Create a proof packet for testing.
    fn test_proof_packet(hops: u8, link_id: LinkId) -> Packet {
        Packet {
            header: Header {
                ifac_flag: IfacFlag::Authenticated,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                hops,
            },
            ifac: None,
            destination: link_id,
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new(),
        }
    }

    #[test]
    fn test_link_table_new() {
        let table = LinkTable::new();
        assert!(table.0.is_empty());
    }

    #[test]
    fn test_add_link_entry() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0xAA);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface);

        assert_eq!(table.0.len(), 1);

        let link_id = LinkId::from(&link_request);
        let entry = table.0.get(&link_id).unwrap();

        assert_eq!(entry.next_hop, next_hop);
        assert_eq!(entry.received_from, received_from);
        assert_eq!(entry.original_destination, destination);
        assert_eq!(entry.taken_hops, 1); // hops (0) + 1
        assert_eq!(entry.remaining_hops, 0);
        assert!(!entry.validated);
    }

    #[test]
    fn test_add_duplicate_ignored() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0xBB);
        let destination1 = test_address_hash(10);
        let destination2 = test_address_hash(99);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        // Add first entry
        table.add(&link_request, destination1, received_from, next_hop, iface);
        // Try to add duplicate with different destination
        table.add(&link_request, destination2, received_from, next_hop, iface);

        // Should still only have one entry
        assert_eq!(table.0.len(), 1);

        // Original destination should be preserved
        let link_id = LinkId::from(&link_request);
        let entry = table.0.get(&link_id).unwrap();
        assert_eq!(entry.original_destination, destination1);
    }

    #[test]
    fn test_original_destination_returns_none_when_unvalidated() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0xCC);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface);

        let link_id = LinkId::from(&link_request);

        // Should return None because entry is not validated
        assert!(table.original_destination(&link_id).is_none());
    }

    #[test]
    fn test_original_destination_returns_none_for_nonexistent() {
        let table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0xDD);
        let link_id = LinkId::from(&link_request);

        // Should return None for non-existent link
        assert!(table.original_destination(&link_id).is_none());
    }

    #[test]
    fn test_handle_proof_validates_link() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0xEE);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface);

        let link_id = LinkId::from(&link_request);
        let proof = test_proof_packet(5, link_id);

        // Before proof: not validated
        assert!(table.original_destination(&link_id).is_none());

        // Handle proof
        let result = table.handle_proof(&proof);
        assert!(result.is_some());

        // After proof: validated
        assert!(table.original_destination(&link_id).is_some());
        assert_eq!(table.original_destination(&link_id).unwrap(), destination);

        // Check remaining_hops was updated
        let entry = table.0.get(&link_id).unwrap();
        assert_eq!(entry.remaining_hops, 5);
        assert!(entry.validated);
    }

    #[test]
    fn test_handle_proof_returns_none_for_nonexistent() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0xFF);
        let link_id = LinkId::from(&link_request);
        let proof = test_proof_packet(5, link_id);

        // Should return None for non-existent link
        let result = table.handle_proof(&proof);
        assert!(result.is_none());
    }

    #[test]
    fn test_handle_proof_returns_backward_packet() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x11);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface);

        let link_id = LinkId::from(&link_request);
        let proof = test_proof_packet(3, link_id);

        let result = table.handle_proof(&proof);
        assert!(result.is_some());

        let (backward_packet, to_iface) = result.unwrap();

        // Check backward routing
        assert_eq!(to_iface, received_from);
        assert_eq!(backward_packet.transport, Some(next_hop));
        // Hops should be incremented
        assert_eq!(backward_packet.header.hops, 4); // proof hops (3) + 1
    }

    #[test]
    fn test_handle_keepalive() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x22);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface);

        let link_id = LinkId::from(&link_request);

        // Create a keepalive packet (same structure as proof but different usage)
        let keepalive = test_proof_packet(2, link_id);

        let result = table.handle_keepalive(&keepalive);
        assert!(result.is_some());

        let (backward_packet, to_iface) = result.unwrap();
        assert_eq!(to_iface, received_from);
        assert_eq!(backward_packet.transport, Some(next_hop));
    }

    #[test]
    fn test_remove_stale_removes_unvalidated_expired() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x33);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface);

        // Force the proof_timeout to be in the past
        let link_id = LinkId::from(&link_request);
        if let Some(entry) = table.0.get_mut(&link_id) {
            entry.proof_timeout = Instant::now() - Duration::from_secs(1);
        }

        assert_eq!(table.0.len(), 1);

        table.remove_stale();

        // Entry should be removed (unvalidated and expired)
        assert!(table.0.is_empty());
    }

    #[test]
    fn test_remove_stale_keeps_validated() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x44);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface);

        // Validate the entry
        let link_id = LinkId::from(&link_request);
        let proof = test_proof_packet(1, link_id);
        table.handle_proof(&proof);

        // Force the proof_timeout to be in the past
        if let Some(entry) = table.0.get_mut(&link_id) {
            entry.proof_timeout = Instant::now() - Duration::from_secs(1);
        }

        assert_eq!(table.0.len(), 1);

        table.remove_stale();

        // Entry should NOT be removed (it's validated)
        assert_eq!(table.0.len(), 1);
    }

    #[test]
    fn test_remove_stale_keeps_unexpired_unvalidated() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x55);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface);

        // Entry is unvalidated but timeout is in future (default 600s)
        assert_eq!(table.0.len(), 1);

        table.remove_stale();

        // Entry should NOT be removed (timeout not expired yet)
        assert_eq!(table.0.len(), 1);
    }

    #[test]
    fn test_taken_hops_calculation() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(5, 0x66); // 5 hops
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface);

        let link_id = LinkId::from(&link_request);
        let entry = table.0.get(&link_id).unwrap();

        // taken_hops = packet.header.hops + 1
        assert_eq!(entry.taken_hops, 6);
    }
}
