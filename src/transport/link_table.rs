use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::destination::link::LinkId;
use crate::destination::link_watchdog::ESTABLISHMENT_TIMEOUT_PER_HOP;
use crate::hash::AddressHash;
use crate::packet::{Header, Packet, RETICULUM_MTU};

/// Timeout for validated link table entries.
/// Matches Python Transport.LINK_TIMEOUT = Link.STALE_TIME * 1.25
/// = (KEEPALIVE_MAX * STALE_FACTOR) * 1.25 = (360 * 2) * 1.25 = 900s
const LINK_TIMEOUT: Duration = Duration::from_secs(900);

/// Extra proof timeout based on interface bitrate, matching Python's
/// Transport.extra_link_proof_timeout(). Accounts for transmission
/// time of one MTU-sized packet on slow links.
fn extra_link_proof_timeout(bitrate: Option<u64>) -> Duration {
    match bitrate {
        Some(bps) if bps > 0 => {
            let secs = (8.0 / bps as f64) * RETICULUM_MTU as f64;
            Duration::from_secs_f64(secs)
        }
        _ => Duration::ZERO,
    }
}

pub struct LinkEntry {
    #[allow(dead_code)]
    pub timestamp: Instant,
    pub proof_timeout: Instant,
    #[allow(dead_code)] // Python parity: routing field used in multihop forwarding
    pub next_hop: AddressHash,
    #[allow(dead_code)]
    pub next_hop_iface: AddressHash,
    pub received_from: AddressHash,
    pub original_destination: AddressHash,
    #[allow(dead_code)] // Python parity: routing field used in multihop forwarding
    pub taken_hops: u8,
    pub remaining_hops: u8,
    pub validated: bool,
}

/// Route a packet backward through the link (toward the link initiator).
///
/// Matches Python Transport.py lines 2035-2037 and 1545-1547: the packet's
/// raw flags byte (header type, transport type, etc.) is preserved as-is.
/// Only the hop count is incremented.  The link table provides routing
/// information (received_from interface), so no transport header
/// manipulation is needed.
fn send_backwards(packet: &Packet, entry: &LinkEntry) -> (Packet, AddressHash) {
    let propagated = Packet {
        header: Header {
            ifac_flag: packet.header.ifac_flag,
            header_type: packet.header.header_type,
            context_flag: packet.header.context_flag,
            transport_type: packet.header.transport_type,
            destination_type: packet.header.destination_type,
            packet_type: packet.header.packet_type,
            hops: packet.header.hops + 1,
        },
        ifac: None,
        destination: packet.destination,
        transport: packet.transport,
        context: packet.context,
        data: packet.data,
        ratchet_id: None,
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
        remaining_hops: u8,
        receiving_iface_bitrate: Option<u64>,
    ) {
        let link_id = LinkId::from(link_request);

        if self.0.contains_key(&link_id) {
            return;
        }

        let now = Instant::now();
        let taken_hops = link_request.header.hops + 1;

        // Compute proof timeout dynamically based on remaining hops and interface
        // bitrate, matching Python Transport.py lines 1454-1456.
        let effective_hops = (remaining_hops as f64).max(1.0);
        let base_timeout = Duration::from_secs_f64(ESTABLISHMENT_TIMEOUT_PER_HOP * effective_hops);
        let extra = extra_link_proof_timeout(receiving_iface_bitrate);

        let entry = LinkEntry {
            timestamp: now,
            proof_timeout: now + base_timeout + extra,
            next_hop,
            next_hop_iface: iface,
            received_from,
            original_destination: destination,
            taken_hops,
            remaining_hops,
            validated: false,
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
                if now >= entry.timestamp + LINK_TIMEOUT {
                    stale.push(*link_id);
                }
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
        DestinationType, HeaderType, IfacFlag, PacketContext, PacketDataBuffer, PacketType,
        TransportType,
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
                context_flag: false,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::LinkRequest,
                hops,
            },
            ifac: None,
            destination: test_address_hash(1),
            transport: None,
            context: PacketContext::None,
            data,
            ratchet_id: None,
        }
    }

    /// Create a proof packet for testing.
    fn test_proof_packet(hops: u8, link_id: LinkId) -> Packet {
        Packet {
            header: Header {
                ifac_flag: IfacFlag::Authenticated,
                header_type: HeaderType::Type2,
                context_flag: false,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                hops,
            },
            ifac: None,
            destination: link_id,
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new(),
            ratchet_id: None,
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

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);

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
        table.add(&link_request, destination1, received_from, next_hop, iface, 0, None);
        // Try to add duplicate with different destination
        table.add(&link_request, destination2, received_from, next_hop, iface, 0, None);

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

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);

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

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);

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

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);

        let link_id = LinkId::from(&link_request);
        let proof = test_proof_packet(3, link_id);

        let result = table.handle_proof(&proof);
        assert!(result.is_some());

        let (backward_packet, to_iface) = result.unwrap();

        // Check backward routing goes to received_from interface
        assert_eq!(to_iface, received_from);
        // Original packet fields are preserved (Python passes raw bytes through)
        assert_eq!(backward_packet.header.header_type, HeaderType::Type2);
        assert_eq!(backward_packet.transport, None); // preserved from proof packet
        // Hops should be incremented
        assert_eq!(backward_packet.header.hops, 4); // proof hops (3) + 1
    }

    /// Verify that send_backwards preserves the original packet's header type
    /// and transport field, matching Python Transport.py lines 2035-2037 where
    /// raw[0:1] (flags byte) is passed through unchanged.
    #[test]
    fn test_send_backwards_preserves_header_type() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x77);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);
        let link_id = LinkId::from(&link_request);

        // Validate the link first
        let proof = test_proof_packet(1, link_id);
        table.handle_proof(&proof);

        // Create a Type1 keepalive (as link traffic typically arrives)
        let type1_keepalive = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                hops: 2,
            },
            ifac: None,
            destination: link_id,
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new(),
            ratchet_id: None,
        };

        let result = table.handle_keepalive(&type1_keepalive);
        assert!(result.is_some());
        let (backward, to_iface) = result.unwrap();

        // Header type preserved as Type1 (not wrapped to Type2)
        assert_eq!(backward.header.header_type, HeaderType::Type1);
        assert_eq!(backward.header.transport_type, TransportType::Broadcast);
        assert_eq!(backward.transport, None);
        assert_eq!(backward.header.hops, 3);
        assert_eq!(to_iface, received_from);
    }

    #[test]
    fn test_handle_keepalive() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x22);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);

        let link_id = LinkId::from(&link_request);

        // Create a keepalive packet (same structure as proof but different usage)
        let keepalive = test_proof_packet(2, link_id);

        let result = table.handle_keepalive(&keepalive);
        assert!(result.is_some());

        let (backward_packet, to_iface) = result.unwrap();
        assert_eq!(to_iface, received_from);
        // Original packet fields preserved — transport was None in the proof packet
        assert_eq!(backward_packet.transport, None);
        assert_eq!(backward_packet.header.header_type, HeaderType::Type2);
    }

    #[test]
    fn test_remove_stale_removes_unvalidated_expired() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x33);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);

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
    fn test_remove_stale_keeps_unexpired_validated() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x44);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);

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

        // Entry should NOT be removed (validated and LINK_TIMEOUT has not elapsed)
        assert_eq!(table.0.len(), 1);
    }

    #[test]
    fn test_remove_stale_removes_expired_validated() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x45);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);

        // Validate the entry
        let link_id = LinkId::from(&link_request);
        let proof = test_proof_packet(1, link_id);
        table.handle_proof(&proof);

        // Force the timestamp far enough in the past to exceed LINK_TIMEOUT (900s)
        if let Some(entry) = table.0.get_mut(&link_id) {
            entry.timestamp = Instant::now() - Duration::from_secs(901);
        }

        assert_eq!(table.0.len(), 1);

        table.remove_stale();

        // Entry should be removed (validated but LINK_TIMEOUT exceeded)
        assert!(table.0.is_empty());
    }

    #[test]
    fn test_remove_stale_keeps_unexpired_unvalidated() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0x55);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);

        // Entry is unvalidated but timeout is in future (6s with 0 remaining hops)
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

        table.add(&link_request, destination, received_from, next_hop, iface, 0, None);

        let link_id = LinkId::from(&link_request);
        let entry = table.0.get(&link_id).unwrap();

        // taken_hops = packet.header.hops + 1
        assert_eq!(entry.taken_hops, 6);
    }

    #[test]
    fn test_proof_timeout_scales_with_hops() {
        let mut table = LinkTable::new();
        let link_request_1 = test_link_request_packet(0, 0xA1);
        let link_request_5 = test_link_request_packet(0, 0xA2);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        // 1 remaining hop → timeout = 6s * max(1,1) = 6s
        table.add(&link_request_1, destination, received_from, next_hop, iface, 1, None);
        // 5 remaining hops → timeout = 6s * max(1,5) = 30s
        table.add(&link_request_5, destination, received_from, next_hop, iface, 5, None);

        let id_1 = LinkId::from(&link_request_1);
        let id_5 = LinkId::from(&link_request_5);
        let entry_1 = table.0.get(&id_1).unwrap();
        let entry_5 = table.0.get(&id_5).unwrap();

        // The 5-hop entry should have a longer proof timeout
        assert!(entry_5.proof_timeout > entry_1.proof_timeout);
    }

    #[test]
    fn test_extra_link_proof_timeout_with_known_bitrate() {
        // 115200 bps serial link: extra = (8 / 115200) * 500 ≈ 0.03472s
        let extra = extra_link_proof_timeout(Some(115200));
        let expected_secs = (8.0 / 115200.0) * RETICULUM_MTU as f64;
        let diff = (extra.as_secs_f64() - expected_secs).abs();
        assert!(diff < 1e-9, "expected ~{} got {}", expected_secs, extra.as_secs_f64());

        // None bitrate → zero extra timeout
        assert_eq!(extra_link_proof_timeout(None), Duration::ZERO);

        // Zero bitrate → zero extra timeout (avoid division by zero)
        assert_eq!(extra_link_proof_timeout(Some(0)), Duration::ZERO);
    }

    #[test]
    fn test_remaining_hops_set_from_parameter() {
        let mut table = LinkTable::new();
        let link_request = test_link_request_packet(0, 0xA3);
        let destination = test_address_hash(10);
        let received_from = test_address_hash(20);
        let next_hop = test_address_hash(30);
        let iface = test_address_hash(40);

        table.add(&link_request, destination, received_from, next_hop, iface, 7, None);

        let link_id = LinkId::from(&link_request);
        let entry = table.0.get(&link_id).unwrap();

        // remaining_hops should be set from the parameter, not hardcoded to 0
        assert_eq!(entry.remaining_hops, 7);
    }
}
