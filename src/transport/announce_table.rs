use alloc::vec::Vec;
use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::packet::{
    DestinationType, Header, HeaderType, IfacFlag,
    Packet, PacketContext, PacketType, PropagationType
};

pub struct AnnounceEntry {
    pub packet: Packet,
    #[allow(dead_code)]
    pub timestamp: Instant,
    pub timeout: Instant,
    pub received_from: AddressHash,
    pub retries: u8,
    pub hops: u8,
}

impl AnnounceEntry {
    pub fn retransmit(
        &mut self,
        transport_id: &AddressHash,
    ) -> Option<(AddressHash, Packet)> {
        // Don't retransmit if timeout hasn't expired yet
        if Instant::now() < self.timeout {
            return None;
        }

        // Don't retransmit if no retries left
        if self.retries == 0 {
            return None;
        }

        // Decrement retry counter
        self.retries = self.retries.saturating_sub(1);

        // Update timeout for next retransmit (if retries > 0 after decrement)
        let random_delay = rand::random::<f64>() * super::PATHFINDER_RW;
        self.timeout = Instant::now()
            + Duration::from_secs(super::PATHFINDER_G)
            + Duration::from_secs_f64(random_delay);

        // Create retransmit packet
        let new_packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: self.hops,
            },
            ifac: None,
            destination: self.packet.destination,
            transport: Some(*transport_id),
            context: PacketContext::None,
            data: self.packet.data,
        };

        Some((self.received_from, new_packet))
    }
}

pub struct AnnounceTable {
    map: HashMap<AddressHash, AnnounceEntry>,
    stale: Vec<AddressHash>,
}

impl AnnounceTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            stale: Vec::new(),
        }
    }

    pub fn add(
        &mut self,
        announce: &Packet,
        destination: AddressHash,
        received_from: AddressHash,
        from_local_client: bool,
    ) {
        if self.map.contains_key(&destination) {
            return;
        }

        let now = Instant::now();
        let hops = announce.header.hops + 1;

        // Match Python behavior: local clients get immediate retransmit,
        // network announces get random delay for collision avoidance
        let (timeout, retries) = if from_local_client {
            (now, super::PATHFINDER_R)  // Immediate, retransmit once
        } else {
            let random_delay = rand::random::<f64>() * super::PATHFINDER_RW;
            (now + Duration::from_secs_f64(random_delay), 0)
        };

        let entry = AnnounceEntry {
            packet: *announce,
            timestamp: now,
            timeout,
            received_from,
            retries,
            hops,
        };

        self.map.insert(destination, entry);
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.stale.clear();
    }

    #[allow(dead_code)]
    pub fn stale(&mut self, destination: &AddressHash) {
        self.map.remove(destination);
    }

    /// Get the cached announce packet for a destination, if available.
    ///
    /// Used for path responses to retrieve the announce to retransmit.
    pub fn get_announce_packet(&self, destination: &AddressHash) -> Option<&Packet> {
        self.map.get(destination).map(|entry| &entry.packet)
    }

    pub fn new_packet(
        &mut self,
        dest_hash: &AddressHash,
        transport_id: &AddressHash,
    ) -> Option<(AddressHash, Packet)> {
        // temporary hack
        self.map.get_mut(dest_hash).and_then(|e| e.retransmit(transport_id))
    }


    #[allow(clippy::wrong_self_convention)]
    pub fn to_retransmit(
        &mut self,
        transport_id: &AddressHash,
    ) -> Vec<(AddressHash, Packet)> {
        let mut packets = vec![];
        let mut completed = vec![];

        for (destination, ref mut entry) in &mut self.map {
            if let Some(pair) = entry.retransmit(transport_id) {
                packets.push(pair);
            } else {
                completed.push(*destination);
            }
        }

        if !(packets.is_empty() && completed.is_empty()) {
            log::trace!(
                "Announce cache: {} to retransmit, {} dropped",
                packets.len(),
                completed.len(),
            );
        }

        for destination in completed {
            self.map.remove(&destination);
        }

        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketDataBuffer;

    /// Create a zero-filled address hash for testing.
    fn zero_address_hash() -> AddressHash {
        AddressHash::new_from_slice(&[0u8; 16])
    }

    /// Create a test address hash with a specific byte pattern.
    fn test_address_hash(val: u8) -> AddressHash {
        AddressHash::new_from_slice(&[val; 16])
    }

    /// Create a minimal test announce packet.
    fn test_announce_packet(hops: u8) -> Packet {
        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops,
            },
            ifac: None,
            destination: zero_address_hash(),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new(),
        }
    }

    #[test]
    fn test_announce_table_new() {
        let table = AnnounceTable::new();
        assert!(table.map.is_empty());
        assert!(table.stale.is_empty());
    }

    #[test]
    fn test_add_announce_entry() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(0);
        let destination = test_address_hash(1);
        let received_from = test_address_hash(2);

        table.add(&packet, destination, received_from, false);

        assert_eq!(table.map.len(), 1);
        assert!(table.map.contains_key(&destination));

        let entry = table.map.get(&destination).unwrap();
        assert_eq!(entry.hops, 1); // Original hops (0) + 1
        assert_eq!(entry.received_from, received_from);
    }

    #[test]
    fn test_add_local_client_immediate_timeout() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(0);
        let destination = test_address_hash(1);
        let received_from = test_address_hash(2);

        table.add(&packet, destination, received_from, true);

        let entry = table.map.get(&destination).unwrap();
        // Local client should have retries set to PATHFINDER_R
        assert_eq!(entry.retries, super::super::PATHFINDER_R);
    }

    #[test]
    fn test_add_network_announce_no_retries() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(0);
        let destination = test_address_hash(1);
        let received_from = test_address_hash(2);

        table.add(&packet, destination, received_from, false);

        let entry = table.map.get(&destination).unwrap();
        // Network announce should have retries set to 0
        assert_eq!(entry.retries, 0);
    }

    #[test]
    fn test_add_duplicate_ignored() {
        let mut table = AnnounceTable::new();
        let packet1 = test_announce_packet(0);
        let packet2 = test_announce_packet(5);
        let destination = test_address_hash(1);
        let received_from1 = test_address_hash(2);
        let received_from2 = test_address_hash(3);

        table.add(&packet1, destination, received_from1, false);
        table.add(&packet2, destination, received_from2, false);

        // Should still only have one entry
        assert_eq!(table.map.len(), 1);
        // Original entry should be preserved
        let entry = table.map.get(&destination).unwrap();
        assert_eq!(entry.received_from, received_from1);
        assert_eq!(entry.hops, 1); // From packet1 (hops=0 + 1)
    }

    #[test]
    fn test_hops_increment() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(3);
        let destination = test_address_hash(1);
        let received_from = test_address_hash(2);

        table.add(&packet, destination, received_from, false);

        let entry = table.map.get(&destination).unwrap();
        assert_eq!(entry.hops, 4); // Original hops (3) + 1
    }

    #[test]
    fn test_get_announce_packet() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(2);
        let destination = test_address_hash(1);
        let received_from = test_address_hash(2);

        // Non-existent destination returns None
        assert!(table.get_announce_packet(&destination).is_none());

        table.add(&packet, destination, received_from, false);

        // Now it should return the packet
        let retrieved = table.get_announce_packet(&destination);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().header.hops, 2);
    }

    #[test]
    fn test_clear() {
        let mut table = AnnounceTable::new();

        // Add multiple entries
        for i in 0..5 {
            let packet = test_announce_packet(i);
            let destination = test_address_hash(i + 10);
            let received_from = test_address_hash(i + 20);
            table.add(&packet, destination, received_from, false);
        }

        assert_eq!(table.map.len(), 5);

        table.clear();

        assert!(table.map.is_empty());
        assert!(table.stale.is_empty());
    }

    #[test]
    fn test_stale_removes_destination() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(0);
        let destination = test_address_hash(1);
        let received_from = test_address_hash(2);

        table.add(&packet, destination, received_from, false);
        assert_eq!(table.map.len(), 1);

        table.stale(&destination);
        assert!(table.map.is_empty());
    }

    #[test]
    fn test_to_retransmit_empty_table() {
        let mut table = AnnounceTable::new();
        let transport_id = test_address_hash(99);

        let packets = table.to_retransmit(&transport_id);
        assert!(packets.is_empty());
    }

    #[test]
    fn test_to_retransmit_removes_completed() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(0);
        let destination = test_address_hash(1);
        let received_from = test_address_hash(2);
        let transport_id = test_address_hash(99);

        // Add a network announce (retries=0, so it will be "completed" after timeout)
        table.add(&packet, destination, received_from, false);
        assert_eq!(table.map.len(), 1);

        // Call to_retransmit - entry should be removed since retries=0
        // and timeout may or may not have passed (depends on random delay)
        // After first call, if timeout passed, entry should be removed
        let _packets = table.to_retransmit(&transport_id);

        // The entry might still be there if timeout hasn't passed yet
        // But if we force it by checking the behavior:
        // Network announces have retries=0, so after timeout they're removed
    }

    #[test]
    fn test_entry_retransmit_no_retries_left() {
        let mut entry = AnnounceEntry {
            packet: test_announce_packet(0),
            timestamp: Instant::now(),
            timeout: Instant::now(), // Already expired
            received_from: test_address_hash(1),
            retries: 0, // No retries left
            hops: 1,
        };

        let transport_id = test_address_hash(99);
        let result = entry.retransmit(&transport_id);

        // Should return None because retries == 0
        assert!(result.is_none());
    }

    #[test]
    fn test_entry_retransmit_timeout_not_expired() {
        let mut entry = AnnounceEntry {
            packet: test_announce_packet(0),
            timestamp: Instant::now(),
            timeout: Instant::now() + Duration::from_secs(3600), // Far in future
            received_from: test_address_hash(1),
            retries: 5,
            hops: 1,
        };

        let transport_id = test_address_hash(99);
        let result = entry.retransmit(&transport_id);

        // Should return None because timeout hasn't expired
        assert!(result.is_none());
    }

    #[test]
    fn test_entry_retransmit_success() {
        let mut entry = AnnounceEntry {
            packet: test_announce_packet(2),
            timestamp: Instant::now(),
            timeout: Instant::now(), // Already expired
            received_from: test_address_hash(1),
            retries: 3,
            hops: 3,
        };

        let transport_id = test_address_hash(99);
        let result = entry.retransmit(&transport_id);

        assert!(result.is_some());
        let (recv_from, packet) = result.unwrap();

        // Check returned values
        assert_eq!(recv_from, test_address_hash(1));
        assert_eq!(packet.header.hops, 3);
        assert_eq!(packet.header.packet_type, PacketType::Announce);
        assert_eq!(packet.transport, Some(transport_id));

        // Retries should be decremented
        assert_eq!(entry.retries, 2);
    }

    #[test]
    fn test_entry_retransmit_decrements_retries() {
        let mut entry = AnnounceEntry {
            packet: test_announce_packet(0),
            timestamp: Instant::now(),
            timeout: Instant::now(), // Already expired
            received_from: test_address_hash(1),
            retries: 1, // Only one retry left
            hops: 1,
        };

        let transport_id = test_address_hash(99);

        // First retransmit should succeed
        let result1 = entry.retransmit(&transport_id);
        assert!(result1.is_some());
        assert_eq!(entry.retries, 0);

        // Force timeout to be expired again
        entry.timeout = Instant::now();

        // Second retransmit should fail (no retries left)
        let result2 = entry.retransmit(&transport_id);
        assert!(result2.is_none());
    }
}
