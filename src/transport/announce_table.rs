use alloc::vec::Vec;
use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::packet::{
    DestinationType, Header, HeaderType, IfacFlag,
    Packet, PacketContext, PacketType, TransportType
};

pub struct AnnounceEntry {
    pub packet: Packet,
    #[allow(dead_code)]
    pub timestamp: Instant,
    pub timeout: Instant,
    pub received_from: AddressHash,
    pub retries: u8,
    pub hops: u8,
    /// Context to use when retransmitting (e.g., PathResponse for path request answers)
    pub context: PacketContext,
}

impl AnnounceEntry {
    /// Returns true when this entry has exhausted all retransmit attempts
    /// and can be removed from the announce table.
    pub fn is_exhausted(&self) -> bool {
        self.retries == 0 && Instant::now() >= self.timeout
    }

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

        // Create retransmit packet.
        //
        // For announces, the header's context_flag indicates whether a ratchet
        // public key is embedded in the data — it must be preserved from the
        // original packet, NOT recomputed from the PacketContext field.
        // Overwriting it would cause announce validation failure on receivers
        // (they'd mis-parse the ratchet/signature boundary in the data).
        //
        // The PacketContext (PathResponse vs None) is stored in the separate
        // `context` byte of the wire format, which does not affect signature
        // verification.
        let new_packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: self.packet.header.context_flag,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: self.hops,
            },
            ifac: None,
            destination: self.packet.destination,
            transport: Some(*transport_id),
            context: self.context,
            data: self.packet.data,
            ratchet_id: None,
        };

        log::debug!(
            "announce_table: retransmit Type2 announce: meta=0x{:02x}, hops={}, context={:?}, context_flag={}, dest={}, transport={}, data_len={}",
            new_packet.header.to_meta(),
            new_packet.header.hops,
            new_packet.context,
            new_packet.header.context_flag,
            new_packet.destination,
            transport_id,
            new_packet.data.as_slice().len(),
        );

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
        // network announces get random delay for collision avoidance.
        // Both get PATHFINDER_R retries so the announce is forwarded to all
        // connected interfaces (critical for transport hub relay).
        let (timeout, retries) = if from_local_client {
            (now, super::PATHFINDER_R)  // Immediate, retransmit once
        } else {
            let random_delay = rand::random::<f64>() * super::PATHFINDER_RW;
            (now + Duration::from_secs_f64(random_delay), super::PATHFINDER_R)
        };

        let entry = AnnounceEntry {
            packet: *announce,
            timestamp: now,
            timeout,
            received_from,
            retries,
            hops,
            context: PacketContext::None,
        };

        self.map.insert(destination, entry);
    }

    /// Add a path response to the announce table with a grace period delay.
    ///
    /// Unlike `add()`, this does NOT increment hops (the hops value from the
    /// path table is already correct). Any existing entry for this destination
    /// is replaced, since path responses take priority.
    ///
    /// # Arguments
    /// * `packet` - The cached announce packet to retransmit
    /// * `destination` - The destination hash
    /// * `exclude_interface` - The interface the path request came from (excluded on retransmit)
    /// * `hops` - Hop count from the path table (not incremented)
    /// * `grace` - Grace period before sending (allows closer peers to answer first)
    pub fn add_path_response(
        &mut self,
        packet: &Packet,
        destination: AddressHash,
        exclude_interface: AddressHash,
        hops: u8,
        grace: Duration,
    ) {
        // Remove any existing entry — path response takes priority
        self.map.remove(&destination);

        let now = Instant::now();
        let entry = AnnounceEntry {
            packet: *packet,
            timestamp: now,
            timeout: now + grace,
            received_from: exclude_interface,
            retries: super::PATHFINDER_R,
            hops,
            context: PacketContext::PathResponse,
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
        let mut exhausted = vec![];

        for (destination, ref mut entry) in &mut self.map {
            if let Some(pair) = entry.retransmit(transport_id) {
                packets.push(pair);
            }
            // Only remove entries that have used all retries and whose
            // timeout has passed. Entries still waiting for their initial
            // delay must stay in the table.
            if entry.is_exhausted() {
                exhausted.push(*destination);
            }
        }

        if !(packets.is_empty() && exhausted.is_empty()) {
            log::trace!(
                "Announce cache: {} to retransmit, {} dropped",
                packets.len(),
                exhausted.len(),
            );
        }

        for destination in exhausted {
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
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops,
            },
            ifac: None,
            destination: zero_address_hash(),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new(),
            ratchet_id: None,
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
    fn test_add_network_announce_has_retries() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(0);
        let destination = test_address_hash(1);
        let received_from = test_address_hash(2);

        table.add(&packet, destination, received_from, false);

        let entry = table.map.get(&destination).unwrap();
        // Network announces get PATHFINDER_R retries (forwarded after random delay)
        assert_eq!(entry.retries, super::super::PATHFINDER_R);
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
    fn test_to_retransmit_removes_exhausted() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(0);
        let destination = test_address_hash(1);
        let received_from = test_address_hash(2);
        let transport_id = test_address_hash(99);

        // Add a network announce (retries=PATHFINDER_R, with random delay)
        table.add(&packet, destination, received_from, false);
        assert_eq!(table.map.len(), 1);

        // Force timeout to expired so retransmit fires
        table.map.get_mut(&destination).unwrap().timeout = Instant::now();
        let packets = table.to_retransmit(&transport_id);
        // Should produce one retransmit packet
        assert_eq!(packets.len(), 1);
        // Entry still exists (retries just decremented to 0, but timeout was updated)
        assert_eq!(table.map.len(), 1);

        // Force timeout again — now retries=0, so retransmit returns None
        // and is_exhausted() returns true
        table.map.get_mut(&destination).unwrap().timeout = Instant::now();
        let packets = table.to_retransmit(&transport_id);
        assert!(packets.is_empty());
        // Entry should be removed now (exhausted)
        assert_eq!(table.map.len(), 0);
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
            context: PacketContext::None,
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
            context: PacketContext::None,
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
            context: PacketContext::None,
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
            context: PacketContext::None,
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

    #[test]
    fn test_add_path_response_basic() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(2);
        let destination = test_address_hash(1);
        let exclude_iface = test_address_hash(5);
        let hops = 3u8;
        let grace = Duration::from_millis(400);

        table.add_path_response(&packet, destination, exclude_iface, hops, grace);

        assert_eq!(table.map.len(), 1);
        let entry = table.map.get(&destination).unwrap();
        // Hops should NOT be incremented (unlike add())
        assert_eq!(entry.hops, 3);
        assert_eq!(entry.received_from, exclude_iface);
        assert_eq!(entry.retries, super::super::PATHFINDER_R);
        assert_eq!(entry.context, PacketContext::PathResponse);
        // Timeout should be in the future (grace period)
        assert!(entry.timeout > Instant::now());
    }

    #[test]
    fn test_add_path_response_replaces_existing() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(0);
        let destination = test_address_hash(1);
        let received_from = test_address_hash(2);

        // Add a regular announce entry
        table.add(&packet, destination, received_from, false);
        assert_eq!(table.map.get(&destination).unwrap().context, PacketContext::None);

        // Add path response for same destination — should replace
        let exclude_iface = test_address_hash(5);
        table.add_path_response(&packet, destination, exclude_iface, 2, Duration::from_millis(400));

        assert_eq!(table.map.len(), 1);
        let entry = table.map.get(&destination).unwrap();
        assert_eq!(entry.context, PacketContext::PathResponse);
        assert_eq!(entry.received_from, exclude_iface);
        assert_eq!(entry.hops, 2);
    }

    #[test]
    fn test_path_response_retransmit_uses_context() {
        let mut table = AnnounceTable::new();
        let packet = test_announce_packet(1);
        let destination = test_address_hash(1);
        let exclude_iface = test_address_hash(5);

        // Add with zero grace so it's immediately retransmittable
        table.add_path_response(&packet, destination, exclude_iface, 2, Duration::ZERO);

        let transport_id = test_address_hash(99);
        let packets = table.to_retransmit(&transport_id);

        assert_eq!(packets.len(), 1);
        let (recv_from, retransmit_packet) = &packets[0];
        assert_eq!(*recv_from, exclude_iface);
        assert_eq!(retransmit_packet.context, PacketContext::PathResponse);
        assert_eq!(retransmit_packet.header.hops, 2);
    }

    /// Verify that retransmit preserves the original packet's context_flag
    /// rather than recomputing it from PacketContext.
    ///
    /// Python Transport.py always passes `context_flag = packet.context_flag`
    /// at every announce retransmit site.  The context_flag for announces
    /// indicates whether a ratchet public key is embedded in the data, which
    /// is independent of the PacketContext (None vs PathResponse).
    #[test]
    fn test_retransmit_preserves_context_flag() {
        let transport_id = test_address_hash(99);

        // Case 1: Ratchet announce (context_flag=true) retransmitted with no context
        let mut ratchet_announce = test_announce_packet(0);
        ratchet_announce.header.context_flag = true;

        let mut entry = AnnounceEntry {
            packet: ratchet_announce,
            timestamp: Instant::now(),
            timeout: Instant::now(),
            received_from: test_address_hash(1),
            retries: 1,
            hops: 1,
            context: PacketContext::None,
        };

        let result = entry.retransmit(&transport_id).unwrap();
        assert!(result.1.header.context_flag, "Ratchet flag must be preserved as true");
        assert_eq!(result.1.context, PacketContext::None);

        // Case 2: Non-ratchet announce (context_flag=false) retransmitted as PathResponse
        let non_ratchet_announce = test_announce_packet(0); // context_flag defaults to false

        let mut entry2 = AnnounceEntry {
            packet: non_ratchet_announce,
            timestamp: Instant::now(),
            timeout: Instant::now(),
            received_from: test_address_hash(1),
            retries: 1,
            hops: 1,
            context: PacketContext::PathResponse,
        };

        let result2 = entry2.retransmit(&transport_id).unwrap();
        assert!(!result2.1.header.context_flag, "Non-ratchet flag must be preserved as false");
        assert_eq!(result2.1.context, PacketContext::PathResponse);
    }
}
