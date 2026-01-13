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
