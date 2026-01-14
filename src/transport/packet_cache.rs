use std::{
    cmp::min,
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::{hash::Hash, packet::Packet};

pub struct PacketTrack {
    pub time: Instant,
    pub min_hops: u8,
}

pub struct PacketCache {
    map: HashMap<Hash, PacketTrack>,
    remove_cache: Vec<Hash>,
}

impl PacketCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            remove_cache: Vec::new(),
        }
    }

    pub fn release(&mut self, duration: Duration) {
        for entry in &self.map {
            if entry.1.time.elapsed() > duration {
                self.remove_cache.push(*entry.0);
            }
        }

        for hash in &self.remove_cache {
            self.map.remove(hash);
        }

        self.remove_cache.clear();
    }

    pub fn update(&mut self, packet: &Packet) -> bool {
        let hash = packet.hash();

        let mut is_new_packet = false;

        let track = self.map.get_mut(&hash);
        if let Some(track) = track {
            track.time = Instant::now();
            track.min_hops = min(packet.header.hops, track.min_hops);
        } else {
            is_new_packet = true;

            self.map.insert(
                hash,
                PacketTrack {
                    time: Instant::now(),
                    min_hops: packet.header.hops,
                },
            );
        }

        is_new_packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::AddressHash;
    use crate::packet::{
        DestinationType, Header, HeaderType, IfacFlag, PacketContext, PacketDataBuffer,
        PacketType, PropagationType,
    };

    /// Create a test address hash with a specific byte pattern.
    fn test_address_hash(val: u8) -> AddressHash {
        AddressHash::new_from_slice(&[val; 16])
    }

    /// Create a test packet with specific hops and unique data.
    fn test_packet(hops: u8, data_byte: u8) -> Packet {
        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops,
            },
            ifac: None,
            destination: test_address_hash(data_byte),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(&[data_byte; 32]),
        }
    }

    #[test]
    fn test_packet_cache_new() {
        let cache = PacketCache::new();
        assert!(cache.map.is_empty());
        assert!(cache.remove_cache.is_empty());
    }

    #[test]
    fn test_update_new_packet_returns_true() {
        let mut cache = PacketCache::new();
        let packet = test_packet(0, 0xAA);

        let result = cache.update(&packet);

        assert!(result); // Should be true for new packet
        assert_eq!(cache.map.len(), 1);
    }

    #[test]
    fn test_update_duplicate_returns_false() {
        let mut cache = PacketCache::new();
        let packet = test_packet(0, 0xBB);

        // First update: new packet
        let first = cache.update(&packet);
        assert!(first);

        // Second update: duplicate
        let second = cache.update(&packet);
        assert!(!second);

        // Still only one entry
        assert_eq!(cache.map.len(), 1);
    }

    #[test]
    fn test_update_different_packets() {
        let mut cache = PacketCache::new();
        let packet1 = test_packet(0, 0xCC);
        let packet2 = test_packet(0, 0xDD);

        let first = cache.update(&packet1);
        let second = cache.update(&packet2);

        assert!(first);
        assert!(second);
        assert_eq!(cache.map.len(), 2);
    }

    #[test]
    fn test_update_tracks_min_hops_lower() {
        let mut cache = PacketCache::new();

        // Create packets with same hash but different hops
        let mut packet = test_packet(5, 0xEE);
        cache.update(&packet);

        // Check initial min_hops
        let hash = packet.hash();
        assert_eq!(cache.map.get(&hash).unwrap().min_hops, 5);

        // Update with lower hops
        packet.header.hops = 2;
        cache.update(&packet);

        // min_hops should be updated to lower value
        assert_eq!(cache.map.get(&hash).unwrap().min_hops, 2);
    }

    #[test]
    fn test_update_does_not_increase_min_hops() {
        let mut cache = PacketCache::new();

        let mut packet = test_packet(3, 0xFF);
        cache.update(&packet);

        let hash = packet.hash();
        assert_eq!(cache.map.get(&hash).unwrap().min_hops, 3);

        // Update with higher hops
        packet.header.hops = 7;
        cache.update(&packet);

        // min_hops should NOT increase
        assert_eq!(cache.map.get(&hash).unwrap().min_hops, 3);
    }

    #[test]
    fn test_release_removes_old_entries() {
        let mut cache = PacketCache::new();
        let packet = test_packet(0, 0x11);

        cache.update(&packet);
        assert_eq!(cache.map.len(), 1);

        // Force the entry to be old by manipulating the time
        let hash = packet.hash();
        if let Some(track) = cache.map.get_mut(&hash) {
            track.time = Instant::now() - Duration::from_secs(100);
        }

        // Release entries older than 50 seconds
        cache.release(Duration::from_secs(50));

        // Entry should be removed
        assert!(cache.map.is_empty());
    }

    #[test]
    fn test_release_keeps_recent_entries() {
        let mut cache = PacketCache::new();
        let packet = test_packet(0, 0x22);

        cache.update(&packet);
        assert_eq!(cache.map.len(), 1);

        // Release entries older than 60 seconds (entry is fresh)
        cache.release(Duration::from_secs(60));

        // Entry should still be there
        assert_eq!(cache.map.len(), 1);
    }

    #[test]
    fn test_release_clears_remove_cache() {
        let mut cache = PacketCache::new();
        let packet = test_packet(0, 0x33);

        cache.update(&packet);

        // Force old
        let hash = packet.hash();
        if let Some(track) = cache.map.get_mut(&hash) {
            track.time = Instant::now() - Duration::from_secs(100);
        }

        cache.release(Duration::from_secs(50));

        // remove_cache should be cleared after release
        assert!(cache.remove_cache.is_empty());
    }

    #[test]
    fn test_release_mixed_entries() {
        let mut cache = PacketCache::new();
        let packet1 = test_packet(0, 0x44);
        let packet2 = test_packet(0, 0x55);
        let packet3 = test_packet(0, 0x66);

        cache.update(&packet1);
        cache.update(&packet2);
        cache.update(&packet3);

        assert_eq!(cache.map.len(), 3);

        // Make packet1 and packet3 old
        let hash1 = packet1.hash();
        let hash3 = packet3.hash();

        if let Some(track) = cache.map.get_mut(&hash1) {
            track.time = Instant::now() - Duration::from_secs(100);
        }
        if let Some(track) = cache.map.get_mut(&hash3) {
            track.time = Instant::now() - Duration::from_secs(100);
        }

        cache.release(Duration::from_secs(50));

        // Only packet2 should remain
        assert_eq!(cache.map.len(), 1);
        assert!(cache.map.contains_key(&packet2.hash()));
    }

    #[test]
    fn test_release_empty_cache() {
        let mut cache = PacketCache::new();

        // Should not panic on empty cache
        cache.release(Duration::from_secs(60));

        assert!(cache.map.is_empty());
    }

    #[test]
    fn test_update_refreshes_time() {
        let mut cache = PacketCache::new();
        let packet = test_packet(0, 0x77);

        cache.update(&packet);

        // Force old
        let hash = packet.hash();
        let old_time = Instant::now() - Duration::from_secs(100);
        if let Some(track) = cache.map.get_mut(&hash) {
            track.time = old_time;
        }

        // Update again (duplicate)
        cache.update(&packet);

        // Time should be refreshed (more recent than old_time)
        let track = cache.map.get(&hash).unwrap();
        assert!(track.time > old_time);
    }

    #[test]
    fn test_packet_with_zero_hops() {
        let mut cache = PacketCache::new();
        let packet = test_packet(0, 0x88);

        cache.update(&packet);

        let hash = packet.hash();
        assert_eq!(cache.map.get(&hash).unwrap().min_hops, 0);
    }

    #[test]
    fn test_packet_with_max_hops() {
        let mut cache = PacketCache::new();
        let mut packet = test_packet(255, 0x99);

        cache.update(&packet);

        let hash = packet.hash();
        assert_eq!(cache.map.get(&hash).unwrap().min_hops, 255);

        // Update with lower hops
        packet.header.hops = 100;
        cache.update(&packet);

        assert_eq!(cache.map.get(&hash).unwrap().min_hops, 100);
    }
}
