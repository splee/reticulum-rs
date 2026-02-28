//! Per-interface announce queue for bandwidth-limited announce forwarding.
//!
//! This module implements ANNOUNCE_CAP bandwidth limiting as specified in Python's
//! Interface.py and Transport.py. Announces are queued per-interface and transmitted
//! at a rate that limits announce traffic to a configurable percentage of interface
//! bandwidth (default 2%).
//!
//! Key behaviors matching Python:
//! - Local announces (hops=0) bypass the queue and are sent immediately
//! - Queued announces are prioritized by minimum hops, then by age (oldest first)
//! - Stale announces (older than 24 hours) are removed from the queue
//! - Queue has a maximum size (default 16384 entries)

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::packet::Packet;

/// Default bandwidth cap for announces (2% = 0.02)
pub const DEFAULT_ANNOUNCE_CAP: f64 = 0.02;

/// Maximum number of queued announces per interface
pub const MAX_QUEUED_ANNOUNCES: usize = 16384;

/// Maximum age of a queued announce before it's considered stale (24 hours)
pub const QUEUED_ANNOUNCE_LIFE: Duration = Duration::from_secs(86400);

/// Default interface bitrate assumption (10 Mbps) when bitrate is unknown
pub const DEFAULT_BITRATE: u64 = 10_000_000;

/// A queued announce waiting to be transmitted.
#[derive(Debug, Clone)]
pub struct QueuedAnnounce {
    /// When the announce was queued
    pub timestamp: Instant,
    /// Number of hops in the announce (for prioritization)
    pub hops: u8,
    /// The serialized announce packet
    pub packet: Packet,
    /// Destination hash from the announce
    pub destination_hash: AddressHash,
    /// Interface that originally received this announce (to exclude from rebroadcast)
    pub received_from: AddressHash,
}

/// Per-interface announce queue state.
#[derive(Debug)]
pub struct InterfaceAnnounceQueue {
    /// Queue of announces waiting to be sent
    queue: VecDeque<QueuedAnnounce>,
    /// Earliest time the next announce can be sent
    announce_allowed_at: Option<Instant>,
    /// Bandwidth cap for announces (fraction, e.g., 0.02 = 2%)
    announce_cap: f64,
    /// Interface bitrate in bits per second (for timing calculations)
    bitrate: u64,
}

impl Default for InterfaceAnnounceQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceAnnounceQueue {
    /// Create a new interface announce queue with default settings.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            announce_allowed_at: None,
            announce_cap: DEFAULT_ANNOUNCE_CAP,
            bitrate: DEFAULT_BITRATE,
        }
    }

    /// Create a new queue with custom settings.
    pub fn with_settings(announce_cap: f64, bitrate: u64) -> Self {
        Self {
            queue: VecDeque::new(),
            announce_allowed_at: None,
            announce_cap,
            bitrate,
        }
    }

    /// Set the interface bitrate (bits per second).
    pub fn set_bitrate(&mut self, bitrate: u64) {
        self.bitrate = bitrate;
    }

    /// Set the announce cap (fraction of bandwidth).
    pub fn set_announce_cap(&mut self, cap: f64) {
        self.announce_cap = cap;
    }

    /// Check if an announce can be transmitted immediately.
    ///
    /// Returns true if:
    /// - The announce is local (hops == 0)
    /// - No announces are queued AND the allowed time has passed
    pub fn can_transmit_now(&self, hops: u8) -> bool {
        // Local announces always bypass the queue
        if hops == 0 {
            return true;
        }

        // If there are queued announces, new ones must queue
        if !self.queue.is_empty() {
            return false;
        }

        // Check if we've passed the allowed time
        match self.announce_allowed_at {
            Some(allowed_at) => Instant::now() >= allowed_at,
            None => true,
        }
    }

    /// Calculate the wait time for transmitting a packet.
    ///
    /// Based on Python's formula: wait_time = (packet_bytes * 8 / bitrate) / announce_cap
    fn calculate_wait_time(&self, packet_size: usize) -> Duration {
        if self.bitrate == 0 || self.announce_cap <= 0.0 {
            return Duration::from_secs(0);
        }

        // tx_time = (packet_bytes * 8) / bitrate (in seconds)
        // wait_time = tx_time / announce_cap
        let bits = (packet_size * 8) as f64;
        let tx_time = bits / (self.bitrate as f64);
        let wait_time = tx_time / self.announce_cap;

        Duration::from_secs_f64(wait_time)
    }

    /// Record that an announce was transmitted.
    ///
    /// Updates announce_allowed_at based on the packet size and bandwidth cap.
    pub fn record_transmit(&mut self, packet_size: usize) {
        let wait_time = self.calculate_wait_time(packet_size);
        self.announce_allowed_at = Some(Instant::now() + wait_time);

        log::trace!(
            "announce_queue: recorded transmit, next allowed in {:.2}ms",
            wait_time.as_secs_f64() * 1000.0
        );
    }

    /// Queue an announce for later transmission.
    ///
    /// Returns false if the queue is full or the announce is already queued.
    pub fn enqueue(&mut self, announce: QueuedAnnounce) -> bool {
        // Check queue capacity
        if self.queue.len() >= MAX_QUEUED_ANNOUNCES {
            log::warn!("announce_queue: queue full, dropping announce for {}", announce.destination_hash);
            return false;
        }

        // Check for duplicate (same destination already queued)
        let already_queued = self.queue.iter().any(|a| a.destination_hash == announce.destination_hash);
        if already_queued {
            // Update the existing entry if the new one has fewer hops
            if let Some(existing) = self.queue.iter_mut().find(|a| a.destination_hash == announce.destination_hash) {
                if announce.hops < existing.hops {
                    existing.hops = announce.hops;
                    existing.packet = announce.packet;
                    existing.received_from = announce.received_from;
                    existing.timestamp = announce.timestamp;
                    log::trace!("announce_queue: updated existing entry with lower hop count");
                }
            }
            return true;
        }

        self.queue.push_back(announce);
        log::trace!("announce_queue: enqueued announce, queue size now {}", self.queue.len());
        true
    }

    /// Remove stale entries from the queue.
    pub fn clean_stale(&mut self) {
        let now = Instant::now();
        let initial_len = self.queue.len();

        self.queue.retain(|a| {
            now.duration_since(a.timestamp) < QUEUED_ANNOUNCE_LIFE
        });

        let removed = initial_len - self.queue.len();
        if removed > 0 {
            log::debug!("announce_queue: removed {} stale entries", removed);
        }
    }

    /// Get the next announce to transmit.
    ///
    /// Selects the announce with minimum hops, then oldest among those.
    /// Returns None if the queue is empty or it's too early to transmit.
    pub fn dequeue(&mut self) -> Option<QueuedAnnounce> {
        // Clean stale entries first
        self.clean_stale();

        if self.queue.is_empty() {
            return None;
        }

        // Check if we're allowed to transmit now
        if let Some(allowed_at) = self.announce_allowed_at {
            if Instant::now() < allowed_at {
                return None;
            }
        }

        // Find minimum hop count
        let min_hops = self.queue.iter().map(|a| a.hops).min().unwrap_or(0);

        // Find the oldest announce with minimum hops
        let idx = self.queue.iter()
            .enumerate()
            .filter(|(_, a)| a.hops == min_hops)
            .min_by_key(|(_, a)| a.timestamp)
            .map(|(idx, _)| idx);

        if let Some(idx) = idx {
            let announce = self.queue.remove(idx).unwrap();
            log::trace!(
                "announce_queue: dequeued announce for {} (hops={}, queue size now {})",
                announce.destination_hash,
                announce.hops,
                self.queue.len()
            );
            Some(announce)
        } else {
            None
        }
    }

    /// Check if there are queued announces waiting.
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Get the number of queued announces.
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Get time until next transmit is allowed.
    pub fn time_until_allowed(&self) -> Duration {
        match self.announce_allowed_at {
            Some(allowed_at) => {
                let now = Instant::now();
                if now >= allowed_at {
                    Duration::from_secs(0)
                } else {
                    allowed_at - now
                }
            }
            None => Duration::from_secs(0),
        }
    }

    /// Clear the queue.
    pub fn clear(&mut self) {
        self.queue.clear();
        log::trace!("announce_queue: cleared");
    }
}

/// Manager for per-interface announce queues.
#[derive(Debug, Default)]
pub struct AnnounceQueueManager {
    /// Per-interface queues, keyed by interface address hash
    queues: HashMap<AddressHash, InterfaceAnnounceQueue>,
}

impl AnnounceQueueManager {
    /// Create a new announce queue manager.
    pub fn new() -> Self {
        Self {
            queues: HashMap::new(),
        }
    }

    /// Get or create the queue for an interface.
    pub fn get_or_create(&mut self, interface: &AddressHash) -> &mut InterfaceAnnounceQueue {
        self.queues.entry(*interface).or_default()
    }

    /// Get the queue for an interface if it exists.
    pub fn get(&self, interface: &AddressHash) -> Option<&InterfaceAnnounceQueue> {
        self.queues.get(interface)
    }

    /// Get mutable queue for an interface if it exists.
    pub fn get_mut(&mut self, interface: &AddressHash) -> Option<&mut InterfaceAnnounceQueue> {
        self.queues.get_mut(interface)
    }

    /// Set the bitrate for an interface.
    pub fn set_interface_bitrate(&mut self, interface: &AddressHash, bitrate: u64) {
        self.get_or_create(interface).set_bitrate(bitrate);
    }

    /// Check if an announce can be transmitted immediately on an interface.
    pub fn can_transmit_now(&self, interface: &AddressHash, hops: u8) -> bool {
        match self.queues.get(interface) {
            Some(queue) => queue.can_transmit_now(hops),
            None => true, // No queue yet means we can transmit
        }
    }

    /// Queue an announce for an interface.
    pub fn enqueue(&mut self, interface: &AddressHash, announce: QueuedAnnounce) -> bool {
        self.get_or_create(interface).enqueue(announce)
    }

    /// Record that an announce was transmitted on an interface.
    pub fn record_transmit(&mut self, interface: &AddressHash, packet_size: usize) {
        self.get_or_create(interface).record_transmit(packet_size);
    }

    /// Process all queues and return announces ready to transmit.
    ///
    /// Returns a list of (interface, announce) pairs.
    /// Processes at most one announce per interface per call to spread transmissions.
    pub fn process_queues(&mut self) -> Vec<(AddressHash, QueuedAnnounce)> {
        let mut ready = Vec::new();

        for (interface, queue) in &mut self.queues {
            if let Some(announce) = queue.dequeue() {
                ready.push((*interface, announce));
            }
        }

        ready
    }

    /// Get total number of queued announces across all interfaces.
    pub fn total_queued(&self) -> usize {
        self.queues.values().map(|q| q.queue_len()).sum()
    }

    /// Clear all queues.
    pub fn clear_all(&mut self) {
        for queue in self.queues.values_mut() {
            queue.clear();
        }
    }

    /// Remove the queue for an interface.
    pub fn remove(&mut self, interface: &AddressHash) {
        self.queues.remove(interface);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketDataBuffer;

    fn make_test_announce(hops: u8, dest_byte: u8) -> QueuedAnnounce {
        let mut packet = Packet::default();
        packet.header.hops = hops;
        packet.data = PacketDataBuffer::new_from_slice(&[0u8; 100]);

        QueuedAnnounce {
            timestamp: Instant::now(),
            hops,
            packet,
            destination_hash: AddressHash::new([dest_byte; 16]),
            received_from: AddressHash::new([0u8; 16]),
        }
    }

    #[test]
    fn test_queue_basic() {
        let queue = InterfaceAnnounceQueue::new();

        // Should be able to transmit initially
        assert!(queue.can_transmit_now(1));

        // Queue should be empty
        assert!(!queue.has_pending());
        assert_eq!(queue.queue_len(), 0);
    }

    #[test]
    fn test_local_announce_bypass() {
        let mut queue = InterfaceAnnounceQueue::new();

        // Simulate that we just transmitted
        queue.record_transmit(100);

        // Non-local announce should be blocked
        assert!(!queue.can_transmit_now(1));

        // Local announce (hops=0) should bypass
        assert!(queue.can_transmit_now(0));
    }

    #[test]
    fn test_queue_priority() {
        let mut queue = InterfaceAnnounceQueue::new();

        // Enqueue announces with different hop counts
        queue.enqueue(make_test_announce(3, 1)); // Higher hops
        queue.enqueue(make_test_announce(1, 2)); // Lower hops
        queue.enqueue(make_test_announce(2, 3)); // Medium hops

        // Should dequeue the one with lowest hops first
        let dequeued = queue.dequeue().unwrap();
        assert_eq!(dequeued.hops, 1);
        assert_eq!(dequeued.destination_hash.as_slice()[0], 2);
    }

    #[test]
    fn test_queue_dedup() {
        let mut queue = InterfaceAnnounceQueue::new();

        // Enqueue same destination twice
        queue.enqueue(make_test_announce(3, 1));
        let result = queue.enqueue(make_test_announce(3, 1));

        // Should succeed but not add duplicate
        assert!(result);
        assert_eq!(queue.queue_len(), 1);
    }

    #[test]
    fn test_queue_update_lower_hops() {
        let mut queue = InterfaceAnnounceQueue::new();

        // Enqueue with higher hop count
        queue.enqueue(make_test_announce(5, 1));

        // Enqueue same destination with lower hop count
        queue.enqueue(make_test_announce(2, 1));

        // Should still be one entry but with lower hops
        assert_eq!(queue.queue_len(), 1);

        let dequeued = queue.dequeue().unwrap();
        assert_eq!(dequeued.hops, 2);
    }

    #[test]
    fn test_wait_time_calculation() {
        let queue = InterfaceAnnounceQueue::with_settings(0.02, 10_000_000);

        // 100 bytes = 800 bits
        // tx_time = 800 / 10,000,000 = 0.00008 seconds
        // wait_time = 0.00008 / 0.02 = 0.004 seconds = 4ms
        let wait = queue.calculate_wait_time(100);

        // Allow some floating point tolerance
        let expected_ms = 4.0;
        let actual_ms = wait.as_secs_f64() * 1000.0;
        assert!((actual_ms - expected_ms).abs() < 0.1);
    }

    #[test]
    fn test_manager_basic() {
        let mut manager = AnnounceQueueManager::new();
        let iface = AddressHash::new_from_slice(&[1u8; 16]);

        // Should be able to transmit on new interface
        assert!(manager.can_transmit_now(&iface, 1));

        // Enqueue should work
        let announce = make_test_announce(1, 1);
        assert!(manager.enqueue(&iface, announce));

        assert_eq!(manager.total_queued(), 1);
    }

    #[test]
    fn test_manager_process_queues() {
        let mut manager = AnnounceQueueManager::new();
        let iface1 = AddressHash::new_from_slice(&[1u8; 16]);
        let iface2 = AddressHash::new_from_slice(&[2u8; 16]);

        // Enqueue on two interfaces
        manager.enqueue(&iface1, make_test_announce(1, 1));
        manager.enqueue(&iface2, make_test_announce(2, 2));

        // Process should return both
        let ready = manager.process_queues();
        assert_eq!(ready.len(), 2);
    }
}
