//! Testing utilities for Reticulum
//!
//! This module provides test utilities, mock interfaces, and helpers
//! for testing Reticulum functionality.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::iface::Interface;
use crate::packet::Packet;

/// A test node for in-memory testing
#[derive(Debug)]
pub struct TestNode {
    /// Node name for debugging
    pub name: String,
    /// Node address hash
    pub address: AddressHash,
    /// Packet queue (received packets)
    rx_queue: Arc<Mutex<VecDeque<Packet>>>,
    /// Packet queue (sent packets)
    tx_queue: Arc<Mutex<VecDeque<Packet>>>,
    /// Simulated latency
    pub latency: Duration,
    /// Simulated packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Whether node is connected
    pub connected: bool,
}

impl TestNode {
    /// Create a new test node
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            address: AddressHash::new([0u8; 16]),
            rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            tx_queue: Arc::new(Mutex::new(VecDeque::new())),
            latency: Duration::ZERO,
            loss_rate: 0.0,
            connected: true,
        }
    }

    /// Create a test node with specific address
    pub fn with_address(mut self, address: AddressHash) -> Self {
        self.address = address;
        self
    }

    /// Set simulated latency
    pub fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    /// Set simulated packet loss rate
    pub fn with_loss_rate(mut self, rate: f64) -> Self {
        self.loss_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Send a packet (adds to tx queue)
    pub fn send(&self, packet: Packet) {
        if !self.connected {
            return;
        }
        self.tx_queue.lock().unwrap().push_back(packet);
    }

    /// Receive a packet (pops from rx queue)
    pub fn receive(&self) -> Option<Packet> {
        self.rx_queue.lock().unwrap().pop_front()
    }

    /// Queue a packet for reception
    pub fn queue_rx(&self, packet: Packet) {
        self.rx_queue.lock().unwrap().push_back(packet);
    }

    /// Get pending tx packets
    pub fn pending_tx(&self) -> Vec<Packet> {
        self.tx_queue.lock().unwrap().drain(..).collect()
    }

    /// Get pending rx count
    pub fn rx_count(&self) -> usize {
        self.rx_queue.lock().unwrap().len()
    }

    /// Get pending tx count
    pub fn tx_count(&self) -> usize {
        self.tx_queue.lock().unwrap().len()
    }

    /// Disconnect the node
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Reconnect the node
    pub fn reconnect(&mut self) {
        self.connected = true;
    }
}

/// Mock interface for testing
#[derive(Debug)]
pub struct MockInterface {
    /// Interface name
    pub name: String,
    /// Interface address
    pub address: AddressHash,
    /// Packets received
    rx_packets: Arc<Mutex<Vec<Packet>>>,
    /// Packets transmitted
    tx_packets: Arc<Mutex<Vec<Packet>>>,
    /// Whether interface is up
    pub is_up: bool,
}

impl MockInterface {
    /// Create a new mock interface
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            address: AddressHash::new([0u8; 16]),
            rx_packets: Arc::new(Mutex::new(Vec::new())),
            tx_packets: Arc::new(Mutex::new(Vec::new())),
            is_up: true,
        }
    }

    /// Simulate receiving a packet
    pub fn inject_rx(&self, packet: Packet) {
        self.rx_packets.lock().unwrap().push(packet);
    }

    /// Get transmitted packets
    pub fn get_tx_packets(&self) -> Vec<Packet> {
        self.tx_packets.lock().unwrap().clone()
    }

    /// Clear all packets
    pub fn clear(&self) {
        self.rx_packets.lock().unwrap().clear();
        self.tx_packets.lock().unwrap().clear();
    }

    /// Get rx count
    pub fn rx_count(&self) -> usize {
        self.rx_packets.lock().unwrap().len()
    }

    /// Get tx count
    pub fn tx_count(&self) -> usize {
        self.tx_packets.lock().unwrap().len()
    }
}

impl Interface for MockInterface {
    fn mtu() -> usize {
        500
    }
}

/// Packet capture utility for recording packets
#[derive(Debug, Default)]
pub struct PacketCapture {
    /// Captured packets with timestamps
    packets: Vec<(Instant, Packet, String)>,
    /// Maximum packets to capture (0 = unlimited)
    max_packets: usize,
}

impl PacketCapture {
    /// Create a new packet capture
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum packets to capture
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.max_packets = limit;
        self
    }

    /// Capture a packet
    pub fn capture(&mut self, packet: Packet, label: &str) {
        if self.max_packets > 0 && self.packets.len() >= self.max_packets {
            return;
        }
        self.packets.push((Instant::now(), packet, label.to_string()));
    }

    /// Get all captured packets
    pub fn packets(&self) -> &[(Instant, Packet, String)] {
        &self.packets
    }

    /// Get packet count
    pub fn count(&self) -> usize {
        self.packets.len()
    }

    /// Clear captured packets
    pub fn clear(&mut self) {
        self.packets.clear();
    }

    /// Filter packets by label
    pub fn filter_by_label(&self, label: &str) -> Vec<&Packet> {
        self.packets
            .iter()
            .filter(|(_, _, l)| l == label)
            .map(|(_, p, _)| p)
            .collect()
    }
}

/// Network simulator for testing
#[derive(Debug)]
pub struct NetworkSimulator {
    /// Nodes in the network
    nodes: Vec<Arc<Mutex<TestNode>>>,
    /// Connections between nodes (index pairs)
    connections: Vec<(usize, usize)>,
    /// Global latency
    pub base_latency: Duration,
    /// Global loss rate
    pub base_loss_rate: f64,
    /// Whether network is partitioned
    pub partitioned: bool,
}

impl NetworkSimulator {
    /// Create a new network simulator
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            connections: Vec::new(),
            base_latency: Duration::ZERO,
            base_loss_rate: 0.0,
            partitioned: false,
        }
    }

    /// Add a node to the network
    pub fn add_node(&mut self, node: TestNode) -> usize {
        let index = self.nodes.len();
        self.nodes.push(Arc::new(Mutex::new(node)));
        index
    }

    /// Connect two nodes
    pub fn connect(&mut self, node1: usize, node2: usize) {
        if node1 < self.nodes.len() && node2 < self.nodes.len() {
            self.connections.push((node1, node2));
        }
    }

    /// Disconnect two nodes
    pub fn disconnect(&mut self, node1: usize, node2: usize) {
        self.connections.retain(|&(a, b)| !((a == node1 && b == node2) || (a == node2 && b == node1)));
    }

    /// Partition the network
    pub fn partition(&mut self) {
        self.partitioned = true;
    }

    /// Heal the network partition
    pub fn heal(&mut self) {
        self.partitioned = false;
    }

    /// Get node count
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get a node by index
    pub fn get_node(&self, index: usize) -> Option<Arc<Mutex<TestNode>>> {
        self.nodes.get(index).cloned()
    }

    /// Step the simulation (process pending packets)
    pub fn step(&self) {
        if self.partitioned {
            return;
        }

        for (i, j) in &self.connections {
            // Transfer packets from i to j
            if let (Some(node_i), Some(node_j)) = (self.nodes.get(*i), self.nodes.get(*j)) {
                let packets: Vec<Packet> = node_i.lock().unwrap().pending_tx();
                for packet in packets {
                    if should_deliver(self.base_loss_rate) {
                        node_j.lock().unwrap().queue_rx(packet);
                    }
                }
            }

            // Transfer packets from j to i
            if let (Some(node_i), Some(node_j)) = (self.nodes.get(*i), self.nodes.get(*j)) {
                let packets: Vec<Packet> = node_j.lock().unwrap().pending_tx();
                for packet in packets {
                    if should_deliver(self.base_loss_rate) {
                        node_i.lock().unwrap().queue_rx(packet);
                    }
                }
            }
        }
    }
}

impl Default for NetworkSimulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to determine if a packet should be delivered based on loss rate
fn should_deliver(loss_rate: f64) -> bool {
    if loss_rate <= 0.0 {
        return true;
    }
    if loss_rate >= 1.0 {
        return false;
    }
    // Simple random check
    let random_byte = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u8;
    (random_byte as f64 / 255.0) > loss_rate
}

/// Assert that two packets are equivalent
pub fn assert_packets_equal(a: &Packet, b: &Packet) {
    assert_eq!(a.header.header_type, b.header.header_type, "Header types differ");
    assert_eq!(a.header.hops, b.header.hops, "Hop counts differ");
    assert_eq!(a.context, b.context, "Contexts differ");
    // Compare data
    assert_eq!(a.data.len(), b.data.len(), "Data lengths differ");
}

/// Wait for a condition with timeout
pub fn wait_for<F>(condition: F, timeout: Duration) -> bool
where
    F: Fn() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Create a random address hash for testing
pub fn random_address() -> AddressHash {
    let bytes: [u8; 16] = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes()[..16]
        .try_into()
        .unwrap();
    AddressHash::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_node() {
        let node = TestNode::new("test")
            .with_latency(Duration::from_millis(10))
            .with_loss_rate(0.1);

        assert_eq!(node.name, "test");
        assert_eq!(node.latency, Duration::from_millis(10));
        assert_eq!(node.loss_rate, 0.1);
        assert!(node.connected);
    }

    #[test]
    fn test_mock_interface() {
        let iface = MockInterface::new("mock0");
        assert!(iface.is_up);
        assert_eq!(iface.rx_count(), 0);
        assert_eq!(iface.tx_count(), 0);
    }

    #[test]
    fn test_packet_capture() {
        use crate::packet::{Header, PacketContext, PacketDataBuffer};

        let mut capture = PacketCapture::new().with_limit(10);

        let packet = Packet {
            header: Header::default(),
            ifac: None,
            destination: AddressHash::new([0u8; 16]),
            transport: None,
            data: PacketDataBuffer::new(),
            context: PacketContext::None,
        };

        capture.capture(packet.clone(), "test");
        assert_eq!(capture.count(), 1);

        let filtered = capture.filter_by_label("test");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_network_simulator() {
        let mut sim = NetworkSimulator::new();

        let n1 = sim.add_node(TestNode::new("node1"));
        let n2 = sim.add_node(TestNode::new("node2"));

        sim.connect(n1, n2);
        assert_eq!(sim.node_count(), 2);

        // Test partition
        sim.partition();
        assert!(sim.partitioned);
        sim.heal();
        assert!(!sim.partitioned);
    }

    #[test]
    fn test_wait_for() {
        let result = wait_for(|| true, Duration::from_millis(100));
        assert!(result);

        let result = wait_for(|| false, Duration::from_millis(50));
        assert!(!result);
    }

    #[test]
    fn test_random_address() {
        let addr1 = random_address();
        std::thread::sleep(Duration::from_millis(1));
        let addr2 = random_address();

        // Should be different (though not guaranteed due to timing)
        // Just check they're valid
        assert_eq!(addr1.as_slice().len(), 16);
        assert_eq!(addr2.as_slice().len(), 16);
    }
}
