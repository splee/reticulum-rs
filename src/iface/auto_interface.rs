//! AutoInterface for automatic peer discovery using IPv6 link-local addresses.
//!
//! AutoInterface automatically discovers peers on local network segments
//! using IPv6 multicast and link-local addressing.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::hash::{AddressHash, Hash};
use crate::iface::Interface;

/// Default multicast group for AutoInterface
pub const AUTO_INTERFACE_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1); // All nodes

/// Default port for AutoInterface
pub const AUTO_INTERFACE_PORT: u16 = 29716;

/// Discovery interval
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

/// Peer expiry time
pub const PEER_EXPIRY: Duration = Duration::from_secs(900); // 15 minutes

/// Maximum peers per interface
pub const MAX_PEERS: usize = 64;

/// Discovered peer information
#[derive(Debug, Clone)]
pub struct Peer {
    /// Peer address
    pub address: SocketAddrV6,
    /// Interface address hash
    pub interface_hash: AddressHash,
    /// When peer was discovered
    pub discovered_at: Instant,
    /// Last activity time
    pub last_seen: Instant,
    /// Whether peer is reachable
    pub reachable: bool,
}

impl Peer {
    /// Create a new peer
    pub fn new(address: SocketAddrV6, interface_hash: AddressHash) -> Self {
        let now = Instant::now();
        Self {
            address,
            interface_hash,
            discovered_at: now,
            last_seen: now,
            reachable: true,
        }
    }

    /// Check if peer has expired
    pub fn is_expired(&self) -> bool {
        self.last_seen.elapsed() > PEER_EXPIRY
    }

    /// Update last seen time
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
        self.reachable = true;
    }

    /// Mark peer as unreachable
    pub fn mark_unreachable(&mut self) {
        self.reachable = false;
    }
}

/// AutoInterface configuration
#[derive(Debug, Clone)]
pub struct AutoInterfaceConfig {
    /// Network interface name (e.g., "eth0")
    pub interface_name: Option<String>,
    /// Port to use
    pub port: u16,
    /// Whether to allow multiple instances
    pub allow_multiple: bool,
    /// Discovery interval
    pub discovery_interval: Duration,
    /// Group ID (for separating networks)
    pub group_id: Option<String>,
    /// Interface address hash
    pub address: AddressHash,
}

impl Default for AutoInterfaceConfig {
    fn default() -> Self {
        Self {
            interface_name: None,
            port: AUTO_INTERFACE_PORT,
            allow_multiple: true,
            discovery_interval: DISCOVERY_INTERVAL,
            group_id: None,
            address: AddressHash::new([0u8; 16]),
        }
    }
}

impl AutoInterfaceConfig {
    /// Create a new config with interface name
    pub fn new(interface_name: Option<&str>) -> Self {
        Self {
            interface_name: interface_name.map(String::from),
            ..Default::default()
        }
    }

    /// Set the port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the group ID
    pub fn with_group_id(mut self, group_id: &str) -> Self {
        self.group_id = Some(group_id.to_string());
        self
    }

    /// Set the address
    pub fn with_address(mut self, address: AddressHash) -> Self {
        self.address = address;
        self
    }
}

/// AutoInterface state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoInterfaceState {
    /// Interface is stopped
    Stopped,
    /// Interface is starting
    Starting,
    /// Interface is running
    Running,
    /// Interface encountered an error
    Error,
}

/// AutoInterface for automatic peer discovery
pub struct AutoInterface {
    /// Configuration
    config: AutoInterfaceConfig,
    /// Current state
    state: AutoInterfaceState,
    /// Discovered peers
    peers: RwLock<HashMap<SocketAddrV6, Peer>>,
    /// Last discovery time
    last_discovery: RwLock<Instant>,
    /// Local addresses
    local_addresses: RwLock<Vec<Ipv6Addr>>,
}

impl AutoInterface {
    /// Create a new AutoInterface
    pub fn new(config: AutoInterfaceConfig) -> Self {
        Self {
            config,
            state: AutoInterfaceState::Stopped,
            peers: RwLock::new(HashMap::new()),
            last_discovery: RwLock::new(Instant::now()),
            local_addresses: RwLock::new(Vec::new()),
        }
    }

    /// Get current state
    pub fn state(&self) -> AutoInterfaceState {
        self.state
    }

    /// Get configuration
    pub fn config(&self) -> &AutoInterfaceConfig {
        &self.config
    }

    /// Get discovered peers
    pub fn peers(&self) -> Vec<Peer> {
        self.peers.read().unwrap().values().cloned().collect()
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.read().unwrap().len()
    }

    /// Add or update a peer
    pub fn add_peer(&self, address: SocketAddrV6, interface_hash: AddressHash) {
        let mut peers = self.peers.write().unwrap();

        if peers.len() >= MAX_PEERS && !peers.contains_key(&address) {
            // Remove oldest expired peer to make room
            if let Some(oldest) = peers
                .iter()
                .filter(|(_, p)| p.is_expired())
                .min_by_key(|(_, p)| p.last_seen)
                .map(|(addr, _)| *addr)
            {
                peers.remove(&oldest);
            } else {
                return; // No room
            }
        }

        if let Some(peer) = peers.get_mut(&address) {
            peer.touch();
            peer.interface_hash = interface_hash;
        } else {
            peers.insert(address, Peer::new(address, interface_hash));
        }
    }

    /// Remove a peer
    pub fn remove_peer(&self, address: &SocketAddrV6) {
        self.peers.write().unwrap().remove(address);
    }

    /// Mark a peer as unreachable
    pub fn mark_peer_unreachable(&self, address: &SocketAddrV6) {
        if let Some(peer) = self.peers.write().unwrap().get_mut(address) {
            peer.mark_unreachable();
        }
    }

    /// Clean up expired peers
    pub fn cleanup_peers(&self) {
        self.peers.write().unwrap().retain(|_, p| !p.is_expired());
    }

    /// Check if a peer exists
    pub fn has_peer(&self, address: &SocketAddrV6) -> bool {
        self.peers.read().unwrap().contains_key(address)
    }

    /// Get a specific peer
    pub fn get_peer(&self, address: &SocketAddrV6) -> Option<Peer> {
        self.peers.read().unwrap().get(address).cloned()
    }

    /// Check if discovery should be performed
    pub fn should_discover(&self) -> bool {
        self.last_discovery.read().unwrap().elapsed() > self.config.discovery_interval
    }

    /// Mark discovery as performed
    pub fn mark_discovered(&self) {
        *self.last_discovery.write().unwrap() = Instant::now();
    }

    /// Get the multicast group for this interface
    pub fn multicast_group(&self) -> SocketAddrV6 {
        SocketAddrV6::new(AUTO_INTERFACE_MULTICAST, self.config.port, 0, 0)
    }

    /// Create a discovery announcement packet
    pub fn create_discovery_packet(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(64);

        // Magic bytes
        packet.extend_from_slice(b"RNS\x00");

        // Version
        packet.push(0x01);

        // Interface hash
        packet.extend_from_slice(self.config.address.as_slice());

        // Group ID hash (if present)
        if let Some(ref group_id) = self.config.group_id {
            let group_hash = Hash::new(
                sha2::Sha256::digest(group_id.as_bytes()).into()
            );
            packet.extend_from_slice(&group_hash.as_bytes()[..8]);
        }

        packet
    }

    /// Parse a discovery packet
    pub fn parse_discovery_packet(&self, data: &[u8]) -> Option<AddressHash> {
        // Check magic
        if data.len() < 5 || &data[..4] != b"RNS\x00" {
            return None;
        }

        // Check version
        if data[4] != 0x01 {
            return None;
        }

        // Check minimum length for interface hash
        if data.len() < 5 + 16 {
            return None;
        }

        // Extract interface hash
        let interface_hash = AddressHash::new_from_slice(&data[5..21]);

        // Check group ID if we have one
        if let Some(ref group_id) = self.config.group_id {
            if data.len() < 5 + 16 + 8 {
                return None;
            }

            let expected_group_hash = Hash::new(
                sha2::Sha256::digest(group_id.as_bytes()).into()
            );

            if &data[21..29] != &expected_group_hash.as_bytes()[..8] {
                return None;
            }
        }

        Some(interface_hash)
    }

    /// Set local addresses
    pub fn set_local_addresses(&self, addresses: Vec<Ipv6Addr>) {
        *self.local_addresses.write().unwrap() = addresses;
    }

    /// Get local addresses
    pub fn local_addresses(&self) -> Vec<Ipv6Addr> {
        self.local_addresses.read().unwrap().clone()
    }

    /// Check if an address is local
    pub fn is_local_address(&self, addr: &Ipv6Addr) -> bool {
        self.local_addresses.read().unwrap().contains(addr)
    }
}

impl Interface for AutoInterface {
    fn mtu() -> usize {
        1280 // Minimum IPv6 MTU
    }
}

use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_interface_config() {
        let config = AutoInterfaceConfig::new(Some("eth0"))
            .with_port(12345)
            .with_group_id("test");

        assert_eq!(config.interface_name, Some("eth0".to_string()));
        assert_eq!(config.port, 12345);
        assert_eq!(config.group_id, Some("test".to_string()));
    }

    #[test]
    fn test_peer_expiry() {
        let addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 12345, 0, 0);
        let hash = AddressHash::new_from_slice(&[1u8; 32]);

        let peer = Peer::new(addr, hash);
        assert!(!peer.is_expired());
    }

    #[test]
    fn test_auto_interface_peers() {
        let config = AutoInterfaceConfig::default();
        let iface = AutoInterface::new(config);

        let addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 12345, 0, 0);
        let hash = AddressHash::new_from_slice(&[1u8; 32]);

        iface.add_peer(addr, hash);
        assert!(iface.has_peer(&addr));
        assert_eq!(iface.peer_count(), 1);

        iface.remove_peer(&addr);
        assert!(!iface.has_peer(&addr));
    }

    #[test]
    fn test_discovery_packet() {
        let mut config = AutoInterfaceConfig::default();
        config.address = AddressHash::new_from_slice(&[1u8; 32]);

        let iface = AutoInterface::new(config);
        let packet = iface.create_discovery_packet();

        assert!(packet.starts_with(b"RNS\x00"));
        assert_eq!(packet[4], 0x01);

        // Parse should succeed
        let parsed = iface.parse_discovery_packet(&packet);
        assert!(parsed.is_some());
    }

    #[test]
    fn test_multicast_group() {
        let config = AutoInterfaceConfig::default();
        let iface = AutoInterface::new(config);

        let group = iface.multicast_group();
        assert_eq!(*group.ip(), AUTO_INTERFACE_MULTICAST);
        assert_eq!(group.port(), AUTO_INTERFACE_PORT);
    }
}
