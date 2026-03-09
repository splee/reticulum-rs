//! AutoInterface for automatic peer discovery using IPv6 link-local addresses.
//!
//! AutoInterface automatically discovers peers on local network segments
//! using IPv6 multicast and link-local addressing. It enumerates local network
//! interfaces, computes a multicast discovery address from the group ID, and
//! manages peer state.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use sha2::Digest;

use crate::config::InterfaceConfig;
use crate::hash::{AddressHash, Hash};
use crate::iface::Interface;

// ---------------------------------------------------------------------------
// Constants — matched to Python AutoInterface.py
// ---------------------------------------------------------------------------

/// Hardware MTU for AutoInterface (Python: HW_MTU = 1196)
pub const HW_MTU: usize = 1196;

/// Default discovery (multicast beacon) port (Python: DEFAULT_DISCOVERY_PORT = 29716)
pub const DEFAULT_DISCOVERY_PORT: u16 = 29716;

/// Default data port for peer-to-peer TCP connections (Python: DEFAULT_DATA_PORT = 42671)
pub const DEFAULT_DATA_PORT: u16 = 42671;

/// Default group identifier — peers must share the same group_id to discover
/// each other. (Python: DEFAULT_GROUP_ID = "reticulum")
pub const DEFAULT_GROUP_ID: &str = "reticulum";

/// Default IFAC (Interface Access Code) size in bytes (Python: DEFAULT_IFAC_SIZE = 16)
pub const DEFAULT_IFAC_SIZE: usize = 16;

/// Estimated link bitrate when no measurement is available (Python: BITRATE_GUESS = 10_000_000)
pub const BITRATE_GUESS: u64 = 10_000_000;

/// Peer expiry timeout — peers not heard from within this window are removed.
/// (Python: PEERING_TIMEOUT = 22.0)
pub const PEERING_TIMEOUT: Duration = Duration::from_millis(22_000);

/// Interval between multicast discovery beacon transmissions.
/// (Python: ANNOUNCE_INTERVAL = 1.6)
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_millis(1_600);

/// Interval between peer-management housekeeping jobs.
/// (Python: PEER_JOB_INTERVAL = 4.0)
pub const PEER_JOB_INTERVAL: Duration = Duration::from_millis(4_000);

/// Timeout for multicast echo responses.
/// (Python: MCAST_ECHO_TIMEOUT = 6.5)
pub const MCAST_ECHO_TIMEOUT: Duration = Duration::from_millis(6_500);

/// Wait period before initial peering attempt.
/// (Python: PEERING_WAIT = 0.5)
pub const PEERING_WAIT: Duration = Duration::from_millis(500);

/// Multi-interface deque length for deduplication.
/// (Python: MULTI_IF_DEQUE_LEN = 48)
pub const MULTI_IF_DEQUE_LEN: usize = 48;

/// Multi-interface deque time-to-live.
/// (Python: MULTI_IF_DEQUE_TTL = 0.75)
pub const MULTI_IF_DEQUE_TTL: Duration = Duration::from_millis(750);

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// IPv6 multicast scope — determines how far discovery packets propagate.
/// The value maps to the scope nibble (position 3) in the IPv6 multicast address.
/// (Python: SCOPE_LINK = "2", SCOPE_ADMIN = "4", etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryScope {
    /// Link-local scope (ff_2::) — same physical/logical link only.
    Link,
    /// Admin-local scope (ff_4::) — administratively configured boundary.
    Admin,
    /// Site-local scope (ff_5::) — same site.
    Site,
    /// Organisation-local scope (ff_8::).
    Organisation,
    /// Global scope (ff_e::) — unrestricted.
    Global,
}

impl DiscoveryScope {
    /// Return the hex nibble value used in the IPv6 multicast address.
    pub fn nibble(&self) -> u8 {
        match self {
            Self::Link => 0x2,
            Self::Admin => 0x4,
            Self::Site => 0x5,
            Self::Organisation => 0x8,
            Self::Global => 0xe,
        }
    }
}

/// Multicast address type — the "flags" nibble (position 2) of the multicast address.
/// (Python: MULTICAST_PERMANENT_ADDRESS_TYPE = "0", MULTICAST_TEMPORARY_ADDRESS_TYPE = "1")
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastAddressType {
    /// Well-known (permanent) multicast address.
    Permanent,
    /// Transient (temporary) multicast address.
    Temporary,
}

impl MulticastAddressType {
    /// Return the hex nibble value used in the IPv6 multicast address.
    pub fn nibble(&self) -> u8 {
        match self {
            Self::Permanent => 0x0,
            Self::Temporary => 0x1,
        }
    }
}

// ---------------------------------------------------------------------------
// Network interface discovery
// ---------------------------------------------------------------------------

/// A discovered local network interface with its IPv6 link-local address.
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// OS interface name (e.g. "en0", "eth0")
    pub name: String,
    /// IPv6 link-local address on this interface
    pub link_local_addr: Ipv6Addr,
    /// OS-level scope ID (interface index) needed for IPv6 socket binding
    pub scope_id: u32,
}

/// Return the platform-specific list of interface names to ignore by default.
/// Matches Python's ALL_IGNORE_IFS, DARWIN_IGNORE_IFS, ANDROID_IGNORE_IFS.
fn default_ignored_interfaces() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        &["awdl0", "llw0", "lo0", "en5"]
    } else if cfg!(target_os = "android") {
        &["dummy0", "lo", "tun0"]
    } else {
        // Default (Linux, etc.)
        &["lo0"]
    }
}

/// Look up the OS interface index for the given interface name.
/// Returns 0 if the name cannot be resolved.
#[cfg(unix)]
fn get_scope_id(ifname: &str) -> u32 {
    use std::ffi::CString;
    let c_name = match CString::new(ifname) {
        Ok(n) => n,
        Err(_) => return 0,
    };
    // SAFETY: if_nametoindex is a well-defined POSIX call; the CString
    // pointer is valid for the duration of the call.
    unsafe { libc::if_nametoindex(c_name.as_ptr()) }
}

#[cfg(not(unix))]
fn get_scope_id(_ifname: &str) -> u32 {
    0
}

/// Enumerate local network interfaces that have IPv6 link-local addresses,
/// applying platform-specific and user-configured filtering.
///
/// # Arguments
/// * `allowed` — If non-empty, only interfaces whose name is in this list
///   will be returned. An allowed interface overrides the platform ignore list.
/// * `ignored` — Interfaces whose name appears here are always excluded.
pub fn enumerate_interfaces(
    allowed: &[String],
    ignored: &[String],
) -> Vec<NetworkInterface> {
    let default_ignored = default_ignored_interfaces();
    let all_ifs = match if_addrs::get_if_addrs() {
        Ok(ifs) => ifs,
        Err(e) => {
            log::warn!("AutoInterface: failed to enumerate network interfaces: {}", e);
            return Vec::new();
        }
    };

    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for iface in &all_ifs {
        // Only process IPv6 addresses
        let ipv6 = match &iface.addr {
            if_addrs::IfAddr::V6(v6) => v6.ip,
            _ => continue,
        };

        // Only link-local addresses (fe80::/10)
        if ipv6.segments()[0] & 0xffc0 != 0xfe80 {
            continue;
        }

        // Deduplicate: one entry per interface name (take first link-local addr)
        if !seen.insert(iface.name.clone()) {
            continue;
        }

        let name = &iface.name;

        // Platform-specific ignore list (overridden by explicit allow list)
        if default_ignored.contains(&name.as_str()) && !allowed.contains(name) {
            continue;
        }

        // User-configured ignore list
        if ignored.contains(name) {
            continue;
        }

        // If an allow-list is configured, interface must be in it
        if !allowed.is_empty() && !allowed.contains(name) {
            continue;
        }

        let scope_id = get_scope_id(name);

        result.push(NetworkInterface {
            name: name.clone(),
            link_local_addr: ipv6,
            scope_id,
        });
    }

    result
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// AutoInterface configuration — all tunables for peer discovery and data transport.
#[derive(Debug, Clone)]
pub struct AutoInterfaceConfig {
    /// Interface address hash (identifies this interface instance)
    pub address: AddressHash,

    /// Group identifier — only peers sharing the same group_id will discover
    /// each other. (Python default: "reticulum")
    pub group_id: String,

    /// UDP port used for multicast discovery beacons.
    /// (Python: DEFAULT_DISCOVERY_PORT = 29716)
    pub discovery_port: u16,

    /// TCP port used for peer data connections.
    /// (Python: DEFAULT_DATA_PORT = 42671)
    pub data_port: u16,

    /// IPv6 multicast scope for discovery packets.
    /// (Python default: SCOPE_LINK)
    pub discovery_scope: DiscoveryScope,

    /// Multicast address type nibble.
    /// (Python default: MULTICAST_TEMPORARY_ADDRESS_TYPE)
    pub multicast_address_type: MulticastAddressType,

    /// If non-empty, only enumerate these OS interface names for peering.
    /// (Python config key: "devices")
    pub allowed_interfaces: Vec<String>,

    /// Exclude these OS interface names from peering.
    /// (Python config key: "ignored_devices")
    pub ignored_interfaces: Vec<String>,

    /// Override for link speed estimation (bits/sec).
    pub configured_bitrate: Option<u64>,

    /// Peer expiry timeout (adjustable, e.g. increased for Android).
    pub peering_timeout: Duration,

    /// Multicast beacon interval.
    pub announce_interval: Duration,
}

impl Default for AutoInterfaceConfig {
    fn default() -> Self {
        Self {
            address: AddressHash::new([0u8; 16]),
            group_id: DEFAULT_GROUP_ID.to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT,
            data_port: DEFAULT_DATA_PORT,
            discovery_scope: DiscoveryScope::Link,
            multicast_address_type: MulticastAddressType::Temporary,
            allowed_interfaces: Vec::new(),
            ignored_interfaces: Vec::new(),
            configured_bitrate: None,
            peering_timeout: PEERING_TIMEOUT,
            announce_interval: ANNOUNCE_INTERVAL,
        }
    }
}

impl AutoInterfaceConfig {
    /// Create a new config with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the group ID.
    pub fn with_group_id(mut self, group_id: &str) -> Self {
        self.group_id = group_id.to_string();
        self
    }

    /// Set the interface address hash.
    pub fn with_address(mut self, address: AddressHash) -> Self {
        self.address = address;
        self
    }

    /// Set the discovery port.
    pub fn with_discovery_port(mut self, port: u16) -> Self {
        self.discovery_port = port;
        self
    }

    /// Set the data port.
    pub fn with_data_port(mut self, port: u16) -> Self {
        self.data_port = port;
        self
    }

    /// Apply configuration values from an InterfaceConfig (parsed from TOML).
    /// Reads AutoInterface-specific keys from `config.extra`.
    pub fn with_config(mut self, config: &InterfaceConfig) -> Self {
        if let Some(v) = config.extra.get("group_id") {
            self.group_id = v.clone();
        }
        if let Some(v) = config.extra.get("discovery_scope") {
            self.discovery_scope = parse_scope(v);
        }
        if let Some(v) = config.extra.get("discovery_port") {
            if let Ok(p) = v.parse() {
                self.discovery_port = p;
            }
        }
        if let Some(v) = config.extra.get("data_port") {
            if let Ok(p) = v.parse() {
                self.data_port = p;
            }
        }
        if let Some(v) = config.extra.get("multicast_address_type") {
            self.multicast_address_type = parse_mcast_type(v);
        }
        // Python uses "devices" for allow-list, "ignored_devices" for ignore-list.
        if let Some(v) = config.extra.get("devices") {
            self.allowed_interfaces = parse_comma_list(v);
        }
        if let Some(v) = config.extra.get("ignored_devices") {
            self.ignored_interfaces = parse_comma_list(v);
        }
        if let Some(bitrate) = config.bitrate {
            self.configured_bitrate = Some(bitrate);
        }
        self
    }

    /// Compute the IPv6 multicast discovery address from group_id, scope,
    /// and address type.
    ///
    /// Matches Python AutoInterface.py lines 202-212:
    ///   full_hash = SHA-256(group_id)
    ///   address = ff<type><scope>:0:<hash_segments...>
    pub fn multicast_discovery_address(&self) -> Ipv6Addr {
        let g = sha2::Sha256::digest(self.group_id.as_bytes());

        // First segment: 0xff00 | (address_type_nibble << 4) | scope_nibble
        let seg0: u16 = 0xff00
            | ((self.multicast_address_type.nibble() as u16) << 4)
            | (self.discovery_scope.nibble() as u16);

        // Second segment: hardcoded 0 (Python comments out the first hash pair)
        // Segments 3-8: big-endian u16 from consecutive hash byte pairs [2..14]
        Ipv6Addr::new(
            seg0,
            0,
            u16::from_be_bytes([g[2], g[3]]),
            u16::from_be_bytes([g[4], g[5]]),
            u16::from_be_bytes([g[6], g[7]]),
            u16::from_be_bytes([g[8], g[9]]),
            u16::from_be_bytes([g[10], g[11]]),
            u16::from_be_bytes([g[12], g[13]]),
        )
    }

    /// Return the multicast socket address for discovery beacons.
    pub fn multicast_group(&self) -> SocketAddrV6 {
        SocketAddrV6::new(self.multicast_discovery_address(), self.discovery_port, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Config parsing helpers
// ---------------------------------------------------------------------------

/// Parse a discovery scope string (from config) into a DiscoveryScope.
fn parse_scope(s: &str) -> DiscoveryScope {
    match s.trim().to_lowercase().as_str() {
        "link" => DiscoveryScope::Link,
        "admin" => DiscoveryScope::Admin,
        "site" => DiscoveryScope::Site,
        "organisation" | "organization" => DiscoveryScope::Organisation,
        "global" => DiscoveryScope::Global,
        _ => {
            log::warn!("AutoInterface: unknown discovery_scope '{}', defaulting to Link", s);
            DiscoveryScope::Link
        }
    }
}

/// Parse a multicast address type string (from config).
/// Python maps "admin" → Temporary (the default), "permanent" → Permanent.
fn parse_mcast_type(s: &str) -> MulticastAddressType {
    match s.trim().to_lowercase().as_str() {
        "permanent" => MulticastAddressType::Permanent,
        // "admin", "temporary", and anything else → Temporary (matches Python)
        _ => MulticastAddressType::Temporary,
    }
}

/// Split a comma-separated string into a list of trimmed, non-empty strings.
/// Matches Python's `as_list()` config helper.
fn parse_comma_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Peer
// ---------------------------------------------------------------------------

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

    /// Check if peer has expired based on the given timeout.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
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

// ---------------------------------------------------------------------------
// AutoInterface state
// ---------------------------------------------------------------------------

/// AutoInterface lifecycle state
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

// ---------------------------------------------------------------------------
// AutoInterface
// ---------------------------------------------------------------------------

/// AutoInterface for automatic peer discovery using IPv6 multicast.
pub struct AutoInterface {
    /// Configuration
    config: AutoInterfaceConfig,
    /// Current state
    state: AutoInterfaceState,
    /// Discovered peers (unbounded — matches Python's dict)
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

    /// Add or update a peer. No upper limit on peer count (matches Python).
    pub fn add_peer(&self, address: SocketAddrV6, interface_hash: AddressHash) {
        let mut peers = self.peers.write().unwrap();

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

    /// Clean up expired peers using the configured peering timeout.
    pub fn cleanup_peers(&self) {
        let timeout = self.config.peering_timeout;
        self.peers
            .write()
            .unwrap()
            .retain(|_, p| !p.is_expired(timeout));
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
        self.last_discovery.read().unwrap().elapsed() > self.config.announce_interval
    }

    /// Mark discovery as performed
    pub fn mark_discovered(&self) {
        *self.last_discovery.write().unwrap() = Instant::now();
    }

    /// Get the multicast discovery socket address for this interface.
    pub fn multicast_group(&self) -> SocketAddrV6 {
        self.config.multicast_group()
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

        // Group ID hash (always present — group_id defaults to "reticulum")
        let group_hash = Hash::new(
            sha2::Sha256::digest(self.config.group_id.as_bytes()).into(),
        );
        packet.extend_from_slice(&group_hash.as_bytes()[..8]);

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

        // Verify group ID hash
        if data.len() < 5 + 16 + 8 {
            return None;
        }

        let expected_group_hash = Hash::new(
            sha2::Sha256::digest(self.config.group_id.as_bytes()).into(),
        );

        if data[21..29] != expected_group_hash.as_bytes()[..8] {
            return None;
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
        HW_MTU
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_interface_config_defaults() {
        let config = AutoInterfaceConfig::new();
        assert_eq!(config.group_id, "reticulum");
        assert_eq!(config.discovery_port, 29716);
        assert_eq!(config.data_port, 42671);
        assert_eq!(config.discovery_scope, DiscoveryScope::Link);
        assert_eq!(config.multicast_address_type, MulticastAddressType::Temporary);
        assert!(config.allowed_interfaces.is_empty());
        assert!(config.ignored_interfaces.is_empty());
        assert_eq!(config.peering_timeout, PEERING_TIMEOUT);
        assert_eq!(config.announce_interval, ANNOUNCE_INTERVAL);
    }

    #[test]
    fn test_auto_interface_config_builders() {
        let config = AutoInterfaceConfig::new()
            .with_group_id("test")
            .with_discovery_port(12345)
            .with_data_port(54321);

        assert_eq!(config.group_id, "test");
        assert_eq!(config.discovery_port, 12345);
        assert_eq!(config.data_port, 54321);
    }

    #[test]
    fn test_discovery_scope_nibbles() {
        assert_eq!(DiscoveryScope::Link.nibble(), 0x2);
        assert_eq!(DiscoveryScope::Admin.nibble(), 0x4);
        assert_eq!(DiscoveryScope::Site.nibble(), 0x5);
        assert_eq!(DiscoveryScope::Organisation.nibble(), 0x8);
        assert_eq!(DiscoveryScope::Global.nibble(), 0xe);
    }

    #[test]
    fn test_multicast_address_type_nibbles() {
        assert_eq!(MulticastAddressType::Permanent.nibble(), 0x0);
        assert_eq!(MulticastAddressType::Temporary.nibble(), 0x1);
    }

    #[test]
    fn test_multicast_discovery_address_default() {
        // Default config: group_id = "reticulum", scope = Link (0x2), type = Temporary (0x1)
        let config = AutoInterfaceConfig::new();
        let addr = config.multicast_discovery_address();

        // First segment should be ff12 (ff + temporary:1 + link:2)
        assert_eq!(addr.segments()[0], 0xff12);
        // Second segment should be 0
        assert_eq!(addr.segments()[1], 0);
        // Remaining segments derived from SHA-256("reticulum") — verify non-trivial
        let non_zero = addr.segments()[2..].iter().any(|&s| s != 0);
        assert!(non_zero, "hash-derived segments should not all be zero");
    }

    #[test]
    fn test_multicast_discovery_address_scope_variation() {
        let config_link = AutoInterfaceConfig::new();
        let config_admin = AutoInterfaceConfig {
            discovery_scope: DiscoveryScope::Admin,
            ..AutoInterfaceConfig::new()
        };
        let config_global = AutoInterfaceConfig {
            discovery_scope: DiscoveryScope::Global,
            ..AutoInterfaceConfig::new()
        };

        assert_eq!(config_link.multicast_discovery_address().segments()[0], 0xff12);
        assert_eq!(config_admin.multicast_discovery_address().segments()[0], 0xff14);
        assert_eq!(config_global.multicast_discovery_address().segments()[0], 0xff1e);

        // Hash-derived segments should be identical (same group_id)
        assert_eq!(
            config_link.multicast_discovery_address().segments()[2..],
            config_admin.multicast_discovery_address().segments()[2..],
        );
    }

    #[test]
    fn test_multicast_discovery_address_group_variation() {
        let config_a = AutoInterfaceConfig::new().with_group_id("alpha");
        let config_b = AutoInterfaceConfig::new().with_group_id("beta");

        let addr_a = config_a.multicast_discovery_address();
        let addr_b = config_b.multicast_discovery_address();

        // Same scope prefix
        assert_eq!(addr_a.segments()[0], addr_b.segments()[0]);
        // Different hash-derived segments
        assert_ne!(addr_a.segments()[2..], addr_b.segments()[2..]);
    }

    #[test]
    fn test_parse_scope() {
        assert_eq!(parse_scope("link"), DiscoveryScope::Link);
        assert_eq!(parse_scope("admin"), DiscoveryScope::Admin);
        assert_eq!(parse_scope("site"), DiscoveryScope::Site);
        assert_eq!(parse_scope("organisation"), DiscoveryScope::Organisation);
        assert_eq!(parse_scope("organization"), DiscoveryScope::Organisation);
        assert_eq!(parse_scope("global"), DiscoveryScope::Global);
        assert_eq!(parse_scope("  Link  "), DiscoveryScope::Link);
        // Unknown defaults to Link
        assert_eq!(parse_scope("bogus"), DiscoveryScope::Link);
    }

    #[test]
    fn test_parse_mcast_type() {
        assert_eq!(parse_mcast_type("permanent"), MulticastAddressType::Permanent);
        assert_eq!(parse_mcast_type("admin"), MulticastAddressType::Temporary);
        assert_eq!(parse_mcast_type("temporary"), MulticastAddressType::Temporary);
        assert_eq!(parse_mcast_type("anything"), MulticastAddressType::Temporary);
    }

    #[test]
    fn test_parse_comma_list() {
        assert_eq!(parse_comma_list("en0,en1,wlan0"), vec!["en0", "en1", "wlan0"]);
        assert_eq!(parse_comma_list(" en0 , en1 "), vec!["en0", "en1"]);
        assert_eq!(parse_comma_list("single"), vec!["single"]);
        assert!(parse_comma_list("").is_empty());
        assert!(parse_comma_list(" , , ").is_empty());
    }

    #[test]
    fn test_with_config() {
        let mut extra = HashMap::new();
        extra.insert("group_id".to_string(), "mygroup".to_string());
        extra.insert("discovery_scope".to_string(), "admin".to_string());
        extra.insert("discovery_port".to_string(), "30000".to_string());
        extra.insert("data_port".to_string(), "50000".to_string());
        extra.insert("multicast_address_type".to_string(), "permanent".to_string());
        extra.insert("devices".to_string(), "en0,en1".to_string());
        extra.insert("ignored_devices".to_string(), "lo0".to_string());

        let iface_config = InterfaceConfig {
            name: "test".to_string(),
            interface_type: "AutoInterface".to_string(),
            enabled: true,
            mode: None,
            network_name: None,
            passphrase: None,
            target_host: None,
            target_port: None,
            listen_ip: None,
            listen_port: None,
            outgoing: false,
            bitrate: Some(1_000_000),
            fixed_mtu: None,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
            extra,
        };

        let config = AutoInterfaceConfig::new().with_config(&iface_config);

        assert_eq!(config.group_id, "mygroup");
        assert_eq!(config.discovery_scope, DiscoveryScope::Admin);
        assert_eq!(config.discovery_port, 30000);
        assert_eq!(config.data_port, 50000);
        assert_eq!(config.multicast_address_type, MulticastAddressType::Permanent);
        assert_eq!(config.allowed_interfaces, vec!["en0", "en1"]);
        assert_eq!(config.ignored_interfaces, vec!["lo0"]);
        assert_eq!(config.configured_bitrate, Some(1_000_000));
    }

    #[test]
    fn test_peer_expiry() {
        let addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 12345, 0, 0);
        let hash = AddressHash::new_from_slice(&[1u8; 32]);

        let peer = Peer::new(addr, hash);
        assert!(!peer.is_expired(PEERING_TIMEOUT));
        // With a zero timeout, the peer should be expired immediately
        assert!(peer.is_expired(Duration::ZERO));
    }

    #[test]
    fn test_auto_interface_peers_no_limit() {
        // Verify that peer count is unbounded (no MAX_PEERS)
        let config = AutoInterfaceConfig::new();
        let iface = AutoInterface::new(config);

        for i in 0..100u16 {
            let addr = SocketAddrV6::new(
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, i + 1),
                12345,
                0,
                0,
            );
            let hash = AddressHash::new_from_slice(&[i as u8; 32]);
            iface.add_peer(addr, hash);
        }

        assert_eq!(iface.peer_count(), 100);
    }

    #[test]
    fn test_auto_interface_peers_basic() {
        let config = AutoInterfaceConfig::new();
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
        let config = AutoInterfaceConfig::new()
            .with_address(AddressHash::new_from_slice(&[1u8; 32]));

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
        let config = AutoInterfaceConfig::new();
        let iface = AutoInterface::new(config);

        let group = iface.multicast_group();
        assert_eq!(group.port(), DEFAULT_DISCOVERY_PORT);
        // Address should start with ff12 (temporary + link scope)
        assert_eq!(group.ip().segments()[0], 0xff12);
    }

    #[test]
    fn test_mtu() {
        assert_eq!(AutoInterface::mtu(), HW_MTU);
        assert_eq!(AutoInterface::mtu(), 1196);
    }

    #[test]
    fn test_enumerate_interfaces_smoke() {
        // Smoke test: verify it doesn't panic and returns valid results
        let interfaces = enumerate_interfaces(&[], &[]);
        for iface in &interfaces {
            assert!(!iface.name.is_empty());
            // All returned addresses should be link-local
            assert_eq!(
                iface.link_local_addr.segments()[0] & 0xffc0,
                0xfe80,
                "expected link-local address for {}",
                iface.name,
            );
        }
    }
}
