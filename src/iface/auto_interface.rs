//! AutoInterface for automatic peer discovery using IPv6 link-local addresses.
//!
//! AutoInterface automatically discovers peers on local network segments
//! using IPv6 multicast and link-local addressing. It enumerates local network
//! interfaces, computes a multicast discovery address from the group ID, and
//! manages peer state via a background async task architecture.
//!
//! ## Wire Protocol
//!
//! Discovery packets are exactly 32 bytes: `SHA-256(group_id_bytes + link_local_addr_string_bytes)`.
//! This matches Python's `AutoInterface.py` peer_announce/discovery_handler.
//!
//! ## Architecture
//!
//! `AutoInterface::run()` spawns per-OS-interface tasks for:
//! - Multicast discovery (send + recv on `discovery_port`)
//! - Unicast discovery (recv on `discovery_port + 1`)
//! - Data receive (recv on `data_port`, with MifDeque deduplication)
//! - A single peer job task for expiry, reverse peering, and echo checks.
//! - A peer spawn task that processes PeerCommand messages to spawn/teardown
//!   peer interfaces via InterfaceManager.
//!
//! ## Data Flow
//!
//! ```text
//! Incoming (peer → transport):
//!   UDP datagram → parent data_recv_task → MifDeque dedup →
//!   Packet::deserialize → RxMessage{peer_hash} → transport rx_channel
//!
//! Outgoing (transport → peer):
//!   Transport → InterfaceManager::send() → peer tx_channel →
//!   AutoInterfacePeer::spawn TX loop → packet.serialize() →
//!   UdpSocket::send_to(peer_sockaddr)
//! ```

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use sha2::Digest;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::config::InterfaceConfig;
use crate::hash::{AddressHash, Hash};
use crate::iface::stats::InterfaceMetadata;
use crate::iface::{
    InterfaceContext, InterfaceManager, InterfaceRegistry, InterfaceRxSender, Interface, RxMessage,
};
use crate::serde::Serialize;

// ---------------------------------------------------------------------------
// Constants — matched to Python AutoInterface.py
// ---------------------------------------------------------------------------

/// Hardware MTU for AutoInterface (Python: HW_MTU = 1196)
pub const HW_MTU: usize = 1196;

/// Default discovery (multicast beacon) port (Python: DEFAULT_DISCOVERY_PORT = 29716)
pub const DEFAULT_DISCOVERY_PORT: u16 = 29716;

/// Default data port for peer-to-peer UDP connections (Python: DEFAULT_DATA_PORT = 42671)
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

/// Multiplier applied to announce_interval to compute reverse peering interval.
/// (Python: peer[2] checked against ANNOUNCE_INTERVAL * 3.25)
const REVERSE_PEERING_MULTIPLIER: f64 = 3.25;

// ---------------------------------------------------------------------------
// Peer management types
// ---------------------------------------------------------------------------

/// Commands sent from sync add_peer/run_peer_jobs to the async peer_spawn_task.
/// Uses an unbounded channel because add_peer() is called from a sync RwLock
/// context and cannot await.
enum PeerCommand {
    /// Spawn a new peer interface for the discovered peer.
    Spawn { addr: String, ifname: String },
    /// Teardown an expired peer interface.
    Teardown { addr: String },
}

/// Tracking info for a spawned peer interface.
struct SpawnedPeerInfo {
    /// Interface address hash (matches InterfaceManager's channel address).
    address: AddressHash,
    /// Stop token to individually teardown this peer's worker task.
    stop: CancellationToken,
    /// Shared metadata for stats tracking.
    metadata: Arc<InterfaceMetadata>,
}

/// Spawned peer interface — one per discovered peer.
///
/// Handles TX only (outbound packets from transport → UDP to peer).
/// RX is handled centrally by the parent AutoInterface's data_recv_task,
/// which forwards packets using this peer's AddressHash as the source.
///
/// This matches Python's `AutoInterfacePeer` which is a full Interface subclass,
/// but in Rust we split RX (parent) from TX (peer) for efficiency.
pub struct AutoInterfacePeer {
    /// Peer IPv6 address (descoped, e.g. "fe80::1234:5678")
    addr: String,
    /// OS interface name this peer was discovered on
    ifname: String,
    /// OS-level scope ID for SocketAddrV6
    scope_id: u32,
    /// Data port for UDP sends
    data_port: u16,
    /// Shared outbound UDP socket (one per AutoInterface)
    outbound_socket: Arc<tokio::net::UdpSocket>,
    /// Parent interface's address hash (for metadata tracking)
    parent_address: AddressHash,
}

impl Interface for AutoInterfacePeer {
    fn mtu() -> usize {
        HW_MTU
    }
}

impl AutoInterfacePeer {
    /// TX-only worker for a spawned peer interface.
    ///
    /// Reads outbound packets from the tx_channel (provided by InterfaceManager),
    /// serializes them, and sends via UDP to this specific peer's address.
    /// No HDLC framing — raw serialized bytes go directly into UDP datagrams
    /// (UDP provides message framing).
    pub async fn spawn(context: InterfaceContext<Self>) {
        // Extract fields from inner
        let (addr, ifname, scope_id, data_port, outbound_socket, parent_address) = {
            let inner = context.inner.lock().await;
            (
                inner.addr.clone(),
                inner.ifname.clone(),
                inner.scope_id,
                inner.data_port,
                inner.outbound_socket.clone(),
                inner.parent_address,
            )
        };

        let iface_address = *context.channel.address();
        let peer_name = format!("AutoInterfacePeer[{}]", addr);

        // Parse peer IPv6 address for socket sends
        let peer_ipv6: Ipv6Addr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                log::error!("{}: invalid IPv6 address: {}", peer_name, e);
                return;
            }
        };
        let peer_sockaddr = SocketAddrV6::new(peer_ipv6, data_port, 0, scope_id);

        // Create and register metadata
        let metadata = Arc::new(
            InterfaceMetadata::new(
                &peer_name,
                &format!("peer:{}", addr),
                "AutoInterfacePeer",
                &addr,
            )
            .with_parent(parent_address)
            .with_hw_mtu(HW_MTU)
            .with_bitrate(BITRATE_GUESS)
            .with_direction(true, true),
        );

        if let Some(ref reg) = context.interface_registry {
            reg.register(iface_address, metadata.clone()).await;
        }

        metadata.set_online(true);
        log::info!("{}: spawned on {} (TX → {})", peer_name, ifname, peer_sockaddr);

        // TX loop: read from tx_channel, serialize, send UDP
        let (_, mut tx_channel) = context.channel.split();
        let mut tx_buffer = [0u8; HW_MTU + 128];

        loop {
            tokio::select! {
                _ = context.cancel.cancelled() => break,
                msg = tx_channel.recv() => {
                    match msg {
                        Some(message) => {
                            let packet = message.packet;
                            let mut output = OutputBuffer::new(&mut tx_buffer);
                            if packet.serialize(&mut output).is_ok() {
                                let data = output.as_slice();
                                metadata.add_tx_bytes(data.len() as u64);
                                if let Err(e) = outbound_socket.send_to(data, peer_sockaddr).await {
                                    log::debug!("{}: send error: {}", peer_name, e);
                                }
                            }
                        }
                        None => break, // Channel closed
                    }
                }
            }
        }

        metadata.set_online(false);
        if let Some(ref reg) = context.interface_registry {
            reg.unregister(&iface_address).await;
        }
        log::info!("{}: stopped", peer_name);
    }
}

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

    /// UDP port used for peer data connections.
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

    /// Unicast discovery port — one higher than the multicast discovery port.
    /// (Python: self.discovery_port + 1)
    pub fn unicast_discovery_port(&self) -> u16 {
        self.discovery_port + 1
    }

    /// Compute the reverse peering interval.
    /// (Python: checks `peer[2]` against `ANNOUNCE_INTERVAL * 3.25`)
    pub fn reverse_peering_interval(&self) -> Duration {
        Duration::from_secs_f64(self.announce_interval.as_secs_f64() * REVERSE_PEERING_MULTIPLIER)
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
// Discovery token — wire format compatible with Python AutoInterface.py
// ---------------------------------------------------------------------------

/// Create a 32-byte discovery token: SHA-256(group_id_bytes + link_local_addr_string_bytes).
///
/// Matches Python AutoInterface.py:494:
///   `discovery_token = RNS.Identity.full_hash(self.group_id + link_local_address.encode("utf-8"))`
///
/// Python's `group_id` is `"reticulum".encode("utf-8")` (bytes). In Rust, `group_id` is
/// a `String`, so `.as_bytes()` produces identical UTF-8 bytes.
pub fn create_discovery_token(group_id: &str, link_local_addr: &str) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(group_id.as_bytes());
    hasher.update(link_local_addr.as_bytes());
    hasher.finalize().into()
}

/// Validate a received discovery token against the expected hash for a sender address.
///
/// Matches Python AutoInterface.py discovery_handler:
///   `expected_hash = RNS.Identity.full_hash(self.group_id + ipv6_src[0].encode("utf-8"))`
///   `if peering_hash == expected_hash: self.add_peer(...)`
pub fn validate_discovery_token(group_id: &str, received: &[u8], sender_addr: &str) -> bool {
    if received.len() < 32 {
        return false;
    }
    let expected = create_discovery_token(group_id, sender_addr);
    received[..32] == expected
}

// ---------------------------------------------------------------------------
// Address normalization
// ---------------------------------------------------------------------------

/// Normalize a link-local IPv6 address by removing scope identifiers.
///
/// Matches Python `AutoInterface.descope_linklocal()`:
///   1. Strip `%ifname` suffix (macOS: `fe80::1%en0` → `fe80::1`)
///   2. Strip embedded scope bits (NetBSD/OpenBSD: `fe80:4::1234` → `fe80::1234`)
pub fn descope_linklocal(addr: &str) -> String {
    // Step 1: strip %ifname suffix (macOS)
    let addr = addr.split('%').next().unwrap_or(addr);

    // Step 2: strip embedded scope bits (NetBSD/OpenBSD)
    // Python regex: re.sub(r"fe80:[0-9a-f]*::", "fe80::", addr)
    if let Some(rest) = addr.strip_prefix("fe80:") {
        if let Some(pos) = rest.find("::") {
            let between = &rest[..pos];
            if !between.is_empty() && between.chars().all(|c| c.is_ascii_hexdigit()) {
                return format!("fe80::{}", &rest[pos + 2..]);
            }
        }
    }

    addr.to_string()
}

// ---------------------------------------------------------------------------
// Multi-interface deduplication deque
// ---------------------------------------------------------------------------

/// Ring buffer for cross-interface packet deduplication.
///
/// When the same packet arrives on multiple OS interfaces, only the first
/// copy should be processed. MifDeque stores recent packet hashes with
/// timestamps and rejects duplicates within the TTL window.
///
/// (Python: MULTI_IF_DEQUE_LEN = 48, MULTI_IF_DEQUE_TTL = 0.75s)
pub struct MifDeque {
    entries: VecDeque<(Hash, Instant)>,
}

impl MifDeque {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MULTI_IF_DEQUE_LEN),
        }
    }

    /// Check if a packet hash was recently seen (within TTL window).
    pub fn is_duplicate(&self, hash: &Hash) -> bool {
        let cutoff = Instant::now() - MULTI_IF_DEQUE_TTL;
        self.entries
            .iter()
            .any(|(h, t)| h == hash && *t > cutoff)
    }

    /// Insert a packet hash into the deque, evicting oldest entries if at capacity.
    pub fn insert(&mut self, hash: Hash) {
        // Evict expired entries
        let cutoff = Instant::now() - MULTI_IF_DEQUE_TTL;
        while let Some((_, t)) = self.entries.front() {
            if *t <= cutoff {
                self.entries.pop_front();
            } else {
                break;
            }
        }

        // Evict oldest if at capacity
        while self.entries.len() >= MULTI_IF_DEQUE_LEN {
            self.entries.pop_front();
        }

        self.entries.push_back((hash, Instant::now()));
    }
}

// ---------------------------------------------------------------------------
// Adopted interface — per-OS-interface state
// ---------------------------------------------------------------------------

/// State for a network interface that has been adopted for peering.
#[derive(Debug, Clone)]
pub struct AdoptedInterface {
    /// OS interface name (e.g. "en0")
    pub name: String,
    /// Descoped link-local address as string (used for hash computation)
    pub link_local_addr: String,
    /// Parsed IPv6 address (for socket binding)
    pub link_local_ipv6: Ipv6Addr,
    /// OS-level scope/interface index
    pub scope_id: u32,
}

// ---------------------------------------------------------------------------
// Peer
// ---------------------------------------------------------------------------

/// Discovered peer information, matching Python's `self.peers[addr] = [ifname, last_heard, last_outbound]`.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Peer IPv6 address string (descoped, e.g. "fe80::1234:5678")
    pub addr: String,
    /// OS interface this peer was discovered on
    pub ifname: String,
    /// When this peer was last heard from (for expiry)
    pub last_heard: Instant,
    /// When we last sent a reverse announce to this peer
    pub last_outbound: Instant,
}

impl Peer {
    /// Create a new peer with current timestamps.
    pub fn new(addr: &str, ifname: &str) -> Self {
        let now = Instant::now();
        Self {
            addr: addr.to_string(),
            ifname: ifname.to_string(),
            last_heard: now,
            last_outbound: now,
        }
    }

    /// Check if peer has expired based on the given timeout.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_heard.elapsed() > timeout
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
///
/// Uses `Arc<Self>` with interior mutability for shared access across
/// async tasks. All `RwLock`/`Mutex` fields are held only in synchronous
/// blocks, never across `.await` points.
///
/// AutoInterface itself is NOT registered as a routable interface with
/// InterfaceManager — it doesn't transmit data directly. Instead, each
/// discovered peer gets a spawned `AutoInterfacePeer` interface that IS
/// registered for routing. The parent handles RX centrally, while each
/// peer handles its own TX.
pub struct AutoInterface {
    /// Configuration (immutable after construction)
    config: AutoInterfaceConfig,
    /// Lifecycle state
    state: RwLock<AutoInterfaceState>,
    /// Discovered peers, keyed by descoped IPv6 address string
    peers: RwLock<HashMap<String, Peer>>,
    /// Adopted OS interfaces, keyed by interface name
    adopted_interfaces: RwLock<HashMap<String, AdoptedInterface>>,
    /// All local link-local addresses (descoped strings) for self-echo detection
    link_local_addresses: RwLock<Vec<String>>,
    /// Last multicast echo timestamp per interface — carrier detection
    multicast_echoes: RwLock<HashMap<String, Instant>>,
    /// First multicast echo per interface — used to avoid false positive on startup
    initial_echoes: RwLock<HashMap<String, Instant>>,
    /// Interfaces that have timed out (carrier lost)
    timed_out_interfaces: RwLock<HashMap<String, bool>>,
    /// Cross-interface packet deduplication
    mif_deque: std::sync::Mutex<MifDeque>,
    /// True after initial peering delay has elapsed
    final_init_done: AtomicBool,
    /// True when the interface is fully online
    online: AtomicBool,
    /// Set when carrier state changes (for external polling)
    carrier_changed: AtomicBool,

    // -- Peer management fields (initialized by run()) --

    /// Spawned peer interfaces keyed by descoped IPv6 address.
    spawned_interfaces: RwLock<HashMap<String, SpawnedPeerInfo>>,
    /// Shared outbound UDP socket for all peers (lazy-init via run()).
    outbound_socket: tokio::sync::OnceCell<Arc<tokio::net::UdpSocket>>,
    /// Command channel sender for async peer spawn/teardown.
    /// Set once by run(); add_peer/run_peer_jobs send commands through this.
    peer_command_tx: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<PeerCommand>>,
}

impl AutoInterface {
    /// Create a new AutoInterface with the given configuration.
    pub fn new(config: AutoInterfaceConfig) -> Self {
        Self {
            config,
            state: RwLock::new(AutoInterfaceState::Stopped),
            peers: RwLock::new(HashMap::new()),
            adopted_interfaces: RwLock::new(HashMap::new()),
            link_local_addresses: RwLock::new(Vec::new()),
            multicast_echoes: RwLock::new(HashMap::new()),
            initial_echoes: RwLock::new(HashMap::new()),
            timed_out_interfaces: RwLock::new(HashMap::new()),
            mif_deque: std::sync::Mutex::new(MifDeque::new()),
            final_init_done: AtomicBool::new(false),
            online: AtomicBool::new(false),
            carrier_changed: AtomicBool::new(false),
            spawned_interfaces: RwLock::new(HashMap::new()),
            outbound_socket: tokio::sync::OnceCell::new(),
            peer_command_tx: std::sync::OnceLock::new(),
        }
    }

    /// Get current lifecycle state.
    pub fn state(&self) -> AutoInterfaceState {
        *self.state.read().unwrap()
    }

    /// Whether the interface has completed initialization and is online.
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }

    /// Whether the initial peering delay has elapsed.
    pub fn is_final_init_done(&self) -> bool {
        self.final_init_done.load(Ordering::SeqCst)
    }

    /// Get configuration.
    pub fn config(&self) -> &AutoInterfaceConfig {
        &self.config
    }

    /// Get snapshot of all discovered peers.
    pub fn peers(&self) -> Vec<Peer> {
        self.peers.read().unwrap().values().cloned().collect()
    }

    /// Get peer count.
    pub fn peer_count(&self) -> usize {
        self.peers.read().unwrap().len()
    }

    /// Check if a peer exists by address string.
    pub fn has_peer(&self, addr: &str) -> bool {
        self.peers.read().unwrap().contains_key(addr)
    }

    /// Get the multicast discovery socket address.
    pub fn multicast_group(&self) -> SocketAddrV6 {
        self.config.multicast_group()
    }

    /// Get all link-local addresses (descoped).
    pub fn link_local_addresses(&self) -> Vec<String> {
        self.link_local_addresses.read().unwrap().clone()
    }

    /// Check if an address is one of our own.
    pub fn is_local_address(&self, addr: &str) -> bool {
        self.link_local_addresses.read().unwrap().contains(&addr.to_string())
    }

    // -----------------------------------------------------------------------
    // Peer management — matches Python AutoInterface.add_peer / refresh_peer
    // -----------------------------------------------------------------------

    /// Add a new peer or update an existing one.
    ///
    /// If `addr` is one of our own link-local addresses, this is a multicast echo
    /// and we update the echo tracking instead of the peer table.
    ///
    /// Matches Python AutoInterface.py add_peer() lines 513-571.
    fn add_peer(&self, addr: &str, ifname: &str) {
        // Check if this is our own multicast echo
        {
            let link_locals = self.link_local_addresses.read().unwrap();
            if link_locals.iter().any(|a| a == addr) {
                drop(link_locals);

                // Find which adopted interface this address belongs to
                let echo_ifname = {
                    let adopted = self.adopted_interfaces.read().unwrap();
                    adopted
                        .iter()
                        .find(|(_, ai)| ai.link_local_addr == addr)
                        .map(|(name, _)| name.clone())
                };

                if let Some(echo_ifname) = echo_ifname {
                    self.multicast_echoes
                        .write()
                        .unwrap()
                        .insert(echo_ifname.clone(), Instant::now());
                    self.initial_echoes
                        .write()
                        .unwrap()
                        .entry(echo_ifname)
                        .or_insert_with(Instant::now);
                } else {
                    log::warn!(
                        "AutoInterface: received echo from own address {} but no matching interface",
                        addr
                    );
                }
                return;
            }
        }

        // Remote peer — add or refresh
        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.get_mut(addr) {
            peer.last_heard = Instant::now();
        } else {
            log::debug!("AutoInterface: added peer {} on {}", addr, ifname);
            peers.insert(addr.to_string(), Peer::new(addr, ifname));

            // Send spawn command to the async peer_spawn_task (if running).
            // Gracefully skips when run() hasn't been called (standalone tests).
            if let Some(tx) = self.peer_command_tx.get() {
                let _ = tx.send(PeerCommand::Spawn {
                    addr: addr.to_string(),
                    ifname: ifname.to_string(),
                });
            }
        }
    }

    /// Refresh a peer's last_heard timestamp (for data traffic).
    fn refresh_peer(&self, addr: &str) {
        if let Some(peer) = self.peers.write().unwrap().get_mut(addr) {
            peer.last_heard = Instant::now();
        }
    }

    // -----------------------------------------------------------------------
    // Announce methods — send discovery tokens
    // -----------------------------------------------------------------------

    /// Send a multicast discovery announcement on the given interface.
    ///
    /// Creates a fresh UDP socket per call (matching Python behavior).
    /// Matches Python AutoInterface.py peer_announce() lines 491-507.
    fn peer_announce(&self, ifname: &str) -> std::io::Result<()> {
        let (link_local_addr, scope_id) = {
            let adopted = self.adopted_interfaces.read().unwrap();
            let ai = adopted.get(ifname).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "interface not adopted")
            })?;
            (ai.link_local_addr.clone(), ai.scope_id)
        };

        let token = create_discovery_token(&self.config.group_id, &link_local_addr);
        let mcast_addr = self.config.multicast_discovery_address();

        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_multicast_if_v6(scope_id)?;

        let dest = socket2::SockAddr::from(SocketAddrV6::new(
            mcast_addr,
            self.config.discovery_port,
            0,
            scope_id,
        ));
        socket.send_to(&token, &dest)?;

        Ok(())
    }

    /// Send a unicast reverse discovery announcement to a specific peer.
    ///
    /// Matches Python AutoInterface.py reverse_announce() lines 477-489.
    fn reverse_announce(&self, ifname: &str, peer_addr: &str) -> std::io::Result<()> {
        let (link_local_addr, scope_id) = {
            let adopted = self.adopted_interfaces.read().unwrap();
            let ai = adopted.get(ifname).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "interface not adopted")
            })?;
            (ai.link_local_addr.clone(), ai.scope_id)
        };

        let token = create_discovery_token(&self.config.group_id, &link_local_addr);

        let peer_ipv6: Ipv6Addr = peer_addr.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IPv6 address '{}': {}", peer_addr, e),
            )
        })?;

        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        let dest = socket2::SockAddr::from(SocketAddrV6::new(
            peer_ipv6,
            self.config.unicast_discovery_port(),
            0,
            scope_id,
        ));
        socket.send_to(&token, &dest)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Peer job — periodic maintenance
    // -----------------------------------------------------------------------

    /// Run periodic peer management tasks.
    ///
    /// Matches Python AutoInterface.py peer_jobs() lines 371-468:
    /// 1. Expire stale peers
    /// 2. Send reverse announces to peers that haven't heard from us recently
    /// 3. Check multicast echo status for carrier detection
    fn run_peer_jobs(&self) {
        let now = Instant::now();

        // 1. Expire stale peers and send teardown commands for spawned interfaces
        {
            let mut peers = self.peers.write().unwrap();
            let before = peers.len();
            let mut expired_addrs = Vec::new();
            peers.retain(|addr, peer| {
                if now.duration_since(peer.last_heard) > self.config.peering_timeout {
                    log::debug!("AutoInterface: peer {} on {} timed out", addr, peer.ifname);
                    expired_addrs.push(addr.clone());
                    false
                } else {
                    true
                }
            });
            let removed = before - peers.len();
            if removed > 0 {
                log::debug!(
                    "AutoInterface: {} peers removed, {} remaining",
                    removed,
                    peers.len()
                );
            }

            // Send teardown commands for expired peers (outside the peers lock)
            if let Some(tx) = self.peer_command_tx.get() {
                for addr in expired_addrs {
                    let _ = tx.send(PeerCommand::Teardown { addr });
                }
            }
        }

        // 2. Reverse peering — send announces to peers we haven't contacted recently
        let reverse_interval = self.config.reverse_peering_interval();
        let peers_needing_reverse: Vec<(String, String)> = {
            let peers = self.peers.read().unwrap();
            peers
                .iter()
                .filter(|(_, peer)| now.duration_since(peer.last_outbound) > reverse_interval)
                .map(|(addr, peer)| (addr.clone(), peer.ifname.clone()))
                .collect()
        };

        for (peer_addr, ifname) in &peers_needing_reverse {
            if let Err(e) = self.reverse_announce(ifname, peer_addr) {
                log::debug!(
                    "AutoInterface: reverse announce to {} on {} failed: {}",
                    peer_addr,
                    ifname,
                    e
                );
            }
            // Update last_outbound regardless of success (avoid tight retry loops)
            if let Some(peer) = self.peers.write().unwrap().get_mut(peer_addr.as_str()) {
                peer.last_outbound = Instant::now();
            }
        }

        // 3. Multicast echo check — carrier detection
        {
            let echoes = self.multicast_echoes.read().unwrap();
            let initial = self.initial_echoes.read().unwrap();
            let mut timed_out = self.timed_out_interfaces.write().unwrap();
            let adopted = self.adopted_interfaces.read().unwrap();

            for ifname in adopted.keys() {
                let was_timed_out = timed_out.get(ifname).copied().unwrap_or(false);

                if let Some(last_echo) = echoes.get(ifname) {
                    if now.duration_since(*last_echo) > MCAST_ECHO_TIMEOUT {
                        // Only report carrier loss if we've received at least one echo before
                        if !was_timed_out && initial.contains_key(ifname) {
                            log::warn!(
                                "AutoInterface: multicast echo timeout on {}, carrier lost",
                                ifname
                            );
                            timed_out.insert(ifname.clone(), true);
                            self.carrier_changed.store(true, Ordering::SeqCst);
                        }
                    } else if was_timed_out {
                        log::info!(
                            "AutoInterface: multicast echo resumed on {}, carrier recovered",
                            ifname
                        );
                        timed_out.insert(ifname.clone(), false);
                        self.carrier_changed.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
    }
}

impl Interface for AutoInterface {
    fn mtu() -> usize {
        HW_MTU
    }
}

// ---------------------------------------------------------------------------
// Socket setup helpers
// ---------------------------------------------------------------------------

/// Create a multicast discovery socket bound to the multicast group on a specific interface.
///
/// Matches Python AutoInterface.py lines 275-297.
fn create_multicast_socket(
    mcast_addr: &Ipv6Addr,
    port: u16,
    scope_id: u32,
    scope: DiscoveryScope,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_multicast_if_v6(scope_id)?;
    socket.join_multicast_v6(mcast_addr, scope_id)?;

    // Bind address: for link scope, include scope_id; for other scopes, omit it.
    // This matches Python's getaddrinfo behavior with/without %ifname.
    let bind_addr = if scope == DiscoveryScope::Link {
        SocketAddrV6::new(*mcast_addr, port, 0, scope_id)
    } else {
        SocketAddrV6::new(*mcast_addr, port, 0, 0)
    };
    socket.bind(&socket2::SockAddr::from(bind_addr))?;
    socket.set_nonblocking(true)?;

    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}

/// Create a unicast UDP socket bound to a link-local address on a specific interface.
///
/// Used for both the unicast discovery socket and the data socket.
/// Matches Python AutoInterface.py lines 256-269 (unicast) and 332-342 (data).
fn create_udp_socket(
    link_local_addr: &Ipv6Addr,
    port: u16,
    scope_id: u32,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;

    let bind_addr = SocketAddrV6::new(*link_local_addr, port, 0, scope_id);
    socket.bind(&socket2::SockAddr::from(bind_addr))?;
    socket.set_nonblocking(true)?;

    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}

/// Create an unbound IPv6 UDP socket for outgoing peer data.
///
/// This matches Python's `outbound_udp_socket` — a single socket shared by all
/// peers for sending data. The OS selects the source address based on routing.
/// Using `send_to` with a `SocketAddrV6` that includes the correct `scope_id`
/// ensures the packet goes out the right OS interface for link-local addresses.
fn create_outbound_socket() -> std::io::Result<Arc<tokio::net::UdpSocket>> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    // Bind to unspecified address with OS-assigned port (matching Python's unbound socket)
    let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
    socket.bind(&socket2::SockAddr::from(bind_addr))?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;
    Ok(Arc::new(tokio_socket))
}

// ---------------------------------------------------------------------------
// Async task architecture
// ---------------------------------------------------------------------------

impl AutoInterface {
    /// Main entry point — enumerate interfaces, set up sockets, and run discovery.
    ///
    /// This method spawns per-interface discovery tasks, a shared peer job task,
    /// and a peer spawn task that processes PeerCommand messages. Waits for the
    /// initial peering delay, then marks the interface online.
    ///
    /// # Arguments
    /// * `cancel` — Cancellation token for graceful shutdown.
    /// * `iface_manager` — Optional InterfaceManager for spawning peer interfaces.
    ///   When None (standalone tests), discovery still works but peers are not
    ///   registered with transport and data is not forwarded.
    pub async fn run(
        self: Arc<Self>,
        cancel: CancellationToken,
        iface_manager: Option<Arc<tokio::sync::Mutex<InterfaceManager>>>,
    ) -> std::io::Result<()> {
        *self.state.write().unwrap() = AutoInterfaceState::Starting;

        // 1. Enumerate and adopt interfaces
        let interfaces = enumerate_interfaces(
            &self.config.allowed_interfaces,
            &self.config.ignored_interfaces,
        );

        if interfaces.is_empty() {
            log::warn!("AutoInterface: no suitable network interfaces found");
            *self.state.write().unwrap() = AutoInterfaceState::Error;
            return Ok(());
        }

        {
            let mut adopted = self.adopted_interfaces.write().unwrap();
            let mut link_locals = self.link_local_addresses.write().unwrap();
            for iface in &interfaces {
                let descoped = descope_linklocal(&iface.link_local_addr.to_string());
                log::info!(
                    "AutoInterface: adopting {} ({}, scope_id={})",
                    iface.name,
                    descoped,
                    iface.scope_id
                );
                adopted.insert(
                    iface.name.clone(),
                    AdoptedInterface {
                        name: iface.name.clone(),
                        link_local_addr: descoped.clone(),
                        link_local_ipv6: iface.link_local_addr,
                        scope_id: iface.scope_id,
                    },
                );
                link_locals.push(descoped);
            }
        }

        // 2. Set up transport integration (if iface_manager is provided)
        let interface_name = format!("AutoInterface[{}]", self.config.group_id);
        let parent_address =
            AddressHash::new_from_hash(&Hash::new_from_slice(interface_name.as_bytes()));
        let rx_sender: Option<InterfaceRxSender>;
        let interface_registry: Option<Arc<InterfaceRegistry>>;

        if let Some(ref mgr) = iface_manager {
            let mgr_locked = mgr.lock().await;
            rx_sender = Some(mgr_locked.rx_sender());
            interface_registry = mgr_locked.interface_registry();
            drop(mgr_locked);

            // Register parent metadata (IN=true, OUT=false — parent receives but doesn't transmit)
            if let Some(ref reg) = interface_registry {
                let parent_meta = Arc::new(
                    InterfaceMetadata::new(
                        &interface_name,
                        &format!("auto:{}", self.config.group_id),
                        "AutoInterface",
                        "",
                    )
                    .with_hw_mtu(HW_MTU)
                    .with_bitrate(self.config.configured_bitrate.unwrap_or(BITRATE_GUESS))
                    .with_direction(true, false),
                );
                parent_meta.set_online(true);
                reg.register(parent_address, parent_meta).await;
            }

            // Set up PeerCommand channel
            let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<PeerCommand>();
            let _ = self.peer_command_tx.set(cmd_tx);

            // Spawn peer_spawn_task
            let auto_for_spawn = Arc::clone(&self);
            let cancel_for_spawn = cancel.clone();
            let mgr_for_spawn = Arc::clone(mgr);
            let reg_for_spawn = interface_registry.clone();
            tokio::spawn(async move {
                auto_for_spawn
                    .peer_spawn_task(
                        cmd_rx,
                        mgr_for_spawn,
                        reg_for_spawn,
                        parent_address,
                        &cancel_for_spawn,
                    )
                    .await;
            });
        } else {
            rx_sender = None;
            interface_registry = None;
        }

        let mcast_addr = self.config.multicast_discovery_address();
        let mut task_handles = Vec::new();

        // 3. Create sockets and spawn per-interface tasks
        for iface in &interfaces {
            // Multicast discovery socket
            match create_multicast_socket(
                &mcast_addr,
                self.config.discovery_port,
                iface.scope_id,
                self.config.discovery_scope,
            ) {
                Ok(sock) => {
                    let auto = Arc::clone(&self);
                    let cancel = cancel.clone();
                    let ifname = iface.name.clone();
                    task_handles.push(tokio::spawn(async move {
                        auto.discovery_task(&ifname, sock, &cancel).await;
                    }));
                }
                Err(e) => {
                    log::error!(
                        "AutoInterface: failed to create multicast socket for {}: {}",
                        iface.name,
                        e
                    );
                }
            }

            // Unicast discovery socket
            match create_udp_socket(
                &iface.link_local_addr,
                self.config.unicast_discovery_port(),
                iface.scope_id,
            ) {
                Ok(sock) => {
                    let auto = Arc::clone(&self);
                    let cancel = cancel.clone();
                    let ifname = iface.name.clone();
                    task_handles.push(tokio::spawn(async move {
                        auto.unicast_discovery_task(&ifname, sock, &cancel).await;
                    }));
                }
                Err(e) => {
                    log::error!(
                        "AutoInterface: failed to create unicast socket for {}: {}",
                        iface.name,
                        e
                    );
                }
            }

            // Data socket
            match create_udp_socket(&iface.link_local_addr, self.config.data_port, iface.scope_id)
            {
                Ok(sock) => {
                    let auto = Arc::clone(&self);
                    let cancel = cancel.clone();
                    let ifname = iface.name.clone();
                    let rx_tx = rx_sender.clone();
                    task_handles.push(tokio::spawn(async move {
                        auto.data_recv_task(&ifname, sock, &cancel, rx_tx, parent_address)
                            .await;
                    }));
                }
                Err(e) => {
                    log::error!(
                        "AutoInterface: failed to create data socket for {}: {}",
                        iface.name,
                        e
                    );
                }
            }
        }

        // 4. Spawn shared peer job task
        {
            let auto = Arc::clone(&self);
            let cancel = cancel.clone();
            task_handles.push(tokio::spawn(async move {
                auto.peer_job_task(&cancel).await;
            }));
        }

        // 5. Initial peering delay — matches Python's final_init()
        let init_delay =
            Duration::from_secs_f64(self.config.announce_interval.as_secs_f64() * 1.2);
        tokio::select! {
            _ = cancel.cancelled() => {
                // Cancelled during init — clean up
                *self.state.write().unwrap() = AutoInterfaceState::Stopped;
                for handle in task_handles {
                    let _ = handle.await;
                }
                return Ok(());
            }
            _ = tokio::time::sleep(init_delay) => {}
        }

        self.final_init_done.store(true, Ordering::SeqCst);
        self.online.store(true, Ordering::SeqCst);
        *self.state.write().unwrap() = AutoInterfaceState::Running;
        log::info!(
            "AutoInterface: online, {} interfaces adopted",
            interfaces.len()
        );

        // 6. Wait for cancellation
        cancel.cancelled().await;

        // 7. Shutdown
        self.online.store(false, Ordering::SeqCst);
        *self.state.write().unwrap() = AutoInterfaceState::Stopped;

        // Teardown all spawned peers
        {
            let spawned = self.spawned_interfaces.read().unwrap();
            for (_, info) in spawned.iter() {
                info.stop.cancel();
                info.metadata.set_online(false);
            }
        }

        // Unregister parent from interface registry
        if let Some(ref reg) = interface_registry {
            reg.unregister(&parent_address).await;
        }

        for handle in task_handles {
            let _ = handle.await;
        }

        log::info!("AutoInterface: shut down");
        Ok(())
    }

    /// Async task that processes PeerCommand messages to spawn and teardown
    /// peer interfaces via InterfaceManager.
    ///
    /// This task bridges the sync add_peer()/run_peer_jobs() world (which holds
    /// std::sync::RwLock and cannot await) with the async InterfaceManager::spawn().
    async fn peer_spawn_task(
        self: &Arc<Self>,
        mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<PeerCommand>,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
        interface_registry: Option<Arc<InterfaceRegistry>>,
        parent_address: AddressHash,
        cancel: &CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(PeerCommand::Spawn { addr, ifname }) => {
                            // Check if already spawned
                            {
                                let spawned = self.spawned_interfaces.read().unwrap();
                                if spawned.contains_key(&addr) {
                                    continue;
                                }
                            }

                            // Look up scope_id from adopted interfaces
                            let scope_id = {
                                let adopted = self.adopted_interfaces.read().unwrap();
                                match adopted.get(&ifname) {
                                    Some(ai) => ai.scope_id,
                                    None => {
                                        log::warn!(
                                            "AutoInterface: cannot spawn peer {} — interface {} not adopted",
                                            addr,
                                            ifname
                                        );
                                        continue;
                                    }
                                }
                            };

                            // Initialize the shared outbound socket (lazy, once)
                            let outbound_socket = match self.outbound_socket.get_or_try_init(|| async {
                                create_outbound_socket()
                            }).await {
                                Ok(sock) => sock.clone(),
                                Err(e) => {
                                    log::error!(
                                        "AutoInterface: failed to create outbound socket: {}",
                                        e
                                    );
                                    continue;
                                }
                            };

                            // Create the peer interface
                            let peer = AutoInterfacePeer {
                                addr: addr.clone(),
                                ifname: ifname.clone(),
                                scope_id,
                                data_port: self.config.data_port,
                                outbound_socket,
                                parent_address,
                            };

                            let peer_name = format!("AutoInterfacePeer[{}]", addr);

                            // Spawn via InterfaceManager — this registers the channel
                            // and starts the TX worker task
                            let (address, stop) = {
                                let mut mgr = iface_manager.lock().await;
                                mgr.spawn_with_stop(peer, AutoInterfacePeer::spawn, &peer_name)
                            };

                            // Build metadata for tracking (mirrors what spawn() creates internally).
                            // We need our own reference for RX stats updates in data_recv_task.
                            let metadata = Arc::new(
                                InterfaceMetadata::new(
                                    &peer_name,
                                    &format!("peer:{}", addr),
                                    "AutoInterfacePeer",
                                    &addr,
                                )
                                .with_parent(parent_address)
                                .with_hw_mtu(HW_MTU)
                                .with_bitrate(BITRATE_GUESS)
                                .with_direction(true, true),
                            );

                            // Store tracking info
                            {
                                let mut spawned = self.spawned_interfaces.write().unwrap();
                                spawned.insert(
                                    addr.clone(),
                                    SpawnedPeerInfo {
                                        address,
                                        stop,
                                        metadata,
                                    },
                                );
                            }

                            log::info!(
                                "AutoInterface: spawned peer interface {} ({}) on {}",
                                addr,
                                address,
                                ifname
                            );
                        }
                        Some(PeerCommand::Teardown { addr }) => {
                            let info = {
                                let mut spawned = self.spawned_interfaces.write().unwrap();
                                spawned.remove(&addr)
                            };

                            if let Some(info) = info {
                                // Cancel the peer's worker task
                                info.stop.cancel();
                                info.metadata.set_online(false);

                                // Unregister from interface registry
                                if let Some(ref reg) = interface_registry {
                                    reg.unregister(&info.address).await;
                                }

                                // Clean up stopped interfaces from InterfaceManager
                                {
                                    let mut mgr = iface_manager.lock().await;
                                    mgr.cleanup();
                                }

                                log::info!(
                                    "AutoInterface: torn down peer interface {} ({})",
                                    addr,
                                    info.address
                                );
                            }
                        }
                        None => break, // Channel closed
                    }
                }
            }
        }
    }

    /// Multicast discovery task — sends periodic announces and processes incoming
    /// discovery tokens on the multicast socket.
    ///
    /// Matches Python AutoInterface.py discovery_handler() + announce_handler().
    async fn discovery_task(
        &self,
        ifname: &str,
        socket: tokio::net::UdpSocket,
        cancel: &CancellationToken,
    ) {
        let mut buf = [0u8; 1024];
        let mut announce_interval = tokio::time::interval(self.config.announce_interval);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = announce_interval.tick() => {
                    if let Err(e) = self.peer_announce(ifname) {
                        log::debug!("AutoInterface: announce failed on {}: {}", ifname, e);
                    }
                }
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => {
                            if !self.final_init_done.load(Ordering::SeqCst) {
                                continue;
                            }
                            if let std::net::SocketAddr::V6(v6) = addr {
                                let sender_addr = descope_linklocal(&v6.ip().to_string());
                                let data = &buf[..len];
                                if validate_discovery_token(
                                    &self.config.group_id,
                                    data,
                                    &sender_addr,
                                ) {
                                    self.add_peer(&sender_addr, ifname);
                                } else {
                                    log::debug!(
                                        "AutoInterface: invalid discovery token on {} from {}",
                                        ifname,
                                        sender_addr
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            if cancel.is_cancelled() {
                                break;
                            }
                            log::debug!("AutoInterface: recv error on {}: {}", ifname, e);
                        }
                    }
                }
            }
        }
    }

    /// Unicast discovery task — listens for unicast reverse announces.
    ///
    /// Same validation as multicast discovery, but no outgoing announces.
    /// Matches Python's unicast discovery_handler (announce=False).
    async fn unicast_discovery_task(
        &self,
        ifname: &str,
        socket: tokio::net::UdpSocket,
        cancel: &CancellationToken,
    ) {
        let mut buf = [0u8; 1024];

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => {
                            if !self.final_init_done.load(Ordering::SeqCst) {
                                continue;
                            }
                            if let std::net::SocketAddr::V6(v6) = addr {
                                let sender_addr = descope_linklocal(&v6.ip().to_string());
                                let data = &buf[..len];
                                if validate_discovery_token(
                                    &self.config.group_id,
                                    data,
                                    &sender_addr,
                                ) {
                                    self.add_peer(&sender_addr, ifname);
                                } else {
                                    log::debug!(
                                        "AutoInterface: invalid unicast token on {} from {}",
                                        ifname,
                                        sender_addr
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            if cancel.is_cancelled() {
                                break;
                            }
                            log::debug!("AutoInterface: unicast recv error on {}: {}", ifname, e);
                        }
                    }
                }
            }
        }
    }

    /// Data receive task — receives data packets, deduplicates via MifDeque,
    /// refreshes peer timestamps, and forwards to transport.
    ///
    /// RX is handled centrally by the parent (one task per OS interface) rather
    /// than per-peer, because all peers share the same data port and we need
    /// cross-interface deduplication. The peer's AddressHash is looked up to
    /// attribute the packet to the correct spawned interface for transport.
    ///
    /// Matches Python AutoInterface.py data handler lines 603-619.
    async fn data_recv_task(
        &self,
        ifname: &str,
        socket: tokio::net::UdpSocket,
        cancel: &CancellationToken,
        rx_sender: Option<InterfaceRxSender>,
        parent_address: AddressHash,
    ) {
        // Extra headroom beyond MTU for potential framing
        let mut buf = vec![0u8; HW_MTU + 128];

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => {
                            if !self.final_init_done.load(Ordering::SeqCst) {
                                continue;
                            }

                            let data = &buf[..len];

                            // Deduplicate via MifDeque
                            let data_hash = Hash::new_from_slice(data);
                            {
                                let mut deque = self.mif_deque.lock().unwrap();
                                if deque.is_duplicate(&data_hash) {
                                    continue;
                                }
                                deque.insert(data_hash);
                            }

                            // Resolve sender address and look up peer
                            let sender_addr = if let std::net::SocketAddr::V6(v6) = addr {
                                let descoped = descope_linklocal(&v6.ip().to_string());
                                self.refresh_peer(&descoped);
                                descoped
                            } else {
                                continue;
                            };

                            // Forward to transport if rx_sender is available
                            if let Some(ref rx) = rx_sender {
                                // Look up the peer's interface address hash and
                                // update RX stats — all done synchronously before await
                                let source_address = {
                                    let spawned = self.spawned_interfaces.read().unwrap();
                                    if let Some(info) = spawned.get(&sender_addr) {
                                        info.metadata.add_rx_bytes(len as u64);
                                        info.address
                                    } else {
                                        // Peer not yet spawned — use parent address
                                        parent_address
                                    }
                                };

                                // Deserialize the raw UDP data into a Packet
                                match crate::packet::Packet::deserialize(
                                    &mut InputBuffer::new(data),
                                ) {
                                    Ok(packet) => {
                                        let _ = rx.send(RxMessage {
                                            address: source_address,
                                            packet,
                                        }).await;
                                    }
                                    Err(e) => {
                                        log::debug!(
                                            "AutoInterface: packet deserialize error on {} from {}: {}",
                                            ifname,
                                            sender_addr,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            if cancel.is_cancelled() {
                                break;
                            }
                            log::debug!("AutoInterface: data recv error on {}: {}", ifname, e);
                        }
                    }
                }
            }
        }
    }

    /// Peer job task — runs periodic maintenance on the peer table.
    ///
    /// Matches Python AutoInterface.py peer_jobs thread.
    async fn peer_job_task(&self, cancel: &CancellationToken) {
        let mut interval = tokio::time::interval(PEER_JOB_INTERVAL);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    self.run_peer_jobs();
                }
            }
        }
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
        let config = AutoInterfaceConfig::new();
        let addr = config.multicast_discovery_address();
        assert_eq!(addr.segments()[0], 0xff12);
        assert_eq!(addr.segments()[1], 0);
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

        assert_eq!(addr_a.segments()[0], addr_b.segments()[0]);
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
            kiss_framing: false,
            i2p_tunneled: false,
            connect_timeout: None,
            max_reconnect_tries: None,
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

    // -- Config derived methods --

    #[test]
    fn test_unicast_discovery_port() {
        let config = AutoInterfaceConfig::new();
        assert_eq!(config.unicast_discovery_port(), DEFAULT_DISCOVERY_PORT + 1);
        assert_eq!(config.unicast_discovery_port(), 29717);
    }

    #[test]
    fn test_reverse_peering_interval() {
        let config = AutoInterfaceConfig::new();
        let expected = Duration::from_secs_f64(1.6 * 3.25);
        let actual = config.reverse_peering_interval();
        // Compare as millis to avoid floating-point precision issues
        assert_eq!(actual.as_millis(), expected.as_millis());
    }

    // -- Discovery token tests --

    #[test]
    fn test_discovery_token_deterministic() {
        let token1 = create_discovery_token("reticulum", "fe80::1");
        let token2 = create_discovery_token("reticulum", "fe80::1");
        assert_eq!(token1, token2);
        assert_eq!(token1.len(), 32);
    }

    #[test]
    fn test_discovery_token_matches_manual_sha256() {
        // Verify that our token matches a direct SHA-256 of the concatenated bytes.
        // This is the same computation Python performs:
        //   full_hash(group_id + link_local_address.encode("utf-8"))
        let token = create_discovery_token("reticulum", "fe80::1");

        let mut hasher = sha2::Sha256::new();
        hasher.update(b"reticulum");
        hasher.update(b"fe80::1");
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(token, expected);
    }

    #[test]
    fn test_discovery_token_different_inputs() {
        let token_a = create_discovery_token("reticulum", "fe80::1");
        let token_b = create_discovery_token("reticulum", "fe80::2");
        let token_c = create_discovery_token("other_group", "fe80::1");
        assert_ne!(token_a, token_b);
        assert_ne!(token_a, token_c);
        assert_ne!(token_b, token_c);
    }

    #[test]
    fn test_validate_discovery_token_valid() {
        let token = create_discovery_token("reticulum", "fe80::1");
        assert!(validate_discovery_token("reticulum", &token, "fe80::1"));
    }

    #[test]
    fn test_validate_discovery_token_wrong_sender() {
        let token = create_discovery_token("reticulum", "fe80::1");
        assert!(!validate_discovery_token("reticulum", &token, "fe80::2"));
    }

    #[test]
    fn test_validate_discovery_token_wrong_group() {
        let token = create_discovery_token("reticulum", "fe80::1");
        assert!(!validate_discovery_token("other_group", &token, "fe80::1"));
    }

    #[test]
    fn test_validate_discovery_token_too_short() {
        assert!(!validate_discovery_token("reticulum", &[0u8; 31], "fe80::1"));
        assert!(!validate_discovery_token("reticulum", &[], "fe80::1"));
    }

    #[test]
    fn test_validate_discovery_token_extra_data_ignored() {
        // Python only checks first HASHLENGTH//8 = 32 bytes
        let mut data = create_discovery_token("reticulum", "fe80::1").to_vec();
        data.extend_from_slice(b"extra garbage");
        assert!(validate_discovery_token("reticulum", &data, "fe80::1"));
    }

    // -- descope_linklocal tests --

    #[test]
    fn test_descope_linklocal_clean_passthrough() {
        assert_eq!(descope_linklocal("fe80::1"), "fe80::1");
        assert_eq!(
            descope_linklocal("fe80::abcd:ef01:2345:6789"),
            "fe80::abcd:ef01:2345:6789"
        );
    }

    #[test]
    fn test_descope_linklocal_strip_ifname() {
        // macOS format: fe80::1%en0
        assert_eq!(descope_linklocal("fe80::1%en0"), "fe80::1");
        assert_eq!(
            descope_linklocal("fe80::abcd:1234%wlan0"),
            "fe80::abcd:1234"
        );
    }

    #[test]
    fn test_descope_linklocal_strip_embedded_scope() {
        // NetBSD/OpenBSD: fe80:SCOPE:: embedded in address
        assert_eq!(descope_linklocal("fe80:4::1234"), "fe80::1234");
        assert_eq!(descope_linklocal("fe80:ff::abcd"), "fe80::abcd");
        assert_eq!(descope_linklocal("fe80:0::1"), "fe80::1");
    }

    #[test]
    fn test_descope_linklocal_both() {
        // Both %ifname and embedded scope — %ifname stripped first
        assert_eq!(descope_linklocal("fe80:4::1234%en0"), "fe80::1234");
    }

    // -- MifDeque tests --

    #[test]
    fn test_mif_deque_basic() {
        let mut deque = MifDeque::new();
        let hash1 = Hash::new_from_slice(b"test1");
        let hash2 = Hash::new_from_slice(b"test2");

        assert!(!deque.is_duplicate(&hash1));
        deque.insert(hash1);
        assert!(deque.is_duplicate(&hash1));
        assert!(!deque.is_duplicate(&hash2));
    }

    #[test]
    fn test_mif_deque_capacity() {
        let mut deque = MifDeque::new();

        // Fill beyond capacity
        for i in 0..(MULTI_IF_DEQUE_LEN + 10) {
            let data = format!("packet_{}", i);
            deque.insert(Hash::new_from_slice(data.as_bytes()));
        }

        // Should not exceed capacity
        assert!(deque.entries.len() <= MULTI_IF_DEQUE_LEN);
    }

    #[test]
    fn test_mif_deque_different_hashes_not_duplicate() {
        let mut deque = MifDeque::new();
        let hash1 = Hash::new_from_slice(b"data_a");
        let hash2 = Hash::new_from_slice(b"data_b");

        deque.insert(hash1);
        assert!(!deque.is_duplicate(&hash2));
    }

    // -- Peer tests --

    #[test]
    fn test_peer_creation() {
        let peer = Peer::new("fe80::1", "en0");
        assert_eq!(peer.addr, "fe80::1");
        assert_eq!(peer.ifname, "en0");
        assert!(!peer.is_expired(PEERING_TIMEOUT));
    }

    #[test]
    fn test_peer_expiry() {
        let peer = Peer::new("fe80::1", "en0");
        assert!(!peer.is_expired(PEERING_TIMEOUT));
        // With a zero timeout, the peer should be expired immediately
        assert!(peer.is_expired(Duration::ZERO));
    }

    #[test]
    fn test_auto_interface_add_peer() {
        let config = AutoInterfaceConfig::new();
        let iface = AutoInterface::new(config);

        iface.add_peer("fe80::1", "en0");
        assert!(iface.has_peer("fe80::1"));
        assert_eq!(iface.peer_count(), 1);

        // Adding same peer again should just refresh, not duplicate
        iface.add_peer("fe80::1", "en0");
        assert_eq!(iface.peer_count(), 1);
    }

    #[test]
    fn test_auto_interface_add_peer_own_address_is_echo() {
        let config = AutoInterfaceConfig::new();
        let iface = AutoInterface::new(config);

        // Set up link-local addresses and adopted interfaces
        iface
            .link_local_addresses
            .write()
            .unwrap()
            .push("fe80::1".to_string());
        iface.adopted_interfaces.write().unwrap().insert(
            "en0".to_string(),
            AdoptedInterface {
                name: "en0".to_string(),
                link_local_addr: "fe80::1".to_string(),
                link_local_ipv6: "fe80::1".parse().unwrap(),
                scope_id: 1,
            },
        );

        // Adding our own address should NOT create a peer
        iface.add_peer("fe80::1", "en0");
        assert_eq!(iface.peer_count(), 0);

        // But should update multicast echoes
        let echoes = iface.multicast_echoes.read().unwrap();
        assert!(echoes.contains_key("en0"));

        let initial = iface.initial_echoes.read().unwrap();
        assert!(initial.contains_key("en0"));
    }

    #[test]
    fn test_auto_interface_peers_no_limit() {
        let config = AutoInterfaceConfig::new();
        let iface = AutoInterface::new(config);

        for i in 0..100u16 {
            let addr = format!("fe80::{:x}", i + 1);
            iface.add_peer(&addr, "en0");
        }

        assert_eq!(iface.peer_count(), 100);
    }

    #[test]
    fn test_auto_interface_peer_refresh() {
        let config = AutoInterfaceConfig::new();
        let iface = AutoInterface::new(config);

        iface.add_peer("fe80::1", "en0");
        let original_time = iface.peers.read().unwrap().get("fe80::1").unwrap().last_heard;

        // Small sleep to ensure time advances
        std::thread::sleep(Duration::from_millis(10));

        iface.refresh_peer("fe80::1");
        let refreshed_time = iface.peers.read().unwrap().get("fe80::1").unwrap().last_heard;

        assert!(refreshed_time > original_time);
    }

    #[test]
    fn test_auto_interface_peer_expiry_in_job() {
        let config = AutoInterfaceConfig {
            peering_timeout: Duration::ZERO, // Expire immediately
            ..AutoInterfaceConfig::new()
        };
        let iface = AutoInterface::new(config);

        iface.add_peer("fe80::1", "en0");
        iface.add_peer("fe80::2", "en0");
        assert_eq!(iface.peer_count(), 2);

        // run_peer_jobs should expire all peers (timeout = 0)
        iface.run_peer_jobs();
        assert_eq!(iface.peer_count(), 0);
    }

    // -- Multicast group test --

    #[test]
    fn test_multicast_group() {
        let config = AutoInterfaceConfig::new();
        let iface = AutoInterface::new(config);
        let group = iface.multicast_group();
        assert_eq!(group.port(), DEFAULT_DISCOVERY_PORT);
        assert_eq!(group.ip().segments()[0], 0xff12);
    }

    // -- MTU test --

    #[test]
    fn test_mtu() {
        assert_eq!(AutoInterface::mtu(), HW_MTU);
        assert_eq!(AutoInterface::mtu(), 1196);
    }

    // -- Interface enumeration test --

    #[test]
    fn test_enumerate_interfaces_smoke() {
        let interfaces = enumerate_interfaces(&[], &[]);
        for iface in &interfaces {
            assert!(!iface.name.is_empty());
            assert_eq!(
                iface.link_local_addr.segments()[0] & 0xffc0,
                0xfe80,
                "expected link-local address for {}",
                iface.name,
            );
        }
    }

    // -- IPv6 address string format test --

    #[test]
    fn test_ipv6_canonical_form() {
        // Verify that Rust's Ipv6Addr::to_string() produces the same canonical
        // form as Python for common link-local patterns. Both should follow RFC 5952.
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(addr.to_string(), "fe80::1");

        let addr: Ipv6Addr = "fe80::abcd:ef01:2345:6789".parse().unwrap();
        assert_eq!(addr.to_string(), "fe80::abcd:ef01:2345:6789");

        // Zero-compression: longest run of zeros gets ::
        let addr: Ipv6Addr = "fe80:0:0:0:0:0:0:1".parse().unwrap();
        assert_eq!(addr.to_string(), "fe80::1");

        // Lowercase hex
        let addr: Ipv6Addr = "FE80::ABCD".parse().unwrap();
        assert_eq!(addr.to_string(), "fe80::abcd");
    }
}
