//! Interface statistics tracking.
//!
//! This module provides thread-safe structures for tracking interface metadata
//! and traffic statistics (rx/tx bytes, online status, etc.), as well as
//! announce frequency tracking and ingress control for burst detection.

use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::packet::Packet;

/// How long an interface is considered "new" (2 hours).
/// Python: `IC_NEW_TIME = 2*60*60`
pub const IC_NEW_TIME: Duration = Duration::from_secs(2 * 60 * 60);

/// Number of incoming announce frequency samples to track.
/// Python: `IA_FREQ_SAMPLES = 6`
pub const IA_FREQ_SAMPLES: usize = 6;

/// Number of outgoing announce frequency samples to track.
/// Python: `OA_FREQ_SAMPLES = 6`
pub const OA_FREQ_SAMPLES: usize = 6;

/// Maximum number of held announces per interface.
/// Python: `MAX_HELD_ANNOUNCES = 256`
pub const MAX_HELD_ANNOUNCES: usize = 256;

/// Announce frequency threshold (Hz) for interfaces younger than IC_NEW_TIME.
/// Python: `IC_BURST_FREQ_NEW = 3.5`
pub const IC_BURST_FREQ_NEW: f64 = 3.5;

/// Announce frequency threshold (Hz) for established interfaces.
/// Python: `IC_BURST_FREQ = 12`
pub const IC_BURST_FREQ: f64 = 12.0;

/// Minimum burst mode duration before deactivation is considered.
/// Python: `IC_BURST_HOLD = 1*60`
pub const IC_BURST_HOLD: Duration = Duration::from_secs(60);

/// Penalty delay after burst mode deactivation before releasing held announces.
/// Python: `IC_BURST_PENALTY = 5*60`
pub const IC_BURST_PENALTY: Duration = Duration::from_secs(300);

/// Minimum interval between releasing held announces.
/// Python: `IC_HELD_RELEASE_INTERVAL = 30`
pub const IC_HELD_RELEASE_INTERVAL: Duration = Duration::from_secs(30);

/// Bounded deque of timestamps for computing announce frequency.
///
/// Stores up to `capacity` timestamps and computes the rolling frequency
/// using the Python formula: `num_samples / (sum_of_consecutive_deltas + elapsed_since_last)`.
struct FreqDeque {
    times: VecDeque<Instant>,
    capacity: usize,
}

impl FreqDeque {
    /// Create a new frequency deque with the given maximum capacity.
    fn new(capacity: usize) -> Self {
        Self {
            times: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Record a timestamp. Evicts the oldest entry if at capacity.
    fn push(&mut self, now: Instant) {
        if self.times.len() >= self.capacity {
            self.times.pop_front();
        }
        self.times.push_back(now);
    }

    /// Calculate the rolling announce frequency in Hz.
    ///
    /// Python formula (Interface.py lines 212-227):
    /// ```text
    /// delta_sum = sum of consecutive intervals + elapsed since last sample
    /// frequency = num_samples / delta_sum
    /// ```
    /// Returns 0.0 if fewer than 2 samples exist.
    fn frequency(&self) -> f64 {
        if self.times.len() <= 1 {
            return 0.0;
        }
        let dq_len = self.times.len();
        let mut delta_sum = Duration::ZERO;

        // Sum intervals between consecutive samples
        for i in 1..dq_len {
            delta_sum += self.times[i].duration_since(self.times[i - 1]);
        }

        // Add time elapsed since last recorded sample
        delta_sum += self.times[dq_len - 1].elapsed();

        let delta_secs = delta_sum.as_secs_f64();
        if delta_secs == 0.0 {
            0.0
        } else {
            dq_len as f64 / delta_secs
        }
    }
}

/// A held announce entry — the packet plus the interface it arrived on.
pub struct HeldAnnounce {
    pub packet: Packet,
    pub receiving_interface: AddressHash,
}

/// Per-interface ingress control state for announce burst detection and held announces.
///
/// Tracks announce frequencies and manages burst detection per Python's
/// `Interface.py` lines 94-200. Protected by a `std::sync::Mutex` inside
/// `InterfaceMetadata` — callers use accessor methods and never touch the lock.
struct IngressControl {
    /// Whether ingress control is enabled for this interface.
    enabled: bool,
    /// Incoming announce frequency tracker.
    ia_freq: FreqDeque,
    /// Outgoing announce frequency tracker.
    oa_freq: FreqDeque,
    /// Whether burst mode is currently active.
    burst_active: bool,
    /// When burst mode was activated.
    burst_activated: Instant,
    /// Earliest time at which a held announce may be released.
    held_release: Instant,
    /// Map from destination hash to held announce (latest wins per destination).
    held_announces: HashMap<AddressHash, HeldAnnounce>,
}

impl IngressControl {
    /// Create new ingress control state.
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ia_freq: FreqDeque::new(IA_FREQ_SAMPLES),
            oa_freq: FreqDeque::new(OA_FREQ_SAMPLES),
            burst_active: false,
            burst_activated: Instant::now(),
            // Allow immediate release (now is already passed)
            held_release: Instant::now(),
            held_announces: HashMap::new(),
        }
    }

    /// Record an incoming announce timestamp.
    fn record_incoming(&mut self) {
        self.ia_freq.push(Instant::now());
    }

    /// Record an outgoing announce timestamp.
    fn record_outgoing(&mut self) {
        self.oa_freq.push(Instant::now());
    }

    /// Get current incoming announce frequency in Hz.
    fn incoming_announce_frequency(&self) -> f64 {
        self.ia_freq.frequency()
    }

    /// Get current outgoing announce frequency in Hz.
    fn outgoing_announce_frequency(&self) -> f64 {
        self.oa_freq.frequency()
    }

    /// Check whether this interface should ingress-limit announces.
    ///
    /// Implements the Python `should_ingress_limit()` state machine (Interface.py lines 117-138):
    /// - If burst is active: check if frequency dropped AND hold time elapsed → deactivate
    /// - If not in burst: check if frequency exceeds threshold → activate burst
    fn should_ingress_limit(&mut self, interface_age: Duration) -> bool {
        if !self.enabled {
            return false;
        }

        let freq_threshold = if interface_age < IC_NEW_TIME {
            IC_BURST_FREQ_NEW
        } else {
            IC_BURST_FREQ
        };
        let ia_freq = self.ia_freq.frequency();

        if self.burst_active {
            // In burst mode: check deactivation conditions
            if ia_freq < freq_threshold
                && self.burst_activated.elapsed() >= IC_BURST_HOLD
            {
                self.burst_active = false;
                // Apply penalty before releasing held announces
                self.held_release = Instant::now() + IC_BURST_PENALTY;
            }
            true // Always limit while burst was/is active this check
        } else {
            // Not in burst: check activation threshold
            if ia_freq > freq_threshold {
                self.burst_active = true;
                self.burst_activated = Instant::now();
                true
            } else {
                false
            }
        }
    }

    /// Hold an announce packet for later release.
    ///
    /// If an announce for the same destination is already held, it is replaced
    /// (latest wins). New announces are only added if under the capacity limit.
    fn hold_announce(&mut self, dest_hash: AddressHash, packet: Packet, receiving_interface: AddressHash) {
        if self.held_announces.contains_key(&dest_hash) {
            // Replace existing announce for this destination
            self.held_announces.insert(dest_hash, HeldAnnounce { packet, receiving_interface });
        } else if self.held_announces.len() < MAX_HELD_ANNOUNCES {
            self.held_announces.insert(dest_hash, HeldAnnounce { packet, receiving_interface });
        }
        // Drop silently if at capacity and not a replacement
    }

    /// Try to release one held announce for reprocessing.
    ///
    /// Selects the announce with the minimum hop count (highest priority),
    /// respecting the release interval. Returns None if conditions aren't met.
    fn take_releasable_announce(&mut self) -> Option<(AddressHash, HeldAnnounce)> {
        if self.held_announces.is_empty() {
            return None;
        }

        // Check release interval
        if Instant::now() < self.held_release {
            return None;
        }

        // Find announce with minimum hops
        let best_dest = self
            .held_announces
            .iter()
            .min_by_key(|(_, held)| held.packet.header.hops)
            .map(|(dest, _)| *dest);

        if let Some(dest) = best_dest {
            // Update release timer
            self.held_release = Instant::now() + IC_HELD_RELEASE_INTERVAL;
            let held = self.held_announces.remove(&dest).unwrap();
            Some((dest, held))
        } else {
            None
        }
    }

    /// Get count of currently held announces.
    fn held_count(&self) -> usize {
        self.held_announces.len()
    }
}

/// Interface mode constants matching Python implementation.
///
/// These define how an interface operates within the network:
/// - Full: Standard interface with full routing capabilities
/// - AccessPoint: Acts as an access point for other nodes
/// - PointToPoint: Direct connection between two nodes
/// - Roaming: Mobile interface that may change connections
/// - Boundary: Interface at network boundary
/// - Gateway: Gateway interface for inter-network routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum InterfaceMode {
    #[default]
    Full = 0x01,
    PointToPoint = 0x02,
    AccessPoint = 0x03,
    Roaming = 0x04,
    Boundary = 0x05,
    Gateway = 0x06,
}

impl From<u8> for InterfaceMode {
    fn from(value: u8) -> Self {
        match value {
            0x01 => InterfaceMode::Full,
            0x02 => InterfaceMode::PointToPoint,
            0x03 => InterfaceMode::AccessPoint,
            0x04 => InterfaceMode::Roaming,
            0x05 => InterfaceMode::Boundary,
            0x06 => InterfaceMode::Gateway,
            _ => InterfaceMode::Full,
        }
    }
}

impl InterfaceMode {
    /// Interface modes that warrant active path discovery in Transport Node mode.
    /// Python: `DISCOVER_PATHS_FOR = [MODE_ACCESS_POINT, MODE_GATEWAY, MODE_ROAMING]`
    pub const DISCOVER_PATHS_FOR: &[InterfaceMode] = &[
        InterfaceMode::AccessPoint,
        InterfaceMode::Gateway,
        InterfaceMode::Roaming,
    ];

    /// Get a human-readable string representation of the mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            InterfaceMode::Full => "full",
            InterfaceMode::AccessPoint => "accesspoint",
            InterfaceMode::PointToPoint => "pointtopoint",
            InterfaceMode::Roaming => "roaming",
            InterfaceMode::Boundary => "boundary",
            InterfaceMode::Gateway => "gateway",
        }
    }

}

impl FromStr for InterfaceMode {
    type Err = ();

    /// Parse interface mode from string configuration value.
    /// Supports multiple aliases for backwards compatibility with Python implementation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_lower = s.to_lowercase();
        match s_lower.as_str() {
            "full" => Ok(InterfaceMode::Full),
            "access_point" | "accesspoint" | "ap" => Ok(InterfaceMode::AccessPoint),
            "pointtopoint" | "ptp" | "point_to_point" => Ok(InterfaceMode::PointToPoint),
            "roaming" => Ok(InterfaceMode::Roaming),
            "boundary" => Ok(InterfaceMode::Boundary),
            "gateway" | "gw" => Ok(InterfaceMode::Gateway),
            _ => Err(()),
        }
    }
}

/// Thread-safe interface metadata and statistics.
///
/// Uses atomic operations for stats that are frequently updated from async tasks,
/// allowing lock-free updates without requiring mutex locks on every packet.
pub struct InterfaceMetadata {
    /// Full interface name (e.g., "TCPInterface[hostname:port]")
    pub name: String,
    /// Short interface name for display
    pub short_name: String,
    /// Interface type name (e.g., "TCPClientInterface")
    pub interface_type: String,
    /// Interface mode
    pub mode: InterfaceMode,
    /// Whether interface is online/connected
    online: AtomicBool,
    /// Bytes received (atomic for thread-safe updates)
    rx_bytes: AtomicU64,
    /// Bytes transmitted (atomic for thread-safe updates)
    tx_bytes: AtomicU64,
    /// Interface bitrate in bits/sec (if known)
    pub bitrate: Option<u64>,
    /// When the interface was created
    pub created: Instant,
    /// Optional parent interface hash (for spawned TCP server clients)
    pub parent_interface_hash: Option<AddressHash>,
    /// Network endpoint address (for display, e.g., "127.0.0.1:4242")
    pub endpoint_address: String,
    /// Whether interface has been detached from transport
    pub detached: bool,
    /// Whether interface supports peer discovery
    pub supports_discovery: bool,
    /// Whether interface can be discovered by others
    pub discoverable: bool,
    /// Timestamp of last discovery announce sent (seconds since epoch, 0 = never)
    pub last_discovery_announce: f64,
    /// Whether interface is only used for bootstrapping
    pub bootstrap_only: bool,
    /// Child interface hashes (parent-to-children tracking)
    pub spawned_interfaces: Vec<AddressHash>,
    /// Tunnel ID for tunneled interfaces
    pub tunnel_id: Option<AddressHash>,
    /// Whether interface can receive packets (Python: Interface.IN)
    pub dir_in: bool,
    /// Whether interface can transmit packets (Python: Interface.OUT)
    pub dir_out: bool,
    /// Whether interface can forward packets (Python: Interface.FWD)
    pub fwd: bool,
    /// Whether interface can repeat packets (Python: Interface.RPT)
    pub rpt: bool,
    /// Per-interface announce rate target in seconds (None = no rate limit).
    /// Python: `interface.announce_rate_target`
    pub announce_rate_target: Option<u64>,
    /// Per-interface announce rate grace violations before blocking.
    /// Python: `interface.announce_rate_grace`
    pub announce_rate_grace: Option<u32>,
    /// Per-interface announce rate penalty in seconds.
    /// Python: `interface.announce_rate_penalty`
    pub announce_rate_penalty: Option<u64>,
    /// Hardware MTU in bytes. None means use default.
    /// Python: self.HW_MTU
    pub hw_mtu: Option<usize>,
    /// Whether this interface auto-configures MTU based on bitrate.
    /// Python: AUTOCONFIGURE_MTU (class-level, subclasses opt in)
    pub autoconfigure_mtu: bool,
    /// Whether this interface has a user-fixed MTU from configuration.
    /// Python: FIXED_MTU
    pub fixed_mtu: bool,
    /// Ingress control state (frequency tracking, burst detection, held announces).
    /// Protected by std::sync::Mutex — callers use accessor methods only.
    ingress_control: std::sync::Mutex<IngressControl>,
}

impl InterfaceMetadata {
    /// Create new interface metadata.
    ///
    /// # Arguments
    /// * `name` - Full interface name
    /// * `short_name` - Short name for display
    /// * `interface_type` - Type of interface (e.g., "TCPClientInterface")
    /// * `endpoint_address` - Network endpoint address string
    pub fn new(
        name: impl Into<String>,
        short_name: impl Into<String>,
        interface_type: impl Into<String>,
        endpoint_address: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            short_name: short_name.into(),
            interface_type: interface_type.into(),
            mode: InterfaceMode::Full,
            online: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            bitrate: None,
            created: Instant::now(),
            parent_interface_hash: None,
            endpoint_address: endpoint_address.into(),
            detached: false,
            supports_discovery: false,
            discoverable: false,
            last_discovery_announce: 0.0,
            bootstrap_only: false,
            spawned_interfaces: Vec::new(),
            tunnel_id: None,
            dir_in: true,
            dir_out: true,
            fwd: false,
            rpt: false,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
            hw_mtu: None,
            autoconfigure_mtu: false,
            fixed_mtu: false,
            ingress_control: std::sync::Mutex::new(IngressControl::new(true)),
        }
    }

    /// Set the interface mode.
    pub fn with_mode(mut self, mode: InterfaceMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the interface bitrate.
    pub fn with_bitrate(mut self, bitrate: u64) -> Self {
        self.bitrate = Some(bitrate);
        self
    }

    /// Set the parent interface hash.
    pub fn with_parent(mut self, parent_hash: AddressHash) -> Self {
        self.parent_interface_hash = Some(parent_hash);
        self
    }

    /// Set the hardware MTU.
    pub fn with_hw_mtu(mut self, mtu: usize) -> Self {
        self.hw_mtu = Some(mtu);
        self
    }

    /// Enable MTU auto-configuration based on bitrate.
    pub fn with_autoconfigure_mtu(mut self) -> Self {
        self.autoconfigure_mtu = true;
        self
    }

    /// Set a fixed (user-configured) MTU and disable auto-configuration.
    pub fn with_fixed_mtu(mut self, mtu: usize) -> Self {
        self.hw_mtu = Some(mtu);
        self.fixed_mtu = true;
        self.autoconfigure_mtu = false;
        self
    }

    /// Set the direction flags (IN and OUT).
    pub fn with_direction(mut self, dir_in: bool, dir_out: bool) -> Self {
        self.dir_in = dir_in;
        self.dir_out = dir_out;
        self
    }

    /// Disable ingress control for this interface.
    ///
    /// Used for interface types like SerialInterface and KISSInterface that
    /// override `should_ingress_limit()` to return `False` in Python.
    pub fn with_ingress_control_disabled(self) -> Self {
        self.ingress_control.lock().unwrap().enabled = false;
        self
    }

    /// Set per-interface announce rate limiting parameters.
    pub fn with_announce_rate(mut self, target: u64, grace: u32, penalty: u64) -> Self {
        self.announce_rate_target = Some(target);
        self.announce_rate_grace = Some(grace);
        self.announce_rate_penalty = Some(penalty);
        self
    }

    /// Auto-configure HW_MTU based on interface bitrate.
    ///
    /// Matches Python's `Interface.optimise_mtu()` (Interface.py lines 140-165).
    /// Must be called before wrapping in Arc since it takes `&mut self`.
    pub fn optimise_mtu(&mut self) {
        if self.fixed_mtu || !self.autoconfigure_mtu {
            return;
        }
        if let Some(bitrate) = self.bitrate {
            self.hw_mtu = if bitrate >= 1_000_000_000 {
                Some(524288)
            } else if bitrate > 750_000_000 {
                Some(262144)
            } else if bitrate > 400_000_000 {
                Some(131072)
            } else if bitrate > 200_000_000 {
                Some(65536)
            } else if bitrate > 100_000_000 {
                Some(32768)
            } else if bitrate > 10_000_000 {
                Some(16384)
            } else if bitrate > 5_000_000 {
                Some(8192)
            } else if bitrate > 2_000_000 {
                Some(4096)
            } else if bitrate > 1_000_000 {
                Some(2048)
            } else if bitrate > 62_500 {
                Some(1024)
            } else {
                None
            };
        }
    }

    /// Increment received bytes counter.
    #[inline]
    pub fn add_rx_bytes(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment transmitted bytes counter.
    #[inline]
    pub fn add_tx_bytes(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Set online status.
    #[inline]
    pub fn set_online(&self, online: bool) {
        self.online.store(online, Ordering::Release);
    }

    /// Get current rx bytes.
    #[inline]
    pub fn get_rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    /// Get current tx bytes.
    #[inline]
    pub fn get_tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    /// Check if online.
    #[inline]
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    /// Returns elapsed time since interface creation.
    /// Python equivalent: `time.time() - self.created`
    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }

    /// Record an incoming announce timestamp for frequency tracking.
    /// Python: `Interface.received_announce()`
    pub fn record_incoming_announce(&self) {
        self.ingress_control.lock().unwrap().record_incoming();
    }

    /// Record an outgoing announce timestamp for frequency tracking.
    /// Python: `Interface.sent_announce()`
    pub fn record_outgoing_announce(&self) {
        self.ingress_control.lock().unwrap().record_outgoing();
    }

    /// Check ingress limit and hold the announce if limiting.
    ///
    /// Returns `true` if the announce was held (caller should stop processing).
    /// Acquires the lock once for both the limit check and the hold operation,
    /// avoiding TOCTOU gaps.
    pub fn check_ingress_and_hold(
        &self,
        dest_hash: AddressHash,
        packet: Packet,
        receiving_interface: AddressHash,
    ) -> bool {
        let mut ic = self.ingress_control.lock().unwrap();
        if ic.should_ingress_limit(self.age()) {
            ic.hold_announce(dest_hash, packet, receiving_interface);
            true
        } else {
            false
        }
    }

    /// Try to release one held announce if conditions permit.
    ///
    /// Returns `None` if the interface is still ingress-limiting, the release
    /// interval hasn't elapsed, or there are no held announces.
    pub fn try_release_held_announce(&self) -> Option<(AddressHash, HeldAnnounce)> {
        let mut ic = self.ingress_control.lock().unwrap();
        // Don't release while burst is active
        if ic.should_ingress_limit(self.age()) {
            return None;
        }
        ic.take_releasable_announce()
    }

    /// Get current incoming announce frequency in Hz.
    pub fn incoming_announce_frequency(&self) -> f64 {
        self.ingress_control.lock().unwrap().incoming_announce_frequency()
    }

    /// Get current outgoing announce frequency in Hz.
    pub fn outgoing_announce_frequency(&self) -> f64 {
        self.ingress_control.lock().unwrap().outgoing_announce_frequency()
    }

    /// Get count of currently held announces.
    pub fn held_announce_count(&self) -> usize {
        self.ingress_control.lock().unwrap().held_count()
    }
}

impl std::fmt::Debug for InterfaceMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceMetadata")
            .field("name", &self.name)
            .field("interface_type", &self.interface_type)
            .field("mode", &self.mode)
            .field("online", &self.is_online())
            .field("rx_bytes", &self.get_rx_bytes())
            .field("tx_bytes", &self.get_tx_bytes())
            .field("endpoint_address", &self.endpoint_address)
            .field("dir_in", &self.dir_in)
            .field("dir_out", &self.dir_out)
            .field("fwd", &self.fwd)
            .field("rpt", &self.rpt)
            .field("announce_rate_target", &self.announce_rate_target)
            .field("announce_rate_grace", &self.announce_rate_grace)
            .field("announce_rate_penalty", &self.announce_rate_penalty)
            .field("held_announces", &self.held_announce_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_metadata_new() {
        let meta = InterfaceMetadata::new(
            "TCPInterface[127.0.0.1:4242]",
            "TCPClient",
            "TCPClientInterface",
            "127.0.0.1:4242",
        );

        assert_eq!(meta.name, "TCPInterface[127.0.0.1:4242]");
        assert_eq!(meta.short_name, "TCPClient");
        assert_eq!(meta.interface_type, "TCPClientInterface");
        assert_eq!(meta.endpoint_address, "127.0.0.1:4242");
        assert!(!meta.is_online());
        assert_eq!(meta.get_rx_bytes(), 0);
        assert_eq!(meta.get_tx_bytes(), 0);
    }

    #[test]
    fn test_atomic_operations() {
        let meta = InterfaceMetadata::new("test", "test", "test", "");

        // Test online status
        assert!(!meta.is_online());
        meta.set_online(true);
        assert!(meta.is_online());
        meta.set_online(false);
        assert!(!meta.is_online());

        // Test byte counters
        meta.add_rx_bytes(100);
        assert_eq!(meta.get_rx_bytes(), 100);
        meta.add_rx_bytes(50);
        assert_eq!(meta.get_rx_bytes(), 150);

        meta.add_tx_bytes(200);
        assert_eq!(meta.get_tx_bytes(), 200);
        meta.add_tx_bytes(100);
        assert_eq!(meta.get_tx_bytes(), 300);
    }

    #[test]
    fn test_builder_methods() {
        let parent_hash = AddressHash::new_from_slice(&[1u8; 32]);
        let meta = InterfaceMetadata::new("test", "test", "test", "")
            .with_mode(InterfaceMode::AccessPoint)
            .with_bitrate(115200)
            .with_parent(parent_hash);

        assert_eq!(meta.mode, InterfaceMode::AccessPoint);
        assert_eq!(meta.bitrate, Some(115200));
        assert_eq!(meta.parent_interface_hash, Some(parent_hash));
    }

    #[test]
    fn test_interface_mode_as_str() {
        assert_eq!(InterfaceMode::Full.as_str(), "full");
        assert_eq!(InterfaceMode::AccessPoint.as_str(), "accesspoint");
        assert_eq!(InterfaceMode::PointToPoint.as_str(), "pointtopoint");
        assert_eq!(InterfaceMode::Roaming.as_str(), "roaming");
        assert_eq!(InterfaceMode::Boundary.as_str(), "boundary");
        assert_eq!(InterfaceMode::Gateway.as_str(), "gateway");
    }

    #[test]
    fn test_interface_mode_from_str() {
        // Test canonical names
        assert_eq!(InterfaceMode::from_str("full"), Ok(InterfaceMode::Full));
        assert_eq!(InterfaceMode::from_str("accesspoint"), Ok(InterfaceMode::AccessPoint));
        assert_eq!(InterfaceMode::from_str("pointtopoint"), Ok(InterfaceMode::PointToPoint));
        assert_eq!(InterfaceMode::from_str("roaming"), Ok(InterfaceMode::Roaming));
        assert_eq!(InterfaceMode::from_str("boundary"), Ok(InterfaceMode::Boundary));
        assert_eq!(InterfaceMode::from_str("gateway"), Ok(InterfaceMode::Gateway));

        // Test aliases for backwards compatibility
        assert_eq!(InterfaceMode::from_str("access_point"), Ok(InterfaceMode::AccessPoint));
        assert_eq!(InterfaceMode::from_str("ap"), Ok(InterfaceMode::AccessPoint));
        assert_eq!(InterfaceMode::from_str("point_to_point"), Ok(InterfaceMode::PointToPoint));
        assert_eq!(InterfaceMode::from_str("ptp"), Ok(InterfaceMode::PointToPoint));
        assert_eq!(InterfaceMode::from_str("gw"), Ok(InterfaceMode::Gateway));

        // Test case insensitivity
        assert_eq!(InterfaceMode::from_str("FULL"), Ok(InterfaceMode::Full));
        assert_eq!(InterfaceMode::from_str("Gateway"), Ok(InterfaceMode::Gateway));
        assert_eq!(InterfaceMode::from_str("AP"), Ok(InterfaceMode::AccessPoint));

        // Test invalid values
        assert!(InterfaceMode::from_str("invalid").is_err());
        assert!(InterfaceMode::from_str("").is_err());
    }

    #[test]
    fn test_interface_mode_values_match_python() {
        // Python: MODE_FULL = 0x01, MODE_POINT_TO_POINT = 0x02,
        // MODE_ACCESS_POINT = 0x03, MODE_ROAMING = 0x04,
        // MODE_BOUNDARY = 0x05, MODE_GATEWAY = 0x06
        assert_eq!(InterfaceMode::Full as u8, 0x01);
        assert_eq!(InterfaceMode::PointToPoint as u8, 0x02);
        assert_eq!(InterfaceMode::AccessPoint as u8, 0x03);
        assert_eq!(InterfaceMode::Roaming as u8, 0x04);
        assert_eq!(InterfaceMode::Boundary as u8, 0x05);
        assert_eq!(InterfaceMode::Gateway as u8, 0x06);
    }

    #[test]
    fn test_interface_mode_from_u8() {
        assert_eq!(InterfaceMode::from(0x01), InterfaceMode::Full);
        assert_eq!(InterfaceMode::from(0x02), InterfaceMode::PointToPoint);
        assert_eq!(InterfaceMode::from(0x03), InterfaceMode::AccessPoint);
        assert_eq!(InterfaceMode::from(0x04), InterfaceMode::Roaming);
        assert_eq!(InterfaceMode::from(0x05), InterfaceMode::Boundary);
        assert_eq!(InterfaceMode::from(0x06), InterfaceMode::Gateway);
    }

    #[test]
    fn test_interface_mode_invalid_defaults_to_full() {
        assert_eq!(InterfaceMode::from(0x00), InterfaceMode::Full);
        assert_eq!(InterfaceMode::from(0x07), InterfaceMode::Full);
        assert_eq!(InterfaceMode::from(0xFF), InterfaceMode::Full);
    }

    #[test]
    fn test_direction_flag_defaults() {
        let meta = InterfaceMetadata::new("test", "test", "test", "");
        // Python: IN=True, OUT=True by default; FWD=False, RPT=False
        assert!(meta.dir_in);
        assert!(meta.dir_out);
        assert!(!meta.fwd);
        assert!(!meta.rpt);
    }

    #[test]
    fn test_direction_builder() {
        let meta = InterfaceMetadata::new("test", "test", "test", "")
            .with_direction(false, true);
        assert!(!meta.dir_in);
        assert!(meta.dir_out);
    }

    #[test]
    fn test_announce_rate_defaults() {
        let meta = InterfaceMetadata::new("test", "test", "test", "");
        assert!(meta.announce_rate_target.is_none());
        assert!(meta.announce_rate_grace.is_none());
        assert!(meta.announce_rate_penalty.is_none());
    }

    #[test]
    fn test_announce_rate_builder() {
        let meta = InterfaceMetadata::new("test", "test", "test", "")
            .with_announce_rate(3600, 10, 7200);
        assert_eq!(meta.announce_rate_target, Some(3600));
        assert_eq!(meta.announce_rate_grace, Some(10));
        assert_eq!(meta.announce_rate_penalty, Some(7200));
    }

    #[test]
    fn test_lifecycle_field_defaults() {
        let meta = InterfaceMetadata::new("test", "test", "test", "");
        assert!(!meta.detached);
        assert!(!meta.supports_discovery);
        assert!(!meta.discoverable);
        assert_eq!(meta.last_discovery_announce, 0.0);
        assert!(!meta.bootstrap_only);
        assert!(meta.spawned_interfaces.is_empty());
        assert!(meta.tunnel_id.is_none());
        assert!(meta.hw_mtu.is_none());
        assert!(!meta.autoconfigure_mtu);
        assert!(!meta.fixed_mtu);
    }

    #[test]
    fn test_optimise_mtu_bitrate_thresholds() {
        // Python: Interface.optimise_mtu() bitrate-to-MTU table
        let cases: Vec<(u64, Option<usize>)> = vec![
            (1_000_000_000, Some(524288)),  // >= 1 Gbps
            (2_000_000_000, Some(524288)),   // > 1 Gbps
            (750_000_001, Some(262144)),     // > 750 Mbps
            (400_000_001, Some(131072)),     // > 400 Mbps
            (200_000_001, Some(65536)),      // > 200 Mbps
            (100_000_001, Some(32768)),      // > 100 Mbps
            (10_000_001, Some(16384)),       // > 10 Mbps
            (10_000_000, Some(8192)),        // = 10 Mbps (not > 10M, but > 5M)
            (5_000_001, Some(8192)),         // > 5 Mbps
            (2_000_001, Some(4096)),         // > 2 Mbps
            (1_000_001, Some(2048)),         // > 1 Mbps
            (62_501, Some(1024)),            // > 62.5 Kbps
            (62_500, None),                  // = 62.5 Kbps (not >)
            (1_000, None),                   // Very low bitrate
        ];

        for (bitrate, expected_mtu) in cases {
            let mut meta = InterfaceMetadata::new("test", "test", "test", "")
                .with_bitrate(bitrate)
                .with_autoconfigure_mtu();
            meta.optimise_mtu();
            assert_eq!(
                meta.hw_mtu, expected_mtu,
                "bitrate={} expected hw_mtu={:?}, got {:?}",
                bitrate, expected_mtu, meta.hw_mtu
            );
        }
    }

    #[test]
    fn test_optimise_mtu_skipped_when_fixed() {
        let mut meta = InterfaceMetadata::new("test", "test", "test", "")
            .with_bitrate(1_000_000_000)
            .with_fixed_mtu(4096);
        meta.optimise_mtu();
        // Fixed MTU should not be overridden by optimise_mtu
        assert_eq!(meta.hw_mtu, Some(4096));
    }

    #[test]
    fn test_optimise_mtu_skipped_when_not_enabled() {
        let mut meta = InterfaceMetadata::new("test", "test", "test", "")
            .with_bitrate(1_000_000_000);
        // autoconfigure_mtu is false by default
        meta.optimise_mtu();
        assert!(meta.hw_mtu.is_none());
    }

    #[test]
    fn test_age_returns_elapsed() {
        let meta = InterfaceMetadata::new("test", "test", "test", "");
        // age() should return a non-zero duration (at least some nanoseconds have passed)
        let age = meta.age();
        assert!(age.as_nanos() > 0);
    }

    #[test]
    fn test_discover_paths_for() {
        assert_eq!(InterfaceMode::DISCOVER_PATHS_FOR.len(), 3);
        assert!(InterfaceMode::DISCOVER_PATHS_FOR.contains(&InterfaceMode::AccessPoint));
        assert!(InterfaceMode::DISCOVER_PATHS_FOR.contains(&InterfaceMode::Gateway));
        assert!(InterfaceMode::DISCOVER_PATHS_FOR.contains(&InterfaceMode::Roaming));
    }

    #[test]
    fn test_ic_new_time() {
        assert_eq!(IC_NEW_TIME.as_secs(), 7200);
    }

    #[test]
    fn test_ic_constants() {
        assert_eq!(IA_FREQ_SAMPLES, 6);
        assert_eq!(OA_FREQ_SAMPLES, 6);
        assert_eq!(MAX_HELD_ANNOUNCES, 256);
        assert_eq!(IC_BURST_FREQ_NEW, 3.5);
        assert_eq!(IC_BURST_FREQ, 12.0);
        assert_eq!(IC_BURST_HOLD.as_secs(), 60);
        assert_eq!(IC_BURST_PENALTY.as_secs(), 300);
        assert_eq!(IC_HELD_RELEASE_INTERVAL.as_secs(), 30);
    }

    #[test]
    fn test_freq_deque_empty_returns_zero() {
        let dq = FreqDeque::new(6);
        assert_eq!(dq.frequency(), 0.0);
    }

    #[test]
    fn test_freq_deque_single_sample_returns_zero() {
        let mut dq = FreqDeque::new(6);
        dq.push(Instant::now());
        assert_eq!(dq.frequency(), 0.0);
    }

    #[test]
    fn test_freq_deque_two_samples() {
        let mut dq = FreqDeque::new(6);
        let now = Instant::now();
        dq.times.push_back(now - Duration::from_secs(1));
        dq.times.push_back(now);
        // 2 samples with ~1 second spread + ~0 elapsed => freq ~= 2/1 = 2 Hz
        let freq = dq.frequency();
        assert!(freq > 1.5 && freq < 2.5, "freq was {}", freq);
    }

    #[test]
    fn test_freq_deque_capacity_bounded() {
        let mut dq = FreqDeque::new(3);
        for _ in 0..5 {
            dq.push(Instant::now());
        }
        assert_eq!(dq.times.len(), 3);
    }

    #[test]
    fn test_freq_deque_evicts_oldest() {
        let mut dq = FreqDeque::new(3);
        let t1 = Instant::now();
        let t2 = t1 + Duration::from_millis(100);
        let t3 = t2 + Duration::from_millis(100);
        let t4 = t3 + Duration::from_millis(100);

        dq.times.push_back(t1);
        dq.times.push_back(t2);
        dq.times.push_back(t3);
        assert_eq!(dq.times.len(), 3);

        dq.push(t4);
        assert_eq!(dq.times.len(), 3);
        // t1 should have been evicted
        assert_eq!(dq.times[0], t2);
    }

    #[test]
    fn test_ingress_control_disabled() {
        let mut ic = IngressControl::new(false);
        // Should never limit when disabled
        assert!(!ic.should_ingress_limit(Duration::from_secs(0)));
        assert!(!ic.should_ingress_limit(IC_NEW_TIME + Duration::from_secs(1)));
    }

    #[test]
    fn test_ingress_control_no_burst_below_threshold() {
        let mut ic = IngressControl::new(true);
        // No samples -> frequency is 0 -> no burst
        assert!(!ic.should_ingress_limit(IC_NEW_TIME + Duration::from_secs(1)));
    }

    #[test]
    fn test_ingress_control_burst_activation() {
        let mut ic = IngressControl::new(true);
        // Simulate high-frequency announces by pushing timestamps very close together
        let now = Instant::now();
        for i in 0..6 {
            ic.ia_freq.times.push_back(now - Duration::from_millis(50 * (5 - i)));
        }
        // 6 samples over ~250ms => freq ~= 6/0.25 = 24 Hz, well above IC_BURST_FREQ (12)
        let age = IC_NEW_TIME + Duration::from_secs(1); // Established interface
        assert!(ic.should_ingress_limit(age));
        assert!(ic.burst_active);
    }

    #[test]
    fn test_ingress_control_burst_new_interface_lower_threshold() {
        let mut ic = IngressControl::new(true);
        // Frequency that's above IC_BURST_FREQ_NEW (3.5) but below IC_BURST_FREQ (12)
        let now = Instant::now();
        for i in 0..6 {
            // 6 samples over ~1 second => freq ~= 6 Hz
            ic.ia_freq.times.push_back(now - Duration::from_millis(200 * (5 - i)));
        }
        // New interface should trigger burst at 3.5 Hz
        assert!(ic.should_ingress_limit(Duration::from_secs(60)));
        // Established interface should not trigger burst at 6 Hz (threshold is 12)
        let mut ic2 = IngressControl::new(true);
        for i in 0..6 {
            ic2.ia_freq.times.push_back(now - Duration::from_millis(200 * (5 - i)));
        }
        assert!(!ic2.should_ingress_limit(IC_NEW_TIME + Duration::from_secs(1)));
    }

    #[test]
    fn test_ingress_control_hold_announce() {
        let mut ic = IngressControl::new(true);
        let dest = AddressHash::new_from_slice(&[1u8; 32]);
        let iface = AddressHash::new_from_slice(&[2u8; 32]);
        let packet = Packet::default();

        ic.hold_announce(dest, packet, iface);
        assert_eq!(ic.held_count(), 1);

        // Replace for same destination
        ic.hold_announce(dest, packet, iface);
        assert_eq!(ic.held_count(), 1);

        // Different destination
        let dest2 = AddressHash::new_from_slice(&[3u8; 32]);
        ic.hold_announce(dest2, packet, iface);
        assert_eq!(ic.held_count(), 2);
    }

    #[test]
    fn test_ingress_control_hold_capacity_limit() {
        let mut ic = IngressControl::new(true);
        let iface = AddressHash::new_from_slice(&[0u8; 32]);
        let packet = Packet::default();

        // Fill to capacity
        for i in 0..MAX_HELD_ANNOUNCES {
            let mut dest_bytes = [0u8; 32];
            dest_bytes[0] = (i & 0xFF) as u8;
            dest_bytes[1] = ((i >> 8) & 0xFF) as u8;
            let dest = AddressHash::new_from_slice(&dest_bytes);
            ic.hold_announce(dest, packet, iface);
        }
        assert_eq!(ic.held_count(), MAX_HELD_ANNOUNCES);

        // One more should be silently dropped
        let extra = AddressHash::new_from_slice(&[0xFF; 32]);
        ic.hold_announce(extra, packet, iface);
        assert_eq!(ic.held_count(), MAX_HELD_ANNOUNCES);
    }

    #[test]
    fn test_ingress_control_release_selects_min_hops() {
        use crate::packet::Header;

        let mut ic = IngressControl::new(true);
        let iface = AddressHash::new_from_slice(&[0u8; 32]);
        // held_release is initialized to Instant::now(), so it should be immediately passable

        let dest1 = AddressHash::new_from_slice(&[1u8; 32]);
        let dest2 = AddressHash::new_from_slice(&[2u8; 32]);

        let mut pkt_high_hops = Packet::default();
        pkt_high_hops.header.hops = 5;
        let mut pkt_low_hops = Packet::default();
        pkt_low_hops.header.hops = 1;

        ic.hold_announce(dest1, pkt_high_hops, iface);
        ic.hold_announce(dest2, pkt_low_hops, iface);

        // Should release the one with fewer hops
        let released = ic.take_releasable_announce();
        assert!(released.is_some());
        let (dest, held) = released.unwrap();
        assert_eq!(dest, dest2);
        assert_eq!(held.packet.header.hops, 1);
        assert_eq!(ic.held_count(), 1);
    }

    #[test]
    fn test_metadata_ingress_accessors() {
        let meta = InterfaceMetadata::new("test", "test", "test", "");
        assert_eq!(meta.incoming_announce_frequency(), 0.0);
        assert_eq!(meta.outgoing_announce_frequency(), 0.0);
        assert_eq!(meta.held_announce_count(), 0);

        // Record some announces
        meta.record_incoming_announce();
        meta.record_outgoing_announce();
        // After one sample, frequency is still 0 (need >=2)
        assert_eq!(meta.incoming_announce_frequency(), 0.0);
        assert_eq!(meta.outgoing_announce_frequency(), 0.0);
    }

    #[test]
    fn test_metadata_ingress_control_disabled() {
        let meta = InterfaceMetadata::new("test", "test", "test", "")
            .with_ingress_control_disabled();
        let dest = AddressHash::new_from_slice(&[1u8; 32]);
        let iface = AddressHash::new_from_slice(&[2u8; 32]);
        let packet = Packet::default();

        // Should never hold when disabled
        assert!(!meta.check_ingress_and_hold(dest, packet, iface));
    }
}
