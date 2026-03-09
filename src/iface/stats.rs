//! Interface statistics tracking.
//!
//! This module provides thread-safe structures for tracking interface metadata
//! and traffic statistics (rx/tx bytes, online status, etc.).

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::hash::AddressHash;

/// How long an interface is considered "new" (2 hours).
/// Python: `IC_NEW_TIME = 2*60*60`
pub const IC_NEW_TIME: Duration = Duration::from_secs(2 * 60 * 60);

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
}
