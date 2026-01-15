//! Interface statistics tracking.
//!
//! This module provides thread-safe structures for tracking interface metadata
//! and traffic statistics (rx/tx bytes, online status, etc.).

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use crate::hash::AddressHash;

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
    Full = 0x00,
    AccessPoint = 0x01,
    PointToPoint = 0x02,
    Roaming = 0x03,
    Boundary = 0x04,
    Gateway = 0x05,
}

impl InterfaceMode {
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
}
