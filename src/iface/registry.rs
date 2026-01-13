//! Interface registry for tracking all interfaces and their statistics.
//!
//! This module provides a centralized registry that tracks all network interfaces
//! and computes traffic speed statistics.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

use crate::hash::AddressHash;

use super::stats::{InterfaceMetadata, InterfaceMode};

/// Computed interface statistics snapshot.
///
/// This struct contains a point-in-time snapshot of interface statistics,
/// including computed speed values. Unlike `InterfaceMetadata` which uses
/// atomic counters, this struct contains plain values suitable for serialization
/// and transmission over RPC.
#[derive(Debug, Clone)]
pub struct InterfaceStatsSnapshot {
    /// Full interface name
    pub name: String,
    /// Short interface name
    pub short_name: String,
    /// Interface type name
    pub interface_type: String,
    /// Interface mode
    pub mode: InterfaceMode,
    /// Whether interface is online
    pub online: bool,
    /// Total bytes received
    pub rx_bytes: u64,
    /// Total bytes transmitted
    pub tx_bytes: u64,
    /// Current receive speed in bits/sec
    pub rx_speed: f64,
    /// Current transmit speed in bits/sec
    pub tx_speed: f64,
    /// Interface bitrate in bits/sec (if known)
    pub bitrate: Option<u64>,
    /// Network endpoint address
    pub endpoint_address: String,
    /// Parent interface hash (for spawned interfaces)
    pub parent_interface_hash: Option<AddressHash>,
    /// Interface address hash (unique identifier)
    pub interface_hash: AddressHash,
}

/// Per-interface speed calculation state.
struct SpeedTracker {
    last_rx_bytes: u64,
    last_tx_bytes: u64,
    last_timestamp: Instant,
    current_rx_speed: f64,
    current_tx_speed: f64,
}

/// Central registry for interface metadata and statistics.
///
/// This registry tracks all active interfaces and computes traffic speeds.
/// It is designed to be shared across async tasks using `Arc<InterfaceRegistry>`.
///
/// # Speed Calculation
///
/// The `update_speeds()` method should be called every 1 second (matching
/// Python's `count_traffic_loop`) to compute current rx/tx speeds for each
/// interface. Speed is calculated as bits per second:
/// `speed = (byte_diff * 8) / time_diff`
pub struct InterfaceRegistry {
    /// Map from interface address hash to metadata
    interfaces: RwLock<HashMap<AddressHash, Arc<InterfaceMetadata>>>,
    /// Speed tracking state per interface
    speed_trackers: RwLock<HashMap<AddressHash, SpeedTracker>>,
}

impl InterfaceRegistry {
    /// Create a new empty interface registry.
    pub fn new() -> Self {
        Self {
            interfaces: RwLock::new(HashMap::new()),
            speed_trackers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new interface.
    ///
    /// # Arguments
    /// * `address` - Unique address hash for the interface
    /// * `metadata` - Shared metadata for the interface
    pub async fn register(&self, address: AddressHash, metadata: Arc<InterfaceMetadata>) {
        log::debug!(
            "iface_registry: registering interface {} ({})",
            metadata.name,
            address
        );
        self.interfaces.write().await.insert(address, metadata);
    }

    /// Unregister an interface.
    ///
    /// This removes the interface from the registry and cleans up its speed tracker.
    pub async fn unregister(&self, address: &AddressHash) {
        if let Some(metadata) = self.interfaces.write().await.remove(address) {
            log::debug!(
                "iface_registry: unregistering interface {} ({})",
                metadata.name,
                address
            );
        }
        self.speed_trackers.write().await.remove(address);
    }

    /// Get metadata for an interface.
    pub async fn get(&self, address: &AddressHash) -> Option<Arc<InterfaceMetadata>> {
        self.interfaces.read().await.get(address).cloned()
    }

    /// Check if an interface is registered.
    pub async fn contains(&self, address: &AddressHash) -> bool {
        self.interfaces.read().await.contains_key(address)
    }

    /// Get the number of registered interfaces.
    pub async fn len(&self) -> usize {
        self.interfaces.read().await.len()
    }

    /// Check if registry is empty.
    pub async fn is_empty(&self) -> bool {
        self.interfaces.read().await.is_empty()
    }

    /// Update speed calculations for all interfaces.
    ///
    /// This should be called every 1 second to calculate current rx/tx speeds.
    /// Speed is reported in bits per second, matching Python's implementation.
    pub async fn update_speeds(&self) {
        let interfaces = self.interfaces.read().await;
        let mut trackers = self.speed_trackers.write().await;
        let now = Instant::now();

        for (address, metadata) in interfaces.iter() {
            let rx_bytes = metadata.get_rx_bytes();
            let tx_bytes = metadata.get_tx_bytes();

            let tracker = trackers.entry(*address).or_insert_with(|| SpeedTracker {
                last_rx_bytes: rx_bytes,
                last_tx_bytes: tx_bytes,
                last_timestamp: now,
                current_rx_speed: 0.0,
                current_tx_speed: 0.0,
            });

            let elapsed = now.duration_since(tracker.last_timestamp).as_secs_f64();
            if elapsed > 0.0 {
                let rx_diff = rx_bytes.saturating_sub(tracker.last_rx_bytes);
                let tx_diff = tx_bytes.saturating_sub(tracker.last_tx_bytes);

                // Calculate speed in bits/sec (matching Python: speed = (bytes * 8) / time)
                tracker.current_rx_speed = (rx_diff as f64 * 8.0) / elapsed;
                tracker.current_tx_speed = (tx_diff as f64 * 8.0) / elapsed;

                tracker.last_rx_bytes = rx_bytes;
                tracker.last_tx_bytes = tx_bytes;
                tracker.last_timestamp = now;
            }
        }
    }

    /// Get statistics snapshot for all interfaces.
    ///
    /// Returns a vector of `InterfaceStatsSnapshot` containing current
    /// statistics for all registered interfaces.
    pub async fn get_all_stats(&self) -> Vec<InterfaceStatsSnapshot> {
        let interfaces = self.interfaces.read().await;
        let trackers = self.speed_trackers.read().await;

        interfaces
            .iter()
            .map(|(address, metadata)| {
                let (rx_speed, tx_speed) = trackers
                    .get(address)
                    .map(|t| (t.current_rx_speed, t.current_tx_speed))
                    .unwrap_or((0.0, 0.0));

                InterfaceStatsSnapshot {
                    name: metadata.name.clone(),
                    short_name: metadata.short_name.clone(),
                    interface_type: metadata.interface_type.clone(),
                    mode: metadata.mode,
                    online: metadata.is_online(),
                    rx_bytes: metadata.get_rx_bytes(),
                    tx_bytes: metadata.get_tx_bytes(),
                    rx_speed,
                    tx_speed,
                    bitrate: metadata.bitrate,
                    endpoint_address: metadata.endpoint_address.clone(),
                    parent_interface_hash: metadata.parent_interface_hash,
                    interface_hash: *address,
                }
            })
            .collect()
    }

    /// Get aggregate traffic statistics across all interfaces.
    ///
    /// Returns (total_rx_bytes, total_tx_bytes, total_rx_speed, total_tx_speed).
    pub async fn get_aggregate_stats(&self) -> (u64, u64, f64, f64) {
        let interfaces = self.interfaces.read().await;
        let trackers = self.speed_trackers.read().await;

        let mut total_rx_bytes = 0u64;
        let mut total_tx_bytes = 0u64;
        let mut total_rx_speed = 0.0f64;
        let mut total_tx_speed = 0.0f64;

        for (address, metadata) in interfaces.iter() {
            total_rx_bytes += metadata.get_rx_bytes();
            total_tx_bytes += metadata.get_tx_bytes();

            if let Some(tracker) = trackers.get(address) {
                total_rx_speed += tracker.current_rx_speed;
                total_tx_speed += tracker.current_tx_speed;
            }
        }

        (total_rx_bytes, total_tx_bytes, total_rx_speed, total_tx_speed)
    }
}

impl Default for InterfaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_basic_operations() {
        let registry = InterfaceRegistry::new();
        let address = AddressHash::new_from_slice(&[1u8; 32]);
        let metadata = Arc::new(InterfaceMetadata::new(
            "TestInterface",
            "Test",
            "TestType",
            "127.0.0.1:1234",
        ));

        // Test empty registry
        assert!(registry.is_empty().await);
        assert_eq!(registry.len().await, 0);
        assert!(!registry.contains(&address).await);

        // Test registration
        registry.register(address, metadata.clone()).await;
        assert!(!registry.is_empty().await);
        assert_eq!(registry.len().await, 1);
        assert!(registry.contains(&address).await);

        // Test retrieval
        let retrieved = registry.get(&address).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "TestInterface");

        // Test unregistration
        registry.unregister(&address).await;
        assert!(registry.is_empty().await);
        assert!(!registry.contains(&address).await);
    }

    #[tokio::test]
    async fn test_stats_snapshot() {
        let registry = InterfaceRegistry::new();
        let address = AddressHash::new_from_slice(&[1u8; 32]);
        let metadata = Arc::new(InterfaceMetadata::new(
            "TestInterface",
            "Test",
            "TestType",
            "127.0.0.1:1234",
        ));

        // Add some traffic
        metadata.add_rx_bytes(1000);
        metadata.add_tx_bytes(500);
        metadata.set_online(true);

        registry.register(address, metadata).await;

        let stats = registry.get_all_stats().await;
        assert_eq!(stats.len(), 1);

        let stat = &stats[0];
        assert_eq!(stat.name, "TestInterface");
        assert_eq!(stat.rx_bytes, 1000);
        assert_eq!(stat.tx_bytes, 500);
        assert!(stat.online);
        assert_eq!(stat.interface_hash, address);
    }

    #[tokio::test]
    async fn test_speed_calculation() {
        let registry = InterfaceRegistry::new();
        let address = AddressHash::new_from_slice(&[1u8; 32]);
        let metadata = Arc::new(InterfaceMetadata::new(
            "TestInterface",
            "Test",
            "TestType",
            "127.0.0.1:1234",
        ));

        registry.register(address, metadata.clone()).await;

        // First update initializes trackers
        registry.update_speeds().await;

        // Simulate traffic
        metadata.add_rx_bytes(1000);
        metadata.add_tx_bytes(500);

        // Sleep briefly to get measurable time delta
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Update speeds again
        registry.update_speeds().await;

        let stats = registry.get_all_stats().await;
        assert_eq!(stats.len(), 1);

        // Speeds should be non-zero now
        let stat = &stats[0];
        assert!(stat.rx_speed > 0.0);
        assert!(stat.tx_speed > 0.0);
    }

    #[tokio::test]
    async fn test_aggregate_stats() {
        let registry = InterfaceRegistry::new();

        let addr1 = AddressHash::new_from_slice(&[1u8; 32]);
        let meta1 = Arc::new(InterfaceMetadata::new("IF1", "IF1", "Type", ""));
        meta1.add_rx_bytes(100);
        meta1.add_tx_bytes(50);

        let addr2 = AddressHash::new_from_slice(&[2u8; 32]);
        let meta2 = Arc::new(InterfaceMetadata::new("IF2", "IF2", "Type", ""));
        meta2.add_rx_bytes(200);
        meta2.add_tx_bytes(100);

        registry.register(addr1, meta1).await;
        registry.register(addr2, meta2).await;

        let (total_rx, total_tx, _, _) = registry.get_aggregate_stats().await;
        assert_eq!(total_rx, 300);
        assert_eq!(total_tx, 150);
    }
}
