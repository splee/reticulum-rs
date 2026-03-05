//! A cloneable facade over `PacketReceiptInner` for higher-layer protocols.
//!
//! `PacketReceipt` snapshots immutable receipt fields (hash, destination_hash)
//! at construction time so consumers can read them without acquiring any lock.
//! Mutable state reads (status, rtt, …) acquire only the inner `Mutex`.
//! This mirrors the `Link` / `LinkInner` pattern.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::receipt::{PacketReceiptInner, PhysicalMetrics, ReceiptStatus};

/// A cloneable handle to a packet receipt that caches immutable fields for
/// lock-free reads and internalises locking for mutable operations.
///
/// Higher-layer protocols (rnprobe, etc.) should use this type instead of
/// holding `Arc<Mutex<PacketReceiptInner>>` directly.
#[derive(Clone)]
pub struct PacketReceipt {
    // Immutable after creation — lock-free reads
    hash: [u8; 32],
    truncated_hash: [u8; 16],
    destination_hash: Option<[u8; 16]>,

    // Interior mutable state
    inner: Arc<Mutex<PacketReceiptInner>>,
}

impl PacketReceipt {
    /// Wrap an existing `PacketReceiptInner` in a facade.
    ///
    /// The caller provides the immutable fields directly to avoid needing
    /// to lock the inner mutex during construction.
    pub(crate) fn new(
        inner: Arc<Mutex<PacketReceiptInner>>,
        hash: [u8; 32],
        truncated_hash: [u8; 16],
        destination_hash: Option<[u8; 16]>,
    ) -> Self {
        Self {
            hash,
            truncated_hash,
            destination_hash,
            inner,
        }
    }

    /// Wrap an existing `PacketReceiptInner` in a facade, reading immutable
    /// fields by locking the inner mutex asynchronously.
    pub(crate) async fn from_inner(inner: Arc<Mutex<PacketReceiptInner>>) -> Self {
        let guard = inner.lock().await;
        let hash = *guard.hash();
        let truncated_hash = *guard.truncated_hash();
        let destination_hash = guard.destination_hash().copied();
        drop(guard);

        Self {
            hash,
            truncated_hash,
            destination_hash,
            inner,
        }
    }

    // ========================================================================
    // Lock-free accessors (immutable after construction)
    // ========================================================================

    /// Full SHA-256 hash of the packet. Lock-free.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Truncated hash for addressing (16 bytes). Lock-free.
    pub fn truncated_hash(&self) -> &[u8; 16] {
        &self.truncated_hash
    }

    /// Destination hash (for identity lookup during proof validation). Lock-free.
    pub fn destination_hash(&self) -> Option<&[u8; 16]> {
        self.destination_hash.as_ref()
    }

    // ========================================================================
    // Single-lock reads
    // ========================================================================

    /// Current receipt status.
    pub async fn status(&self) -> ReceiptStatus {
        self.inner.lock().await.status()
    }

    /// Check if the packet was delivered.
    pub async fn is_delivered(&self) -> bool {
        self.inner.lock().await.is_delivered()
    }

    /// Check if the receipt has concluded (either delivered or failed).
    pub async fn is_concluded(&self) -> bool {
        self.inner.lock().await.is_concluded()
    }

    /// Get the round-trip time if the packet was delivered.
    pub async fn rtt(&self) -> Option<Duration> {
        self.inner.lock().await.rtt()
    }

    /// Get physical layer metrics (owned copy).
    pub async fn metrics(&self) -> Option<PhysicalMetrics> {
        self.inner.lock().await.metrics().cloned()
    }

    // ========================================================================
    // Single-lock writes
    // ========================================================================

    /// Check if the receipt has timed out. Returns true if it just timed out.
    pub async fn check_timeout(&self) -> bool {
        self.inner.lock().await.check_timeout()
    }

    // ========================================================================
    // Convenience methods
    // ========================================================================

    /// Wait for the receipt to conclude (delivered or failed/timeout).
    ///
    /// Polls the inner state periodically until conclusion or the given timeout
    /// elapses. Returns the RTT if delivered, None otherwise.
    pub async fn wait_for_conclusion(&self, timeout: Duration) -> Option<Duration> {
        let start = tokio::time::Instant::now();

        while start.elapsed() < timeout {
            {
                let r = self.inner.lock().await;
                if r.is_delivered() {
                    return r.rtt();
                }
                if r.is_concluded() {
                    return None;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Mark as timed out
        self.inner.lock().await.check_timeout();
        None
    }
}

impl std::fmt::Debug for PacketReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketReceipt")
            .field("hash", &hex::encode(&self.hash[..8]))
            .field("destination_hash", &self.destination_hash.map(hex::encode))
            .finish()
    }
}
