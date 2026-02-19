//! Packet Receipt implementation for delivery tracking
//!
//! This module provides PacketReceipt functionality for tracking packet delivery
//! and validating proofs, matching the Python implementation.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

use crate::identity::{Identity, PrivateIdentity};

/// Length of full hash in bytes (256 bits / 8)
pub const HASH_LENGTH: usize = 32;

/// Length of signature in bytes (512 bits / 8)
pub const SIGNATURE_LENGTH: usize = 64;

/// Explicit proof length: hash + signature
pub const EXPLICIT_PROOF_LENGTH: usize = HASH_LENGTH + SIGNATURE_LENGTH;

/// Implicit proof length: signature only
pub const IMPLICIT_PROOF_LENGTH: usize = SIGNATURE_LENGTH;

/// Default timeout per hop in seconds
pub const TIMEOUT_PER_HOP: f64 = 6.0;

/// Receipt status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum ReceiptStatus {
    /// Packet delivery failed
    Failed = 0x00,
    /// Packet was sent but not yet confirmed
    #[default]
    Sent = 0x01,
    /// Packet delivery was confirmed via proof
    Delivered = 0x02,
    /// Receipt was culled (removed due to timeout or cleanup)
    Culled = 0xFF,
}


/// Callbacks for packet receipt events
#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct ReceiptCallbacks {
    /// Called when delivery is confirmed
    pub delivery: Option<Arc<dyn Fn(&PacketReceipt) + Send + Sync>>,
    /// Called when the receipt times out
    pub timeout: Option<Arc<dyn Fn(&PacketReceipt) + Send + Sync>>,
}


impl std::fmt::Debug for ReceiptCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptCallbacks")
            .field("delivery", &self.delivery.is_some())
            .field("timeout", &self.timeout.is_some())
            .finish()
    }
}

/// Physical layer metrics for a received packet
#[derive(Debug, Clone, Default)]
pub struct PhysicalMetrics {
    /// Received Signal Strength Indicator (dBm)
    pub rssi: Option<i16>,
    /// Signal-to-Noise Ratio (dB)
    pub snr: Option<f32>,
    /// Link quality indicator (0.0 - 1.0)
    pub q: Option<f32>,
}

impl PhysicalMetrics {
    /// Create new metrics
    pub fn new(rssi: Option<i16>, snr: Option<f32>, q: Option<f32>) -> Self {
        Self { rssi, snr, q }
    }

    /// Check if any metrics are available
    pub fn has_metrics(&self) -> bool {
        self.rssi.is_some() || self.snr.is_some() || self.q.is_some()
    }
}

/// A receipt for a sent packet, used to track delivery
#[derive(Debug)]
pub struct PacketReceipt {
    /// Full SHA-256 hash of the packet
    hash: [u8; HASH_LENGTH],
    /// Truncated hash for addressing
    truncated_hash: [u8; 16],
    /// Destination hash (for identity lookup during proof validation)
    destination_hash: Option<[u8; 16]>,
    /// When the packet was sent
    sent_at: Instant,
    /// Unix timestamp when sent
    #[allow(dead_code)]
    sent_timestamp: f64,
    /// Whether delivery has been proved
    proved: bool,
    /// Current status
    status: ReceiptStatus,
    /// Timeout duration
    timeout: Duration,
    /// When the receipt was concluded (delivered or failed)
    concluded_at: Option<Instant>,
    /// Callbacks for receipt events
    callbacks: ReceiptCallbacks,
    /// Physical layer metrics from proof packet
    metrics: Option<PhysicalMetrics>,
    /// Proof packet data (if received)
    proof_data: Option<Vec<u8>>,
}

impl PacketReceipt {
    /// Create a new packet receipt
    pub fn new(packet_hash: [u8; HASH_LENGTH], hops: u8, is_link: bool, rtt: Option<f64>) -> Self {
        let truncated_hash = {
            let mut truncated = [0u8; 16];
            truncated.copy_from_slice(&packet_hash[..16]);
            truncated
        };

        // Calculate timeout based on hops and link status
        let timeout = if is_link {
            // For links, use RTT-based timeout
            let base_timeout = rtt.unwrap_or(TIMEOUT_PER_HOP);
            Duration::from_secs_f64(base_timeout * 4.0) // traffic_timeout_factor
        } else {
            // For regular packets, use hop-based timeout
            let base = TIMEOUT_PER_HOP;
            let hop_timeout = TIMEOUT_PER_HOP * hops as f64;
            Duration::from_secs_f64(base + hop_timeout)
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        Self {
            hash: packet_hash,
            truncated_hash,
            destination_hash: None,
            sent_at: Instant::now(),
            sent_timestamp: now,
            proved: false,
            status: ReceiptStatus::Sent,
            timeout,
            concluded_at: None,
            callbacks: ReceiptCallbacks::default(),
            metrics: None,
            proof_data: None,
        }
    }

    /// Create a new packet receipt with destination hash for proof validation
    pub fn new_with_destination(
        packet_hash: [u8; HASH_LENGTH],
        destination_hash: [u8; 16],
        hops: u8,
        rtt: Option<f64>,
    ) -> Self {
        let mut receipt = Self::new(packet_hash, hops, false, rtt);
        receipt.destination_hash = Some(destination_hash);
        receipt
    }

    /// Get the destination hash (if set)
    pub fn destination_hash(&self) -> Option<&[u8; 16]> {
        self.destination_hash.as_ref()
    }

    /// Get the packet hash
    pub fn hash(&self) -> &[u8; HASH_LENGTH] {
        &self.hash
    }

    /// Get the truncated hash
    pub fn truncated_hash(&self) -> &[u8; 16] {
        &self.truncated_hash
    }

    /// Get the current status
    pub fn status(&self) -> ReceiptStatus {
        self.status
    }

    /// Check if the packet was delivered
    pub fn is_delivered(&self) -> bool {
        self.status == ReceiptStatus::Delivered
    }

    /// Check if the receipt has concluded (either delivered or failed)
    pub fn is_concluded(&self) -> bool {
        self.status != ReceiptStatus::Sent
    }

    /// Get the round-trip time if the packet was delivered
    pub fn rtt(&self) -> Option<Duration> {
        self.concluded_at.map(|concluded| concluded - self.sent_at)
    }

    /// Get physical layer metrics
    pub fn metrics(&self) -> Option<&PhysicalMetrics> {
        self.metrics.as_ref()
    }

    /// Set the delivery callback
    pub fn set_delivery_callback<F>(&mut self, callback: F)
    where
        F: Fn(&PacketReceipt) + Send + Sync + 'static,
    {
        self.callbacks.delivery = Some(Arc::new(callback));
    }

    /// Set the timeout callback
    pub fn set_timeout_callback<F>(&mut self, callback: F)
    where
        F: Fn(&PacketReceipt) + Send + Sync + 'static,
    {
        self.callbacks.timeout = Some(Arc::new(callback));
    }

    /// Check if the receipt has timed out
    pub fn check_timeout(&mut self) -> bool {
        if self.status == ReceiptStatus::Sent && self.sent_at.elapsed() > self.timeout {
            self.status = ReceiptStatus::Failed;
            self.concluded_at = Some(Instant::now());

            if let Some(ref callback) = self.callbacks.timeout {
                callback(self);
            }

            true
        } else {
            false
        }
    }

    /// Validate a proof for this receipt
    ///
    /// Returns true if the proof is valid and the packet is now marked as delivered.
    pub fn validate_proof(&mut self, proof: &[u8], identity: &Identity) -> bool {
        if self.status != ReceiptStatus::Sent {
            return false;
        }

        let valid = if proof.len() == EXPLICIT_PROOF_LENGTH {
            // Explicit proof: hash + signature
            self.validate_explicit_proof(proof, identity)
        } else if proof.len() == IMPLICIT_PROOF_LENGTH {
            // Implicit proof: signature only
            self.validate_implicit_proof(proof, identity)
        } else {
            false
        };

        if valid {
            self.status = ReceiptStatus::Delivered;
            self.proved = true;
            self.concluded_at = Some(Instant::now());
            self.proof_data = Some(proof.to_vec());

            if let Some(ref callback) = self.callbacks.delivery {
                callback(self);
            }
        }

        valid
    }

    /// Validate an explicit proof (hash + signature)
    fn validate_explicit_proof(&self, proof: &[u8], identity: &Identity) -> bool {
        if proof.len() < HASH_LENGTH + SIGNATURE_LENGTH {
            return false;
        }

        let proof_hash = &proof[..HASH_LENGTH];
        let signature_bytes = &proof[HASH_LENGTH..HASH_LENGTH + SIGNATURE_LENGTH];

        // Check that the proof hash matches our packet hash
        if proof_hash != self.hash.as_slice() {
            return false;
        }

        // Verify the signature
        if let Ok(signature) = ed25519_dalek::Signature::from_slice(signature_bytes) {
            identity.verify(&self.hash, &signature).is_ok()
        } else {
            false
        }
    }

    /// Validate an implicit proof (signature only)
    fn validate_implicit_proof(&self, proof: &[u8], identity: &Identity) -> bool {
        if proof.len() < SIGNATURE_LENGTH {
            return false;
        }

        let signature_bytes = &proof[..SIGNATURE_LENGTH];

        if let Ok(signature) = ed25519_dalek::Signature::from_slice(signature_bytes) {
            identity.verify(&self.hash, &signature).is_ok()
        } else {
            false
        }
    }

    /// Validate a proof for a link packet
    pub fn validate_link_proof(
        &mut self,
        proof: &[u8],
        peer_identity: &Identity,
        metrics: Option<PhysicalMetrics>,
    ) -> bool {
        // Link proofs are explicit proofs: hash + signature (matches Python)
        if proof.len() < EXPLICIT_PROOF_LENGTH {
            return false;
        }

        let proof_hash = &proof[..HASH_LENGTH];
        let signature_bytes = &proof[HASH_LENGTH..HASH_LENGTH + SIGNATURE_LENGTH];

        // Verify proof hash matches our packet hash
        if proof_hash != self.hash.as_slice() {
            return false;
        }

        let signature = match ed25519_dalek::Signature::from_slice(signature_bytes) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        if peer_identity.verify(&self.hash, &signature).is_err() {
            return false;
        }

        self.status = ReceiptStatus::Delivered;
        self.proved = true;
        self.concluded_at = Some(Instant::now());
        self.proof_data = Some(proof.to_vec());
        self.metrics = metrics;

        if let Some(ref callback) = self.callbacks.delivery {
            callback(self);
        }

        true
    }

    /// Mark the receipt as failed
    pub fn fail(&mut self) {
        if self.status == ReceiptStatus::Sent {
            self.status = ReceiptStatus::Failed;
            self.concluded_at = Some(Instant::now());

            if let Some(ref callback) = self.callbacks.timeout {
                callback(self);
            }
        }
    }

    /// Mark the receipt as culled
    pub fn cull(&mut self) {
        self.status = ReceiptStatus::Culled;
        self.concluded_at = Some(Instant::now());
    }
}

/// Generate a proof for a packet
pub fn generate_proof(
    packet_hash: &[u8; HASH_LENGTH],
    identity: &PrivateIdentity,
    explicit: bool,
) -> Vec<u8> {
    let signature = identity.sign(packet_hash);
    let sig_bytes = signature.to_bytes();

    if explicit {
        // Explicit proof: hash + signature
        let mut proof = Vec::with_capacity(HASH_LENGTH + SIGNATURE_LENGTH);
        proof.extend_from_slice(packet_hash);
        proof.extend_from_slice(&sig_bytes);
        proof
    } else {
        // Implicit proof: signature only
        sig_bytes.to_vec()
    }
}

/// Manager for tracking multiple packet receipts
///
/// Uses tokio async primitives to avoid blocking the async runtime.
#[derive(Debug)]
pub struct ReceiptManager {
    /// Active receipts (truncated hash -> receipt)
    receipts: tokio::sync::RwLock<std::collections::HashMap<[u8; 16], Arc<Mutex<PacketReceipt>>>>,
    /// Maximum number of receipts to track
    max_receipts: usize,
}

impl Default for ReceiptManager {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl ReceiptManager {
    /// Create a new receipt manager
    pub fn new(max_receipts: usize) -> Self {
        Self {
            receipts: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            max_receipts,
        }
    }

    /// Add a receipt to the manager
    pub async fn add(&self, receipt: PacketReceipt) -> Arc<Mutex<PacketReceipt>> {
        let hash = *receipt.truncated_hash();
        let receipt = Arc::new(Mutex::new(receipt));

        let mut receipts = self.receipts.write().await;

        // Cull old receipts if at capacity
        if receipts.len() >= self.max_receipts {
            self.cull_oldest(&mut receipts).await;
        }

        receipts.insert(hash, receipt.clone());

        receipt
    }

    /// Get a receipt by its truncated hash
    pub async fn get(&self, truncated_hash: &[u8; 16]) -> Option<Arc<Mutex<PacketReceipt>>> {
        self.receipts.read().await.get(truncated_hash).cloned()
    }

    /// Remove a receipt by its truncated hash
    pub async fn remove(&self, truncated_hash: &[u8; 16]) -> Option<Arc<Mutex<PacketReceipt>>> {
        self.receipts.write().await.remove(truncated_hash)
    }

    /// Check all receipts for timeouts
    pub async fn check_timeouts(&self) {
        let receipts = self.receipts.read().await;
        for receipt in receipts.values() {
            let mut r = receipt.lock().await;
            r.check_timeout();
        }
    }

    /// Cull the oldest receipts to make room
    async fn cull_oldest(
        &self,
        receipts: &mut std::collections::HashMap<[u8; 16], Arc<Mutex<PacketReceipt>>>,
    ) {
        // Find concluded receipts to remove
        let mut to_remove = Vec::new();
        for (hash, receipt) in receipts.iter() {
            let r = receipt.lock().await;
            if r.is_concluded() {
                to_remove.push(*hash);
            }
        }

        for hash in to_remove.iter().take(self.max_receipts / 4) {
            if let Some(receipt) = receipts.remove(hash) {
                let mut r = receipt.lock().await;
                r.cull();
            }
        }
    }

    /// Get the number of active receipts
    pub async fn len(&self) -> usize {
        self.receipts.read().await.len()
    }

    /// Check if the manager is empty
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_receipt_creation() {
        let hash = [0u8; HASH_LENGTH];
        let receipt = PacketReceipt::new(hash, 3, false, None);

        assert_eq!(receipt.status(), ReceiptStatus::Sent);
        assert!(!receipt.is_delivered());
        assert!(!receipt.is_concluded());
    }

    #[test]
    fn test_receipt_timeout() {
        let hash = [0u8; HASH_LENGTH];
        let mut receipt = PacketReceipt::new(hash, 0, false, None);

        // Override timeout for testing
        receipt.timeout = Duration::from_millis(1);

        std::thread::sleep(Duration::from_millis(10));

        assert!(receipt.check_timeout());
        assert_eq!(receipt.status(), ReceiptStatus::Failed);
        assert!(receipt.is_concluded());
    }

    #[tokio::test]
    async fn test_receipt_manager() {
        let manager = ReceiptManager::new(100);

        let hash = [0u8; HASH_LENGTH];
        let receipt = PacketReceipt::new(hash, 0, false, None);
        let truncated = *receipt.truncated_hash();

        manager.add(receipt).await;

        assert_eq!(manager.len().await, 1);
        assert!(manager.get(&truncated).await.is_some());

        manager.remove(&truncated).await;
        assert!(manager.get(&truncated).await.is_none());
    }

    #[test]
    fn test_proof_generation() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let hash = [42u8; HASH_LENGTH];

        // Generate explicit proof
        let explicit_proof = generate_proof(&hash, &identity, true);
        assert_eq!(explicit_proof.len(), EXPLICIT_PROOF_LENGTH);

        // Generate implicit proof
        let implicit_proof = generate_proof(&hash, &identity, false);
        assert_eq!(implicit_proof.len(), IMPLICIT_PROOF_LENGTH);
    }

    #[test]
    fn test_proof_validation() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let hash = [42u8; HASH_LENGTH];

        // Create receipt and proof
        let mut receipt = PacketReceipt::new(hash, 0, false, None);
        let proof = generate_proof(&hash, &identity, true);

        // Validate proof
        assert!(receipt.validate_proof(&proof, identity.as_identity()));
        assert!(receipt.is_delivered());
    }

    #[test]
    fn test_physical_metrics() {
        let metrics = PhysicalMetrics::new(Some(-70), Some(12.5), Some(0.85));

        assert!(metrics.has_metrics());
        assert_eq!(metrics.rssi, Some(-70));
        assert_eq!(metrics.snr, Some(12.5));
        assert_eq!(metrics.q, Some(0.85));
    }
}
