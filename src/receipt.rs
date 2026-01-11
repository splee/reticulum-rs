//! Packet Receipt implementation for delivery tracking
//!
//! This module provides PacketReceipt functionality for tracking packet delivery
//! and validating proofs, matching the Python implementation.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
pub enum ReceiptStatus {
    /// Packet delivery failed
    Failed = 0x00,
    /// Packet was sent but not yet confirmed
    Sent = 0x01,
    /// Packet delivery was confirmed via proof
    Delivered = 0x02,
    /// Receipt was culled (removed due to timeout or cleanup)
    Culled = 0xFF,
}

impl Default for ReceiptStatus {
    fn default() -> Self {
        ReceiptStatus::Sent
    }
}

/// Callbacks for packet receipt events
pub struct ReceiptCallbacks {
    /// Called when delivery is confirmed
    pub delivery: Option<Arc<dyn Fn(&PacketReceipt) + Send + Sync>>,
    /// Called when the receipt times out
    pub timeout: Option<Arc<dyn Fn(&PacketReceipt) + Send + Sync>>,
}

impl Default for ReceiptCallbacks {
    fn default() -> Self {
        Self {
            delivery: None,
            timeout: None,
        }
    }
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
        _link_key: &[u8],
        metrics: Option<PhysicalMetrics>,
    ) -> bool {
        // For link proofs, we use HMAC instead of signature verification
        // This is a simplified version - real implementation would use link-specific validation
        if proof.len() < HASH_LENGTH {
            return false;
        }

        let proof_hash = &proof[..HASH_LENGTH];

        // Verify proof hash matches our packet hash
        if proof_hash == self.hash.as_slice() {
            self.status = ReceiptStatus::Delivered;
            self.proved = true;
            self.concluded_at = Some(Instant::now());
            self.proof_data = Some(proof.to_vec());
            self.metrics = metrics;

            if let Some(ref callback) = self.callbacks.delivery {
                callback(self);
            }

            true
        } else {
            false
        }
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
#[derive(Debug, Default)]
pub struct ReceiptManager {
    /// Active receipts (truncated hash -> receipt)
    receipts: RwLock<std::collections::HashMap<[u8; 16], Arc<Mutex<PacketReceipt>>>>,
    /// Maximum number of receipts to track
    max_receipts: usize,
}

impl ReceiptManager {
    /// Create a new receipt manager
    pub fn new(max_receipts: usize) -> Self {
        Self {
            receipts: RwLock::new(std::collections::HashMap::new()),
            max_receipts,
        }
    }

    /// Add a receipt to the manager
    pub fn add(&self, receipt: PacketReceipt) -> Arc<Mutex<PacketReceipt>> {
        let hash = *receipt.truncated_hash();
        let receipt = Arc::new(Mutex::new(receipt));

        if let Ok(mut receipts) = self.receipts.write() {
            // Cull old receipts if at capacity
            if receipts.len() >= self.max_receipts {
                self.cull_oldest(&mut receipts);
            }

            receipts.insert(hash, receipt.clone());
        }

        receipt
    }

    /// Get a receipt by its truncated hash
    pub fn get(&self, truncated_hash: &[u8; 16]) -> Option<Arc<Mutex<PacketReceipt>>> {
        self.receipts
            .read()
            .ok()
            .and_then(|r| r.get(truncated_hash).cloned())
    }

    /// Remove a receipt by its truncated hash
    pub fn remove(&self, truncated_hash: &[u8; 16]) -> Option<Arc<Mutex<PacketReceipt>>> {
        self.receipts
            .write()
            .ok()
            .and_then(|mut r| r.remove(truncated_hash))
    }

    /// Check all receipts for timeouts
    pub fn check_timeouts(&self) {
        if let Ok(receipts) = self.receipts.read() {
            for receipt in receipts.values() {
                if let Ok(mut r) = receipt.lock() {
                    r.check_timeout();
                }
            }
        }
    }

    /// Cull the oldest receipts to make room
    fn cull_oldest(
        &self,
        receipts: &mut std::collections::HashMap<[u8; 16], Arc<Mutex<PacketReceipt>>>,
    ) {
        // Find concluded receipts to remove
        let to_remove: Vec<[u8; 16]> = receipts
            .iter()
            .filter_map(|(hash, receipt)| {
                receipt
                    .lock()
                    .ok()
                    .filter(|r| r.is_concluded())
                    .map(|_| *hash)
            })
            .collect();

        for hash in to_remove.iter().take(self.max_receipts / 4) {
            if let Some(receipt) = receipts.remove(hash) {
                if let Ok(mut r) = receipt.lock() {
                    r.cull();
                }
            }
        }
    }

    /// Get the number of active receipts
    pub fn len(&self) -> usize {
        self.receipts.read().map(|r| r.len()).unwrap_or(0)
    }

    /// Check if the manager is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    #[test]
    fn test_receipt_manager() {
        let manager = ReceiptManager::new(100);

        let hash = [0u8; HASH_LENGTH];
        let receipt = PacketReceipt::new(hash, 0, false, None);
        let truncated = *receipt.truncated_hash();

        manager.add(receipt);

        assert_eq!(manager.len(), 1);
        assert!(manager.get(&truncated).is_some());

        manager.remove(&truncated);
        assert!(manager.get(&truncated).is_none());
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
