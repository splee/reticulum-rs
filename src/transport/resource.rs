//! A cloneable facade over `ResourceInner` for higher-layer protocols.
//!
//! `Resource` snapshots immutable resource fields (hash, size, flags) at
//! construction time so consumers can read them without acquiring any lock.
//! Mutable state reads (status, progress, …) acquire only the inner `RwLock`.
//! This mirrors the `Link` / `LinkInner` pattern.

use std::sync::{Arc, RwLock};

use rand_core::CryptoRngCore;

use crate::error::RnsError;
use crate::resource::{
    EncryptFn, HandleRequestResult, ResourceAdvertisement, ResourceConfig, ResourceFlags,
    ResourceInner, ResourceProgress, ResourceStatus,
};

/// A cloneable handle to a resource that caches immutable fields for lock-free
/// reads and internalises locking for mutable operations.
///
/// Higher-layer protocols (LXMF, rncp, etc.) should use this type instead of
/// holding `Arc<RwLock<ResourceInner>>` directly.
#[derive(Clone)]
pub struct Resource {
    // Immutable after creation — lock-free reads
    hash: [u8; 32],
    truncated_hash: [u8; 16],
    original_hash: [u8; 32],
    size: usize,
    total_size: usize,
    total_parts: usize,
    total_segments: usize,
    segment_index: usize,
    flags: ResourceFlags,
    is_initiator: bool,

    // Interior mutable state
    inner: Arc<RwLock<ResourceInner>>,
}

impl Resource {
    /// Wrap an existing `ResourceInner` in a facade, snapshotting its immutable fields.
    pub(crate) fn from_inner(inner: Arc<RwLock<ResourceInner>>) -> Self {
        let guard = inner.read().unwrap();
        Self {
            hash: *guard.hash(),
            truncated_hash: *guard.truncated_hash(),
            original_hash: *guard.original_hash(),
            size: guard.size(),
            total_size: guard.total_size(),
            total_parts: guard.total_parts(),
            total_segments: guard.total_segments(),
            segment_index: guard.segment_index(),
            flags: guard.flags,
            is_initiator: guard.is_initiator(),
            inner: Arc::clone(&inner),
        }
    }

    /// Create a new outgoing resource from data.
    ///
    /// The optional `encrypt_fn` encrypts the resource data stream before
    /// splitting it into parts. This is typically `link.encrypt()` wrapped in
    /// a closure.
    pub fn new<R: CryptoRngCore>(
        rng: &mut R,
        data: &[u8],
        config: ResourceConfig,
        metadata: Option<&[u8]>,
        encrypt_fn: Option<&EncryptFn>,
    ) -> Result<Self, RnsError> {
        let inner = ResourceInner::new(rng, data, config, metadata, encrypt_fn)?;
        let arc = Arc::new(RwLock::new(inner));
        Ok(Self::from_inner(arc))
    }

    /// Create an incoming resource from an advertisement.
    pub fn from_advertisement(adv: &ResourceAdvertisement, sdu: usize) -> Result<Self, RnsError> {
        let inner = ResourceInner::from_advertisement(adv, sdu)?;
        let arc = Arc::new(RwLock::new(inner));
        Ok(Self::from_inner(arc))
    }

    /// Get a reference to the underlying `Arc<RwLock<ResourceInner>>`.
    ///
    /// This is crate-private; used by the transport layer for internal operations
    /// like watchdog spawning and link tracking.
    pub(crate) fn inner_arc(&self) -> &Arc<RwLock<ResourceInner>> {
        &self.inner
    }

    // ========================================================================
    // Lock-free accessors (immutable after construction)
    // ========================================================================

    /// Resource hash (full 32 bytes). Lock-free.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Truncated hash for identification (16 bytes). Lock-free.
    pub fn truncated_hash(&self) -> &[u8; 16] {
        &self.truncated_hash
    }

    /// Original hash (for segmented resources). Lock-free.
    pub fn original_hash(&self) -> &[u8; 32] {
        &self.original_hash
    }

    /// Transfer size (compressed/encrypted). Lock-free.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Total data size (uncompressed). Lock-free.
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Total number of parts. Lock-free.
    pub fn total_parts(&self) -> usize {
        self.total_parts
    }

    /// Total number of segments. Lock-free.
    pub fn total_segments(&self) -> usize {
        self.total_segments
    }

    /// Current segment index. Lock-free.
    pub fn segment_index(&self) -> usize {
        self.segment_index
    }

    /// Whether the resource is compressed. Lock-free.
    pub fn is_compressed(&self) -> bool {
        self.flags.compressed
    }

    /// Whether the resource is encrypted. Lock-free.
    pub fn is_encrypted(&self) -> bool {
        self.flags.encrypted
    }

    /// Whether we initiated this resource transfer. Lock-free.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Resource flags. Lock-free.
    pub fn flags(&self) -> ResourceFlags {
        self.flags
    }

    // ========================================================================
    // Single-lock reads
    // ========================================================================

    /// Current resource status.
    pub fn status(&self) -> ResourceStatus {
        self.inner.read().unwrap().status()
    }

    /// Get progress information.
    pub fn progress(&self) -> ResourceProgress {
        self.inner.read().unwrap().progress()
    }

    /// Check if all parts have been received.
    pub fn is_complete(&self) -> bool {
        self.inner.read().unwrap().is_complete()
    }

    /// Create a resource advertisement.
    pub fn create_advertisement(&self) -> ResourceAdvertisement {
        self.inner.read().unwrap().create_advertisement()
    }

    /// Get part data by index (owned copy).
    pub fn get_part_data(&self, index: usize) -> Option<Vec<u8>> {
        self.inner
            .read()
            .unwrap()
            .get_part_data(index)
            .map(|s| s.to_vec())
    }

    /// Get the raw assembled data (encrypted) without decryption.
    /// Returns None if resource is not complete.
    pub fn get_raw_assembled_data(&self) -> Option<Vec<u8>> {
        self.inner.read().unwrap().get_raw_assembled_data()
    }

    /// Verify a proof from the receiver.
    pub fn verify_proof(&self, proof_data: &[u8]) -> bool {
        self.inner.read().unwrap().verify_proof(proof_data)
    }

    /// Generate a proof for an assembled resource.
    pub fn generate_proof(&self) -> Result<Vec<u8>, RnsError> {
        self.inner.read().unwrap().generate_proof()
    }

    /// Generate a proof from assembled data.
    pub fn generate_proof_with_data(&self, data: &[u8]) -> Vec<u8> {
        self.inner.read().unwrap().generate_proof_with_data(data)
    }

    // ========================================================================
    // Single-lock writes
    // ========================================================================

    /// Handle an incoming resource request (for outgoing resources).
    pub fn handle_request(&self, request_data: &[u8]) -> Result<HandleRequestResult, RnsError> {
        self.inner.write().unwrap().handle_request(request_data)
    }

    /// Receive a part by map hash. Returns true if the part was accepted.
    pub fn receive_part(&self, data: Vec<u8>) -> bool {
        self.inner.write().unwrap().receive_part(data)
    }

    /// Generate a request for the next batch of parts (for incoming resources).
    pub fn request_next(&self) -> Option<Vec<u8>> {
        self.inner.write().unwrap().request_next()
    }

    /// Update hashmap from a hashmap update packet.
    pub fn update_hashmap(&self, segment: usize, hashmap_data: &[u8]) {
        self.inner.write().unwrap().update_hashmap(segment, hashmap_data)
    }

    /// Finalize assembly with pre-decrypted data.
    pub fn finalize_assembly(&self, decrypted_data: Vec<u8>) -> Result<Vec<u8>, RnsError> {
        self.inner.write().unwrap().finalize_assembly(decrypted_data)
    }

    /// Cancel the resource transfer.
    pub fn cancel(&self) {
        self.inner.write().unwrap().cancel()
    }

    /// Mark part as sent.
    pub fn mark_part_sent(&self, index: usize) {
        self.inner.write().unwrap().mark_part_sent(index)
    }

    /// Set resource status.
    pub fn set_status(&self, status: ResourceStatus) {
        self.inner.write().unwrap().set_status(status)
    }

    /// Mark that the advertisement was sent.
    pub fn mark_adv_sent(&self) {
        self.inner.write().unwrap().mark_adv_sent()
    }

    /// Mark that a resource request was sent.
    pub fn mark_request_sent(&self, bytes: usize) {
        self.inner.write().unwrap().mark_request_sent(bytes)
    }

    /// Set the previous EIFR from the link's last resource transfer.
    pub fn set_previous_eifr(&self, eifr: Option<f64>) {
        self.inner.write().unwrap().set_previous_eifr(eifr)
    }

    /// Set the resource timeout.
    pub fn set_timeout(&self, timeout: std::time::Duration) {
        self.inner.write().unwrap().set_timeout(timeout)
    }

    // ========================================================================
    // Static methods (no lock needed)
    // ========================================================================

    /// Parse a raw HMU (Hashmap Update) packet payload.
    pub fn parse_hashmap_update(payload: &[u8]) -> Option<([u8; 16], usize, Vec<u8>)> {
        ResourceInner::parse_hashmap_update(payload)
    }

    /// Extract rejection data from an advertisement.
    pub fn rejection_data(adv: &ResourceAdvertisement) -> Vec<u8> {
        ResourceInner::rejection_data(adv)
    }
}

impl std::fmt::Debug for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resource")
            .field("hash", &hex::encode(&self.hash[..8]))
            .field("size", &self.size)
            .field("total_parts", &self.total_parts)
            .field("initiator", &self.is_initiator)
            .finish()
    }
}
