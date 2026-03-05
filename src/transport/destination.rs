//! A cloneable facade over a registered `SingleInputDestination`.
//!
//! `RegisteredDestination` caches immutable destination fields (desc,
//! address_hash) at construction time so consumers can read them without
//! acquiring any lock.  This mirrors the `Link` / `LinkInner` and
//! `PacketReceipt` / `PacketReceiptInner` patterns.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;

use rand_core::OsRng;

use crate::destination::proof::ProofStrategy;
use crate::destination::{
    DecryptResult, DefaultAppDataCallback, DestinationDesc, DestinationName,
    SingleInputDestination,
};
use crate::error::RnsError;
use crate::hash::AddressHash;
use crate::identity::Identity;
use crate::packet::Packet;

/// A cloneable facade over a registered `SingleInputDestination`.
///
/// Caches immutable destination fields (desc, address_hash) at construction
/// time so consumers can read them without acquiring any lock.
#[derive(Clone)]
pub struct RegisteredDestination {
    // Immutable after creation — lock-free reads
    desc: DestinationDesc,

    // Interior mutable state
    inner: Arc<Mutex<SingleInputDestination>>,
}

impl RegisteredDestination {
    /// Wrap an existing `SingleInputDestination` in a facade.
    pub(crate) fn new(inner: Arc<Mutex<SingleInputDestination>>, desc: DestinationDesc) -> Self {
        Self { desc, inner }
    }

    // ========================================================================
    // Lock-free accessors (immutable after construction)
    // ========================================================================

    /// Full destination descriptor. Lock-free.
    pub fn desc(&self) -> &DestinationDesc {
        &self.desc
    }

    /// Destination address hash. Lock-free.
    pub fn address_hash(&self) -> &AddressHash {
        &self.desc.address_hash
    }

    /// Destination name. Lock-free.
    pub fn name(&self) -> &DestinationName {
        &self.desc.name
    }

    /// The identity associated with this destination. Lock-free.
    pub fn identity(&self) -> &Identity {
        &self.desc.identity
    }

    // ========================================================================
    // Locked operations
    // ========================================================================

    /// Create an announce packet for this destination.
    ///
    /// Acquires the inner lock to generate the announce. Prefer
    /// `Transport::send_announce()` when you just want to broadcast;
    /// use this only when you need to modify the packet before sending.
    pub async fn announce(&self, app_data: Option<&[u8]>) -> Result<Packet, RnsError> {
        self.inner.lock().await.announce(OsRng, app_data)
    }

    // ========================================================================
    // Configuration methods (locked, typically called once at setup)
    // ========================================================================

    /// Enable ratchets with persistence at the given path.
    ///
    /// Mirrors Python's `Destination.enable_ratchets(path)`.
    pub async fn enable_ratchets(&self, path: PathBuf) -> Result<(), RnsError> {
        self.inner.lock().await.enable_ratchets(path)
    }

    /// Enforce ratchet usage for decryption (reject non-ratchet packets).
    ///
    /// Mirrors Python's `Destination.enforce_ratchets = True`.
    pub async fn set_enforce_ratchets(&self, enforce: bool) {
        self.inner.lock().await.set_enforce_ratchets(enforce);
    }

    /// Set the proof strategy for this destination.
    ///
    /// Mirrors Python's `Destination.set_proof_strategy()`.
    pub async fn set_proof_strategy(&self, strategy: ProofStrategy) {
        self.inner.lock().await.set_proof_strategy(strategy);
    }

    /// Set the callback for packet reception events.
    ///
    /// Mirrors Python's `Destination.set_packet_callback()`.
    pub async fn set_packet_callback<F>(&self, callback: F)
    where
        F: Fn(&[u8], &Packet) + Send + Sync + 'static,
    {
        self.inner.lock().await.set_packet_callback(callback);
    }

    /// Set default app_data callback for path responses and announces.
    ///
    /// Mirrors Python's `Destination.set_default_app_data(callable)`.
    pub async fn set_default_app_data(&self, callback: DefaultAppDataCallback) {
        self.inner.lock().await.set_default_app_data(callback);
    }

    // ========================================================================
    // Cryptographic methods (locked, per-message)
    // ========================================================================

    /// Decrypt a ciphertext using this destination's identity and ratchet state.
    ///
    /// Uses `OsRng` internally, matching how `announce()` hides the RNG parameter.
    pub async fn decrypt(
        &self,
        ciphertext: &[u8],
        ratchet_keys: Option<&[Vec<u8>]>,
        enforce_ratchets: bool,
    ) -> Result<DecryptResult, RnsError> {
        self.inner
            .lock()
            .await
            .decrypt(OsRng, ciphertext, ratchet_keys, enforce_ratchets)
    }

    /// Get a snapshot of the current ratchet private keys.
    ///
    /// Returns owned copies since we cannot return borrows through the lock guard.
    pub async fn ratchet_keys(&self) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .await
            .ratchet_state
            .ratchet_keys()
            .map(|k| k.to_vec())
            .collect()
    }

    /// Check whether ratchet usage is enforced for decryption.
    pub async fn is_ratchets_enforced(&self) -> bool {
        self.inner.lock().await.ratchet_state.enforce()
    }

    // ========================================================================
    // Escape hatch for operations not yet on the facade
    // ========================================================================

    /// Access the raw inner Arc for operations not yet exposed on the facade.
    ///
    /// **Transitional API**: prefer calling facade methods above. This will
    /// revert to `pub(crate)` once all `SingleInputDestination` operations
    /// are available through `RegisteredDestination`.
    pub fn inner_arc(&self) -> &Arc<Mutex<SingleInputDestination>> {
        &self.inner
    }
}
