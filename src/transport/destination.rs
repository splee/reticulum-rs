//! A cloneable facade over a registered `SingleInputDestination`.
//!
//! `RegisteredDestination` caches immutable destination fields (desc,
//! address_hash) at construction time so consumers can read them without
//! acquiring any lock.  This mirrors the `Link` / `LinkInner` and
//! `PacketReceipt` / `PacketReceiptInner` patterns.

use std::sync::Arc;

use tokio::sync::Mutex;

use rand_core::OsRng;

use crate::destination::{DestinationDesc, DestinationName, SingleInputDestination};
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
    // Crate-internal access for transport operations
    // ========================================================================

    /// Access the raw inner Arc for transport operations that need the lock.
    pub(crate) fn inner_arc(&self) -> &Arc<Mutex<SingleInputDestination>> {
        &self.inner
    }
}
