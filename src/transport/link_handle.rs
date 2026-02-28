//! A cloneable, cacheable facade over a `Link` for higher-layer protocols.
//!
//! `LinkHandle` snapshots immutable link fields (id, destination, initiator) at
//! construction time so consumers can read them without acquiring any lock.
//! Mutable state reads (status, rtt, …) acquire only the inner `Link` mutex.
//! Send operations acquire the `Link` mutex to build the packet, then the
//! `TransportHandler` mutex to transmit it, keeping the locking dance internal.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::destination::link::{Link, LinkId, LinkStatus};
use crate::destination::DestinationDesc;
use crate::error::RnsError;
use crate::identity::{Identity, PrivateIdentity};

use super::TransportHandler;

/// A cloneable handle to a link that caches immutable fields for lock-free reads
/// and internalises the lock-then-send dance for mutable operations.
///
/// Higher-layer protocols (LXMF, rncp, etc.) should cache this handle instead of
/// holding `Arc<Mutex<Link>>` directly.
#[derive(Clone)]
pub struct LinkHandle {
    // Immutable after handshake — lock-free reads
    id: LinkId,
    destination: DestinationDesc,
    initiator: bool,

    // Interior mutable state — locked only when needed
    inner: Arc<Mutex<Link>>,

    // Transport send capability — locked to send packets
    handler: Arc<Mutex<TransportHandler>>,
}

impl LinkHandle {
    /// Create a new `LinkHandle` by snapshotting the link's immutable fields.
    ///
    /// This is crate-private; callers obtain handles from `Transport::link()`,
    /// `Transport::find_out_link()`, or `Transport::find_in_link()`.
    #[allow(private_interfaces)]
    pub(crate) fn new(
        inner: Arc<Mutex<Link>>,
        handler: Arc<Mutex<super::TransportHandler>>,
        id: LinkId,
        destination: DestinationDesc,
        initiator: bool,
    ) -> Self {
        Self {
            id,
            destination,
            initiator,
            inner,
            handler,
        }
    }

    // ========================================================================
    // Lock-free accessors (immutable after construction)
    // ========================================================================

    /// Link identifier (truncated hash). Lock-free.
    pub fn id(&self) -> &LinkId {
        &self.id
    }

    /// Destination this link connects to. Lock-free.
    pub fn destination(&self) -> &DestinationDesc {
        &self.destination
    }

    /// Whether we initiated this link (client side). Lock-free.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    // ========================================================================
    // Single-lock reads (lock inner Link only)
    // ========================================================================

    /// Current link status.
    pub async fn status(&self) -> LinkStatus {
        self.inner.lock().await.status()
    }

    /// Round-trip time measurement.
    pub async fn rtt(&self) -> Duration {
        self.inner.lock().await.rtt()
    }

    /// Remote peer's identity, if they have identified themselves.
    pub async fn remote_identity(&self) -> Option<Identity> {
        self.inner.lock().await.remote_identity().cloned()
    }

    /// Truncated hash of the remote identity (16 bytes), if identified.
    pub async fn remote_identity_hash(&self) -> Option<[u8; 16]> {
        self.inner.lock().await.remote_identity_hash()
    }

    /// Maximum data unit size for this link (max plaintext per packet).
    pub async fn mdu(&self) -> usize {
        self.inner.lock().await.mdu()
    }

    // ========================================================================
    // Lock + send methods (lock inner, build packet, lock handler, send)
    // ========================================================================

    /// Send a data packet (context NONE) over the link.
    pub async fn send_data(&self, payload: &[u8]) -> Result<(), RnsError> {
        let packet = self.inner.lock().await.data_packet(payload)?;
        self.handler.lock().await.send_packet(packet).await;
        Ok(())
    }

    /// Send a channel message over the link.
    pub async fn send_channel(&self, payload: &[u8]) -> Result<(), RnsError> {
        let packet = self.inner.lock().await.channel_packet(payload)?;
        self.handler.lock().await.send_packet(packet).await;
        Ok(())
    }

    /// Send a request packet over the link.
    pub async fn send_request(&self, payload: &[u8]) -> Result<(), RnsError> {
        let packet = self.inner.lock().await.request_packet(payload)?;
        self.handler.lock().await.send_packet(packet).await;
        Ok(())
    }

    /// Send a response packet over the link.
    pub async fn send_response(&self, payload: &[u8]) -> Result<(), RnsError> {
        let packet = self.inner.lock().await.response_packet(payload)?;
        self.handler.lock().await.send_packet(packet).await;
        Ok(())
    }

    /// Identify ourselves to the remote destination.
    pub async fn identify(&self, identity: &PrivateIdentity) -> Result<(), RnsError> {
        let packet = self.inner.lock().await.identify(identity)?;
        self.handler.lock().await.send_packet(packet).await;
        Ok(())
    }

    /// Close the link, sending a LINKCLOSE packet if the link is active.
    pub async fn close(&self) {
        let packet = self.inner.lock().await.close();
        if let Some(packet) = packet {
            self.handler.lock().await.send_packet(packet).await;
        }
    }

    // ========================================================================
    // Escape hatch for advanced callers
    // ========================================================================

    /// Raw access to the inner `Link` mutex.
    ///
    /// Use this for resource operations, physical layer stats, or other methods
    /// not exposed on `LinkHandle`.
    pub fn inner(&self) -> &Arc<Mutex<Link>> {
        &self.inner
    }
}

impl std::fmt::Debug for LinkHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkHandle")
            .field("id", &self.id)
            .field("destination", &self.destination.address_hash)
            .field("initiator", &self.initiator)
            .finish()
    }
}
