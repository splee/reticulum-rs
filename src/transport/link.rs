//! A cloneable, cacheable facade over a `LinkInner` for higher-layer protocols.
//!
//! `Link` snapshots immutable link fields (id, destination, initiator) at
//! construction time so consumers can read them without acquiring any lock.
//! Mutable state reads (status, rtt, …) acquire only the inner `LinkInner` mutex.
//! Send operations acquire the `LinkInner` mutex to build the packet, then the
//! `TransportHandler` mutex to transmit it, keeping the locking dance internal.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::destination::link::{LinkInner, LinkId, LinkStatus, ResourceId};
use crate::destination::request_receipt::SharedRequestReceipt;
use crate::destination::DestinationDesc;
use crate::error::RnsError;
use crate::identity::{Identity, PrivateIdentity};
use crate::resource::ResourceAdvertisement;

use super::{Resource, TransportHandler};

/// A cloneable handle to a link that caches immutable fields for lock-free reads
/// and internalises the lock-then-send dance for mutable operations.
///
/// Higher-layer protocols (LXMF, rncp, etc.) should cache this handle instead of
/// holding `Arc<Mutex<LinkInner>>` directly.
#[derive(Clone)]
pub struct Link {
    // Immutable after handshake — lock-free reads
    id: LinkId,
    destination: DestinationDesc,
    initiator: bool,

    // Interior mutable state — locked only when needed
    inner: Arc<Mutex<LinkInner>>,

    // Transport send capability — locked to send packets
    handler: Arc<Mutex<TransportHandler>>,
}

impl Link {
    /// Create a new `Link` by snapshotting the link's immutable fields.
    ///
    /// This is crate-private; callers obtain handles from `Transport::link()`,
    /// `Transport::find_out_link()`, or `Transport::find_in_link()`.
    #[allow(private_interfaces)]
    pub(crate) fn new(
        inner: Arc<Mutex<LinkInner>>,
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
    // Resource packet send (lock inner → build packet → lock handler → send)
    // ========================================================================

    /// Send a resource advertisement packet over the link.
    pub async fn send_resource_advertisement(
        &self,
        advertisement: &ResourceAdvertisement,
        segment: usize,
    ) -> Result<(), RnsError> {
        let packet = self
            .inner
            .lock()
            .await
            .resource_advertisement_packet(advertisement, segment)?;
        self.handler.lock().await.send_packet(packet).await;
        Ok(())
    }

    /// Send a resource data packet over the link.
    ///
    /// Resource data packets are NOT encrypted at the link level — the resource
    /// handles its own encryption internally.
    pub async fn send_resource_data(&self, data: &[u8]) -> Result<(), RnsError> {
        let packet = self.inner.lock().await.resource_data_packet(data)?;
        self.handler.lock().await.send_packet(packet).await;
        Ok(())
    }

    // ========================================================================
    // Resource tracking (lock inner only, no send)
    // ========================================================================

    /// Register an outgoing resource for tracking and transfer.
    /// Returns the resource ID if registered successfully.
    pub async fn register_outgoing_resource(
        &self,
        resource: &Resource,
    ) -> Result<ResourceId, RnsError> {
        self.inner
            .lock()
            .await
            .register_outgoing_resource(resource.inner_arc().clone())
    }

    /// Get an outgoing resource by resource ID.
    ///
    /// Returns `None` if no resource with that ID is tracked.
    pub async fn get_outgoing_resource(
        &self,
        resource_id: &ResourceId,
    ) -> Option<Resource> {
        self.inner
            .lock()
            .await
            .get_outgoing_resource(resource_id)
            .map(|tracked| Resource::from_inner(tracked.resource.clone()))
    }

    /// Notify the link that a resource transfer has concluded.
    /// Updates optimisation hints (window size, expected in-flight rate).
    pub async fn resource_concluded(&self, resource_id: &ResourceId, success: bool) {
        self.inner
            .lock()
            .await
            .resource_concluded(resource_id, success);
    }

    // ========================================================================
    // Decrypt (lock inner only, no send)
    // ========================================================================

    /// Decrypt data using the link's derived key.
    ///
    /// Allocates a buffer internally and returns the decrypted bytes.
    pub async fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, RnsError> {
        let mut buffer = vec![0u8; data.len() + 64];
        let decrypted = self.inner.lock().await.decrypt(data, &mut buffer)?;
        Ok(decrypted.to_vec())
    }

    // ========================================================================
    // Simple getters (lock inner only)
    // ========================================================================

    /// Last time data was sent or received on this link.
    pub async fn last_data(&self) -> Option<Instant> {
        self.inner.lock().await.last_data()
    }

    /// When the link became active (completed handshake).
    pub async fn activated_at(&self) -> Option<Instant> {
        self.inner.lock().await.activated_at()
    }

    // ========================================================================
    // Physical layer stats (lock inner only)
    // ========================================================================

    /// Enable or disable physical layer stats tracking on this link.
    pub async fn set_track_phy_stats(&self, track: bool) {
        self.inner.lock().await.set_track_phy_stats(track);
    }

    /// Whether physical layer stats tracking is enabled.
    pub async fn track_phy_stats(&self) -> bool {
        self.inner.lock().await.track_phy_stats()
    }

    /// Get the last known RSSI value (dBm).
    pub async fn get_rssi(&self) -> Option<i16> {
        self.inner.lock().await.get_rssi()
    }

    /// Get the last known signal-to-noise ratio (dB).
    pub async fn get_snr(&self) -> Option<f32> {
        self.inner.lock().await.get_snr()
    }

    /// Get the last known link quality metric.
    pub async fn get_q(&self) -> Option<f32> {
        self.inner.lock().await.get_q()
    }

    /// Get current physical layer stats (RSSI, SNR, Q) in one lock acquisition.
    pub async fn get_phy_stats(&self) -> (Option<i16>, Option<f32>, Option<f32>) {
        let inner = self.inner.lock().await;
        (inner.get_rssi(), inner.get_snr(), inner.get_q())
    }

    // ========================================================================
    // High-level request/response (lock inner → build + register → send)
    // ========================================================================

    /// Send a structured request to a named path over the link.
    ///
    /// This is the high-level counterpart to `send_request()` (which sends
    /// raw pre-packed bytes). It matches Python's `Link.request(path, data, timeout)`:
    /// hashes the path, packs `[timestamp, path_hash, data]` as msgpack,
    /// checks MDU, and registers a request receipt.
    ///
    /// Returns a `SharedRequestReceipt` for tracking the response.
    pub async fn request(
        &self,
        path: &str,
        data: Option<&[u8]>,
        timeout: Option<Duration>,
    ) -> Result<SharedRequestReceipt, RnsError> {
        let (receipt, packet) = self.inner.lock().await.send_request(path, data, timeout)?;
        self.handler.lock().await.send_packet(packet).await;
        Ok(receipt)
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("id", &self.id)
            .field("destination", &self.destination.address_hash)
            .field("initiator", &self.initiator)
            .finish()
    }
}
