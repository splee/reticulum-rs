//! A cloneable, cacheable facade over a `LinkInner` for higher-layer protocols.
//!
//! `Link` snapshots immutable link fields (id, destination, initiator) at
//! construction time so consumers can read them without acquiring any lock.
//! Mutable state reads (status, rtt, …) acquire only the inner `LinkInner` mutex.
//! Send operations acquire the `LinkInner` mutex to build the packet, then the
//! `TransportHandler` mutex to transmit it, keeping the locking dance internal.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, Mutex};

use crate::destination::link::{LinkEventData, LinkEvent, LinkInner, LinkId, LinkStatus, ResourceId};
use crate::destination::request_receipt::SharedRequestReceipt;
use crate::destination::DestinationDesc;
use crate::error::RnsError;
use crate::identity::{Identity, PrivateIdentity};
use crate::packet::RETICULUM_MDU;
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

    // Broadcast sender for out-link events (used for resource-based response handling)
    link_out_event_tx: broadcast::Sender<LinkEventData>,
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
        link_out_event_tx: broadcast::Sender<LinkEventData>,
    ) -> Self {
        Self {
            id,
            destination,
            initiator,
            inner,
            handler,
            link_out_event_tx,
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

    /// Send a resource hashmap update packet over the link.
    pub async fn send_resource_hashmap_update(&self, data: &[u8]) -> Result<(), RnsError> {
        let packet = self.inner.lock().await.resource_hashmap_update_packet(data)?;
        self.handler.lock().await.send_packet(packet).await;
        Ok(())
    }

    /// Send a resource request packet on this link.
    pub(crate) async fn send_resource_request(&self, request_data: &[u8]) -> Result<(), RnsError> {
        let packet = self.inner.lock().await.resource_request_packet(request_data)?;
        self.handler.lock().await.send_packet(packet).await;
        Ok(())
    }

    /// Send a resource proof packet on this link.
    pub(crate) async fn send_resource_proof(&self, proof_data: &[u8]) -> Result<(), RnsError> {
        let packet = self.inner.lock().await.resource_proof_packet(proof_data)?;
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
        let request_id = *receipt.lock().await.request_id();
        self.handler.lock().await.send_packet(packet).await;

        // Spawn a background task that subscribes to out-link events and
        // transparently drives Resource-based response transfers. If the
        // response fits in a single packet, `handle_response()` resolves the
        // receipt directly and this task exits on the `concluded()` check.
        let events_rx = self.link_out_event_tx.subscribe();
        tokio::spawn(drive_response_resource_receipt(
            events_rx,
            self.clone(),
            request_id,
        ));

        Ok(receipt)
    }
}

/// Maximum response resource size to prevent OOM (16 MiB).
const MAX_RESPONSE_RESOURCE_SIZE: usize = 16 * 1024 * 1024;

/// Timeout for the response resource handler task (matches transport.rs).
const RESPONSE_RESOURCE_TIMEOUT: Duration = Duration::from_secs(120);

/// Background task that drives a Resource-based response transfer for
/// `Link::request()`. Subscribes to out-link events and handles the
/// ResourceAdvertisement → ResourceData → completion flow.
///
/// When the resource transfer completes, the assembled data is fed to
/// `LinkInner::handle_response()` which resolves the pending
/// `SharedRequestReceipt` using existing parsing/resolution logic.
///
/// Exits early if:
/// - The receipt is already concluded (single-packet response resolved it)
/// - The link closes
/// - The 120-second deadline expires
async fn drive_response_resource_receipt(
    mut events: broadcast::Receiver<LinkEventData>,
    link: Link,
    request_id: [u8; 16],
) {
    let deadline = tokio::time::Instant::now() + RESPONSE_RESOURCE_TIMEOUT;
    let mut response_resource: Option<Resource> = None;
    let mut resource_bytes_received: usize = 0;

    loop {
        // Early exit if the receipt was already resolved (single-packet response
        // or timed out via the receipt's own timeout).
        {
            let inner = link.inner.lock().await;
            if inner.get_pending_request(&request_id).is_none() {
                return;
            }
        }

        tokio::select! {
            result = events.recv() => {
                match result {
                    Ok(event) => {
                        if event.id != link.id {
                            continue;
                        }
                        match &event.event {
                            LinkEvent::ResourceAdvertisement(payload) => {
                                match ResourceAdvertisement::unpack(payload.as_slice()) {
                                    Ok(adv) => {
                                        if !adv.is_response() {
                                            continue;
                                        }

                                        // Verify the request_id matches our pending request
                                        if let Some(adv_req_id) = adv.request_id {
                                            if adv_req_id != request_id {
                                                continue;
                                            }
                                        }

                                        if adv.transfer_size > MAX_RESPONSE_RESOURCE_SIZE {
                                            log::warn!(
                                                "link({}): rejecting response resource ({} bytes \
                                                 exceeds {} byte limit)",
                                                link.id, adv.transfer_size, MAX_RESPONSE_RESOURCE_SIZE,
                                            );
                                            continue;
                                        }

                                        log::debug!(
                                            "link({}): received response resource advertisement \
                                             ({} parts, {} bytes)",
                                            link.id, adv.num_parts, adv.transfer_size,
                                        );

                                        match Resource::from_advertisement(&adv, RETICULUM_MDU) {
                                            Ok(resource) => {
                                                // Request first batch of parts
                                                if let Some(req_data) = resource.request_next() {
                                                    if let Err(e) = link.send_resource_request(&req_data).await {
                                                        log::warn!(
                                                            "link({}): failed to send resource request: {:?}",
                                                            link.id, e,
                                                        );
                                                        return;
                                                    }
                                                    resource.mark_request_sent(req_data.len());
                                                }
                                                response_resource = Some(resource);
                                                resource_bytes_received = 0;
                                            }
                                            Err(e) => {
                                                log::warn!(
                                                    "link({}): failed to create resource from advertisement: {:?}",
                                                    link.id, e,
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "link({}): failed to unpack resource advertisement: {:?}",
                                            link.id, e,
                                        );
                                    }
                                }
                            }

                            LinkEvent::ResourceData(payload) => {
                                if let Some(ref resource) = response_resource {
                                    // Guard against a peer sending more data than advertised
                                    resource_bytes_received += payload.len();
                                    if resource_bytes_received > resource.size() {
                                        log::warn!(
                                            "link({}): received {} bytes exceeds advertised \
                                             transfer size {} — cancelling resource",
                                            link.id, resource_bytes_received, resource.size(),
                                        );
                                        response_resource = None;
                                        continue;
                                    }

                                    if resource.receive_part(payload.as_slice().to_vec()) {
                                        if resource.is_complete() {
                                            // All parts received — assemble, decrypt, finalize
                                            finalize_and_resolve(
                                                resource, &link, &request_id,
                                            ).await;
                                            return;
                                        }

                                        // Request more parts
                                        if let Some(req_data) = resource.request_next() {
                                            if let Err(e) = link.send_resource_request(&req_data).await {
                                                log::warn!(
                                                    "link({}): failed to send resource request: {:?}",
                                                    link.id, e,
                                                );
                                                return;
                                            }
                                            resource.mark_request_sent(req_data.len());
                                        }
                                    }
                                }
                            }

                            LinkEvent::ResourceHashmapUpdate(payload) => {
                                if let Some(ref resource) = response_resource {
                                    if let Some((_hash, segment, hashmap_data)) =
                                        Resource::parse_hashmap_update(payload.as_slice())
                                    {
                                        resource.update_hashmap(segment, &hashmap_data);

                                        // Request more parts after hashmap update
                                        if let Some(req_data) = resource.request_next() {
                                            if let Err(e) = link.send_resource_request(&req_data).await {
                                                log::warn!(
                                                    "link({}): failed to send resource request: {:?}",
                                                    link.id, e,
                                                );
                                                return;
                                            }
                                            resource.mark_request_sent(req_data.len());
                                        }
                                    }
                                }
                            }

                            LinkEvent::Closed => {
                                return;
                            }

                            _ => {}
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!(
                            "link({}): response resource handler lagged {} events",
                            link.id, n,
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return;
                    }
                }
            }

            _ = tokio::time::sleep_until(deadline) => {
                log::debug!(
                    "link({}): response resource handler timed out for request {}",
                    link.id, hex::encode(&request_id[..8]),
                );
                return;
            }
        }
    }
}

/// Assemble, decrypt, finalize the resource and resolve the pending request receipt.
async fn finalize_and_resolve(
    resource: &Resource,
    link: &Link,
    request_id: &[u8; 16],
) {
    // Get the raw assembled data (still encrypted)
    let raw_data = match resource.get_raw_assembled_data() {
        Some(data) => data,
        None => {
            log::warn!(
                "link({}): failed to get raw assembled data for response resource",
                link.id,
            );
            return;
        }
    };

    // Decrypt if the resource was encrypted
    let decrypted = if resource.is_encrypted() {
        match link.decrypt(&raw_data).await {
            Ok(d) => d,
            Err(e) => {
                log::warn!(
                    "link({}): failed to decrypt response resource: {:?}",
                    link.id, e,
                );
                return;
            }
        }
    } else {
        raw_data
    };

    // Finalize assembly (strips random hash, decompresses, verifies hash)
    let assembled = match resource.finalize_assembly(decrypted) {
        Ok(a) => a,
        Err(e) => {
            log::warn!(
                "link({}): failed to finalize response resource: {:?}",
                link.id, e,
            );
            return;
        }
    };

    // Send proof to acknowledge successful receipt
    let proof = resource.generate_proof_with_data(&assembled);
    if let Err(e) = link.send_resource_proof(&proof).await {
        log::warn!(
            "link({}): failed to send resource proof: {:?}",
            link.id, e,
        );
        // Continue anyway — the receipt should still be resolved
    }

    // Resolve the pending request receipt via handle_response()
    // The assembled data is the same [request_id, response_data] msgpack
    // that handle_response() already knows how to parse.
    link.inner.lock().await.handle_response(&assembled);

    log::debug!(
        "link({}): response resource transfer complete for request {} ({} bytes)",
        link.id, hex::encode(&request_id[..8]), assembled.len(),
    );
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
