use std::{
    cmp::min,
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use ed25519_dalek::{Signature, SigningKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use rand_core::OsRng;
use sha2::Digest;
use tokio::sync::RwLock;
use x25519_dalek::StaticSecret;

use crate::{
    buffer::OutputBuffer,
    error::RnsError,
    hash::{AddressHash, Hash, ADDRESS_HASH_SIZE},
    identity::{DecryptIdentity, DerivedKey, EncryptIdentity, Identity, PrivateIdentity},
    packet::{
        DestinationType, Header, Packet, PacketContext, PacketDataBuffer, PacketType, PACKET_MDU,
    },
    resource::{Resource, ResourceAdvertisement},
};

use super::DestinationDesc;

const LINK_MTU_SIZE: usize = 3;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum LinkStatus {
    Pending = 0x00,
    Handshake = 0x01,
    Active = 0x02,
    Stale = 0x03,
    Closed = 0x04,
}

impl LinkStatus {
    pub fn not_yet_active(&self) -> bool {
        *self == LinkStatus::Pending || *self == LinkStatus::Handshake
    }
}

pub type LinkId = AddressHash;

#[derive(Clone)]
pub struct LinkPayload {
    buffer: [u8; PACKET_MDU],
    len: usize,
}

impl LinkPayload {
    pub fn new() -> Self {
        Self {
            buffer: [0u8; PACKET_MDU],
            len: 0,
        }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut buffer = [0u8; PACKET_MDU];

        let len = min(data.len(), buffer.len());

        buffer[..len].copy_from_slice(&data[..len]);

        Self { buffer, len }
    }

    pub fn new_from_vec(data: &Vec<u8>) -> Self {
        let mut buffer = [0u8; PACKET_MDU];

        for i in 0..min(buffer.len(), data.len()) {
            buffer[i] = data[i];
        }

        Self {
            buffer,
            len: data.len(),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

impl From<&Packet> for LinkId {
    fn from(packet: &Packet) -> Self {
        let data = packet.data.as_slice();
        let data_diff = if data.len() > PUBLIC_KEY_LENGTH * 2 {
            data.len() - PUBLIC_KEY_LENGTH * 2
        } else {
            0
        };

        let hashable_data = &data[..data.len() - data_diff];

        AddressHash::new_from_hash(&Hash::new(
            Hash::generator()
                .chain_update(&[packet.header.to_meta() & 0b00001111])
                .chain_update(packet.destination.as_slice())
                .chain_update(&[packet.context as u8])
                .chain_update(hashable_data)
                .finalize()
                .into(),
        ))
    }
}

pub enum LinkHandleResult {
    None,
    Activated,
    KeepAlive,
}

#[derive(Clone)]
pub enum LinkEvent {
    Activated,
    Data(LinkPayload),
    /// Resource advertisement received (contains unpacked ResourceAdvertisement)
    ResourceAdvertisement(LinkPayload),
    /// Resource data part received
    ResourceData(LinkPayload),
    /// Resource request received
    ResourceRequest(LinkPayload),
    /// Resource hashmap update received
    ResourceHashmapUpdate(LinkPayload),
    /// Resource proof received
    ResourceProof(LinkPayload),
    /// Resource initiator cancel received
    ResourceInitiatorCancel(LinkPayload),
    /// Resource receiver cancel received
    ResourceReceiverCancel(LinkPayload),
    Closed,
}

#[derive(Clone)]
pub struct LinkEventData {
    pub id: LinkId,
    pub address_hash: AddressHash,
    pub event: LinkEvent,
}

/// Type alias for resource identification (truncated hash)
pub type ResourceId = [u8; 16];

/// Tracked outgoing resource with state
pub struct TrackedResource {
    /// The resource being transferred
    pub resource: Arc<RwLock<Resource>>,
    /// When the resource was registered
    pub registered_at: Instant,
}

/// Maximum number of concurrent outgoing resources per link
pub const MAX_OUTGOING_RESOURCES: usize = 16;

pub struct Link {
    id: LinkId,
    destination: DestinationDesc,
    priv_identity: PrivateIdentity,
    peer_identity: Identity,
    derived_key: DerivedKey,
    status: LinkStatus,
    request_time: Instant,
    rtt: Duration,
    event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    /// Outgoing resources tracked by their truncated hash
    outgoing_resources: HashMap<ResourceId, TrackedResource>,
    /// Incoming resources tracked by their truncated hash
    incoming_resources: HashMap<ResourceId, TrackedResource>,
    /// Last resource window size (for optimization)
    last_resource_window: usize,
    /// Last expected in-flight rate (bits per second)
    last_resource_eifr: Option<f64>,
}

impl Link {
    pub fn new(
        destination: DestinationDesc,
        event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    ) -> Self {
        Self {
            id: AddressHash::new_empty(),
            destination,
            priv_identity: PrivateIdentity::new_from_rand(OsRng),
            peer_identity: Identity::default(),
            derived_key: DerivedKey::new_empty(),
            status: LinkStatus::Pending,
            request_time: Instant::now(),
            rtt: Duration::from_secs(0),
            event_tx,
            outgoing_resources: HashMap::new(),
            incoming_resources: HashMap::new(),
            last_resource_window: crate::resource::WINDOW_INITIAL,
            last_resource_eifr: None,
        }
    }

    pub fn new_from_request(
        packet: &Packet,
        signing_key: SigningKey,
        destination: DestinationDesc,
        event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    ) -> Result<Self, RnsError> {
        if packet.data.len() < PUBLIC_KEY_LENGTH * 2 {
            return Err(RnsError::InvalidArgument);
        }

        let peer_identity = Identity::new_from_slices(
            &packet.data.as_slice()[..PUBLIC_KEY_LENGTH],
            &packet.data.as_slice()[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2],
        );

        let link_id = LinkId::from(packet);
        log::debug!("link: create from request {}", link_id);

        let mut link = Self {
            id: link_id,
            destination,
            priv_identity: PrivateIdentity::new(StaticSecret::random_from_rng(OsRng), signing_key),
            peer_identity,
            derived_key: DerivedKey::new_empty(),
            status: LinkStatus::Pending,
            request_time: Instant::now(),
            rtt: Duration::from_secs(0),
            event_tx,
            outgoing_resources: HashMap::new(),
            incoming_resources: HashMap::new(),
            last_resource_window: crate::resource::WINDOW_INITIAL,
            last_resource_eifr: None,
        };

        link.handshake(peer_identity);

        Ok(link)
    }

    pub fn request(&mut self) -> Packet {
        let mut packet_data = PacketDataBuffer::new();

        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());

        let packet = Packet {
            header: Header {
                packet_type: PacketType::LinkRequest,
                ..Default::default()
            },
            ifac: None,
            destination: self.destination.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        };

        self.status = LinkStatus::Pending;
        self.id = LinkId::from(&packet);
        self.request_time = Instant::now();

        packet
    }

    pub fn prove(&mut self) -> Packet {
        log::debug!("link({}): prove", self.id);

        if self.status != LinkStatus::Active {
            self.status = LinkStatus::Active;
            self.post_event(LinkEvent::Activated);
        }

        let mut packet_data = PacketDataBuffer::new();

        packet_data.safe_write(self.id.as_slice());
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());

        let signature = self.priv_identity.sign(packet_data.as_slice());

        packet_data.reset();
        packet_data.safe_write(&signature.to_bytes()[..]);
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());

        let packet = Packet {
            header: Header {
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::LinkRequestProof,
            data: packet_data,
        };

        packet
    }

    fn handle_data_packet(&mut self, packet: &Packet) -> LinkHandleResult {
        if self.status != LinkStatus::Active {
            log::warn!("link({}): handling data packet in inactive state", self.id);
        }

        match packet.context {
            PacketContext::None => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): data {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::Data(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt packet", self.id);
                }
            }
            PacketContext::KeepAlive => {
                if packet.data.len() >= 1 && packet.data.as_slice()[0] == 0xFF {
                    self.request_time = Instant::now();
                    log::trace!("link({}): keep-alive request", self.id);
                    return LinkHandleResult::KeepAlive;
                }
                if packet.data.len() >= 1 && packet.data.as_slice()[0] == 0xFE {
                    log::trace!("link({}): keep-alive response", self.id);
                    self.request_time = Instant::now();
                    return LinkHandleResult::None;
                }
            }
            // Resource packet types - decrypt and post event for higher-level handling
            PacketContext::ResourceAdvrtisement => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): resource advertisement {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::ResourceAdvertisement(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt resource advertisement", self.id);
                }
            }
            PacketContext::Resource => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): resource data {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::ResourceData(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt resource data", self.id);
                }
            }
            PacketContext::ResourceRequest => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): resource request {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::ResourceRequest(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt resource request", self.id);
                }
            }
            PacketContext::ResourceHashUpdate => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): resource hashmap update {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::ResourceHashmapUpdate(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt resource hashmap update", self.id);
                }
            }
            PacketContext::ResourceProof => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): resource proof {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::ResourceProof(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt resource proof", self.id);
                }
            }
            PacketContext::ResourceInitiatorCancel => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): resource initiator cancel {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::ResourceInitiatorCancel(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt resource initiator cancel", self.id);
                }
            }
            PacketContext::ResourceReceiverCancel => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): resource receiver cancel {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::ResourceReceiverCancel(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt resource receiver cancel", self.id);
                }
            }
            _ => {
                log::trace!("link({}): unhandled packet context {:?}", self.id, packet.context);
            }
        }

        LinkHandleResult::None
    }

    pub fn handle_packet(&mut self, packet: &Packet) -> LinkHandleResult {
        if packet.destination != self.id {
            return LinkHandleResult::None;
        }

        match packet.header.packet_type {
            PacketType::Data => return self.handle_data_packet(packet),
            PacketType::Proof => {
                if self.status == LinkStatus::Pending
                    && packet.context == PacketContext::LinkRequestProof
                {
                    if let Ok(identity) = validate_proof_packet(&self.destination, &self.id, packet)
                    {
                        log::debug!("link({}): has been proved", self.id);

                        self.handshake(identity);

                        self.status = LinkStatus::Active;
                        self.rtt = self.request_time.elapsed();

                        log::debug!("link({}): activated", self.id);

                        self.post_event(LinkEvent::Activated);

                        return LinkHandleResult::Activated;
                    } else {
                        log::warn!("link({}): proof is not valid", self.id);
                    }
                }
            }
            _ => {}
        }

        return LinkHandleResult::None;
    }

    pub fn data_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            log::warn!("link: can't create data packet for closed link");
        }

        let mut packet_data = PacketDataBuffer::new();

        let cipher_text_len = {
            let cipher_text = self.encrypt(data, packet_data.accuire_buf_max())?;
            cipher_text.len()
        };

        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }

    pub fn keep_alive_packet(&self, data: u8) -> Packet {
        log::trace!("link({}): create keep alive {}", self.id, data);

        let mut packet_data = PacketDataBuffer::new();
        packet_data.safe_write(&[data]);

        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::KeepAlive,
            data: packet_data,
        }
    }

    pub fn encrypt<'a>(&self, text: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        self.priv_identity
            .encrypt(OsRng, text, &self.derived_key, out_buf)
    }

    pub fn decrypt<'a>(&self, text: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        self.priv_identity
            .decrypt(OsRng, text, &self.derived_key, out_buf)
    }

    pub fn destination(&self) -> &DestinationDesc {
        &self.destination
    }

    pub fn create_rtt(&self) -> Packet {
        let rtt = self.rtt.as_secs_f32();
        let mut buf = Vec::new();
        {
            buf.reserve(4);
            rmp::encode::write_f32(&mut buf, rtt).unwrap();
        }

        let mut packet_data = PacketDataBuffer::new();

        let token_len = {
            let token = self
                .encrypt(buf.as_slice(), packet_data.accuire_buf_max())
                .expect("encrypted data");
            token.len()
        };

        packet_data.resize(token_len);

        log::trace!("link: {} create rtt packet = {} sec", self.id, rtt);

        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::LinkRTT,
            data: packet_data,
        }
    }

    fn handshake(&mut self, peer_identity: Identity) {
        log::debug!("link({}): handshake", self.id);

        self.status = LinkStatus::Handshake;
        self.peer_identity = peer_identity;

        self.derived_key = self
            .priv_identity
            .derive_key(&self.peer_identity.public_key, Some(&self.id.as_slice()));
    }

    fn post_event(&self, event: LinkEvent) {
        let _ = self.event_tx.send(LinkEventData {
            id: self.id,
            address_hash: self.destination.address_hash,
            event,
        });
    }
    pub fn close(&mut self) {
        self.status = LinkStatus::Closed;

        self.post_event(LinkEvent::Closed);

        log::warn!("link: close {}", self.id);
    }

    pub fn restart(&mut self) {
        log::warn!(
            "link({}): restart after {}s",
            self.id,
            self.request_time.elapsed().as_secs()
        );

        self.status = LinkStatus::Pending;
    }

    pub fn elapsed(&self) -> Duration {
        self.request_time.elapsed()
    }

    pub fn status(&self) -> LinkStatus {
        self.status
    }

    pub fn id(&self) -> &LinkId {
        &self.id
    }

    /// Get round-trip time measurement
    pub fn rtt(&self) -> Duration {
        self.rtt
    }

    // ========================================================================
    // Resource Management Methods
    // ========================================================================

    /// Register an outgoing resource for tracking and transfer.
    /// Returns the resource ID if registered successfully, or error if limit reached.
    pub fn register_outgoing_resource(&mut self, resource: Arc<RwLock<Resource>>) -> Result<ResourceId, RnsError> {
        if self.outgoing_resources.len() >= MAX_OUTGOING_RESOURCES {
            log::warn!("link({}): cannot register outgoing resource, limit reached", self.id);
            return Err(RnsError::InvalidArgument);
        }

        // Get the truncated hash synchronously by blocking briefly
        // In production, this should be refactored to be fully async
        let resource_id = {
            let resource_guard = futures::executor::block_on(resource.read());
            *resource_guard.truncated_hash()
        };

        log::debug!(
            "link({}): registering outgoing resource {}",
            self.id,
            hex::encode(&resource_id)
        );

        self.outgoing_resources.insert(
            resource_id,
            TrackedResource {
                resource,
                registered_at: Instant::now(),
            },
        );

        Ok(resource_id)
    }

    /// Register an incoming resource for tracking during reception.
    /// Returns the resource ID if registered successfully.
    pub fn register_incoming_resource(&mut self, resource: Arc<RwLock<Resource>>) -> Result<ResourceId, RnsError> {
        let resource_id = {
            let resource_guard = futures::executor::block_on(resource.read());
            *resource_guard.truncated_hash()
        };

        log::debug!(
            "link({}): registering incoming resource {}",
            self.id,
            hex::encode(&resource_id)
        );

        self.incoming_resources.insert(
            resource_id,
            TrackedResource {
                resource,
                registered_at: Instant::now(),
            },
        );

        Ok(resource_id)
    }

    /// Check if the link has a specific incoming resource already
    pub fn has_incoming_resource(&self, resource_id: &ResourceId) -> bool {
        self.incoming_resources.contains_key(resource_id)
    }

    /// Check if the link has a specific outgoing resource
    pub fn has_outgoing_resource(&self, resource_id: &ResourceId) -> bool {
        self.outgoing_resources.contains_key(resource_id)
    }

    /// Get an outgoing resource by ID
    pub fn get_outgoing_resource(&self, resource_id: &ResourceId) -> Option<&TrackedResource> {
        self.outgoing_resources.get(resource_id)
    }

    /// Get an incoming resource by ID
    pub fn get_incoming_resource(&self, resource_id: &ResourceId) -> Option<&TrackedResource> {
        self.incoming_resources.get(resource_id)
    }

    /// Cancel and remove an outgoing resource
    pub fn cancel_outgoing_resource(&mut self, resource_id: &ResourceId) -> bool {
        if let Some(tracked) = self.outgoing_resources.remove(resource_id) {
            log::debug!(
                "link({}): canceling outgoing resource {}",
                self.id,
                hex::encode(resource_id)
            );
            // Cancel the resource itself
            let mut resource = futures::executor::block_on(tracked.resource.write());
            resource.cancel();
            true
        } else {
            false
        }
    }

    /// Cancel and remove an incoming resource
    pub fn cancel_incoming_resource(&mut self, resource_id: &ResourceId) -> bool {
        if let Some(tracked) = self.incoming_resources.remove(resource_id) {
            log::debug!(
                "link({}): canceling incoming resource {}",
                self.id,
                hex::encode(resource_id)
            );
            let mut resource = futures::executor::block_on(tracked.resource.write());
            resource.cancel();
            true
        } else {
            false
        }
    }

    /// Check if the link is ready to accept a new outgoing resource.
    /// The Python implementation allows only one outgoing resource at a time
    /// for simplicity, but we support multiple with a limit.
    pub fn ready_for_new_resource(&self) -> bool {
        if self.status != LinkStatus::Active {
            return false;
        }
        self.outgoing_resources.len() < MAX_OUTGOING_RESOURCES
    }

    /// Get the last resource window size used (for optimization)
    pub fn get_last_resource_window(&self) -> usize {
        self.last_resource_window
    }

    /// Get the last expected in-flight rate (bits per second)
    pub fn get_last_resource_eifr(&self) -> Option<f64> {
        self.last_resource_eifr
    }

    /// Called when a resource transfer completes to update optimization hints.
    /// Updates the link's last_resource_window and last_resource_eifr for
    /// future resource transfers on this link.
    pub fn resource_concluded(&mut self, resource_id: &ResourceId, success: bool) {
        // Check outgoing first
        if let Some(tracked) = self.outgoing_resources.remove(resource_id) {
            let resource = futures::executor::block_on(tracked.resource.read());
            let progress = resource.progress();

            if success {
                // Update optimization hints from successful transfer
                self.last_resource_window = resource.window();
                if let Some(eifr) = progress.eifr {
                    self.last_resource_eifr = Some(eifr);
                }
            }

            log::debug!(
                "link({}): outgoing resource {} concluded (success={})",
                self.id,
                hex::encode(resource_id),
                success
            );
            return;
        }

        // Check incoming
        if let Some(tracked) = self.incoming_resources.remove(resource_id) {
            let resource = futures::executor::block_on(tracked.resource.read());
            let progress = resource.progress();

            if success {
                self.last_resource_window = resource.window();
                if let Some(eifr) = progress.eifr {
                    self.last_resource_eifr = Some(eifr);
                }
            }

            log::debug!(
                "link({}): incoming resource {} concluded (success={})",
                self.id,
                hex::encode(resource_id),
                success
            );
        }
    }

    /// Create a resource advertisement packet for sending over this link.
    /// The advertisement data is encrypted using the link's derived key.
    pub fn resource_advertisement_packet(
        &self,
        advertisement: &ResourceAdvertisement,
        segment: usize,
    ) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            log::warn!("link: cannot create resource advertisement on inactive link");
            return Err(RnsError::InvalidArgument);
        }

        // Pack the advertisement into MessagePack format
        let adv_data = advertisement.pack(segment)?;

        // Create encrypted packet
        let mut packet_data = PacketDataBuffer::new();
        let cipher_text_len = {
            let cipher_text = self.encrypt(&adv_data, packet_data.accuire_buf_max())?;
            cipher_text.len()
        };
        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::ResourceAdvrtisement,
            data: packet_data,
        })
    }

    /// Create a resource data packet for sending a resource part.
    pub fn resource_data_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            log::warn!("link: cannot create resource data packet on inactive link");
            return Err(RnsError::InvalidArgument);
        }

        let mut packet_data = PacketDataBuffer::new();
        let cipher_text_len = {
            let cipher_text = self.encrypt(data, packet_data.accuire_buf_max())?;
            cipher_text.len()
        };
        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::Resource,
            data: packet_data,
        })
    }

    /// Create a resource request packet for requesting specific parts.
    pub fn resource_request_packet(&self, request_data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            return Err(RnsError::InvalidArgument);
        }

        let mut packet_data = PacketDataBuffer::new();
        let cipher_text_len = {
            let cipher_text = self.encrypt(request_data, packet_data.accuire_buf_max())?;
            cipher_text.len()
        };
        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::ResourceRequest,
            data: packet_data,
        })
    }

    /// Create a resource hashmap update packet.
    pub fn resource_hashmap_update_packet(&self, hashmap_data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            return Err(RnsError::InvalidArgument);
        }

        let mut packet_data = PacketDataBuffer::new();
        let cipher_text_len = {
            let cipher_text = self.encrypt(hashmap_data, packet_data.accuire_buf_max())?;
            cipher_text.len()
        };
        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::ResourceHashUpdate,
            data: packet_data,
        })
    }

    /// Create a resource proof packet.
    pub fn resource_proof_packet(&self, proof_data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            return Err(RnsError::InvalidArgument);
        }

        let mut packet_data = PacketDataBuffer::new();
        let cipher_text_len = {
            let cipher_text = self.encrypt(proof_data, packet_data.accuire_buf_max())?;
            cipher_text.len()
        };
        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::ResourceProof,
            data: packet_data,
        })
    }

    /// Create a resource cancel packet (initiator side).
    pub fn resource_initiator_cancel_packet(&self, cancel_data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            return Err(RnsError::InvalidArgument);
        }

        let mut packet_data = PacketDataBuffer::new();
        let cipher_text_len = {
            let cipher_text = self.encrypt(cancel_data, packet_data.accuire_buf_max())?;
            cipher_text.len()
        };
        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::ResourceInitiatorCancel,
            data: packet_data,
        })
    }

    /// Create a resource cancel packet (receiver side).
    pub fn resource_receiver_cancel_packet(&self, cancel_data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            return Err(RnsError::InvalidArgument);
        }

        let mut packet_data = PacketDataBuffer::new();
        let cipher_text_len = {
            let cipher_text = self.encrypt(cancel_data, packet_data.accuire_buf_max())?;
            cipher_text.len()
        };
        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::ResourceReceiverCancel,
            data: packet_data,
        })
    }

    /// Count of active outgoing resources
    pub fn outgoing_resource_count(&self) -> usize {
        self.outgoing_resources.len()
    }

    /// Count of active incoming resources
    pub fn incoming_resource_count(&self) -> usize {
        self.incoming_resources.len()
    }
}

fn validate_proof_packet(
    destination: &DestinationDesc,
    id: &LinkId,
    packet: &Packet,
) -> Result<Identity, RnsError> {
    const MIN_PROOF_LEN: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH;
    const MTU_PROOF_LEN: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + LINK_MTU_SIZE;
    const SIGN_DATA_LEN: usize = ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE;

    if packet.data.len() < MIN_PROOF_LEN {
        return Err(RnsError::PacketError);
    }

    let mut proof_data = [0u8; SIGN_DATA_LEN];

    let verifying_key = destination.identity.verifying_key.as_bytes();
    let sign_data_len = {
        let mut output = OutputBuffer::new(&mut proof_data[..]);

        output.write(id.as_slice())?;
        output.write(
            &packet.data.as_slice()[SIGNATURE_LENGTH..SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH],
        )?;
        output.write(verifying_key)?;

        if packet.data.len() >= MTU_PROOF_LEN {
            let mtu_bytes = &packet.data.as_slice()[SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH..];
            output.write(mtu_bytes)?;
        }

        output.offset()
    };

    let identity = Identity::new_from_slices(
        &proof_data[ADDRESS_HASH_SIZE..ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH],
        verifying_key,
    );

    let signature = Signature::from_slice(&packet.data.as_slice()[..SIGNATURE_LENGTH])
        .map_err(|_| RnsError::CryptoError)?;

    identity
        .verify(&proof_data[..sign_data_len], &signature)
        .map_err(|_| RnsError::IncorrectSignature)?;

    Ok(identity)
}
