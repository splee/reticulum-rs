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

/// Size of MTU/mode signalling field in link packets (3 bytes).
const LINK_MTU_SIZE: usize = 3;

/// Default link MTU matching Python's RNS.Reticulum.MTU (500 bytes).
const DEFAULT_LINK_MTU: u32 = 500;

/// Link encryption/signing modes (matching Python Link.py).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkMode {
    /// AES-128 CBC mode for encryption
    Aes128Cbc = 0x00,
    /// AES-256 CBC mode for encryption (default)
    Aes256Cbc = 0x01,
}

impl Default for LinkMode {
    fn default() -> Self {
        // Match Python's default mode (MODE_AES256_CBC)
        LinkMode::Aes256Cbc
    }
}

/// MTU byte mask for extracting MTU from signalling bytes (21 bits).
const MTU_BYTEMASK: u32 = 0x1FFFFF;

/// Mode byte mask for extracting mode from signalling bytes.
const MODE_BYTEMASK: u32 = 0xE0;

/// Generate signalling bytes for link MTU negotiation (matching Python Link.signalling_bytes).
///
/// Returns a 3-byte array encoding the MTU and link mode.
/// Format: Big-endian 24-bit value where:
/// - Lower 21 bits: MTU value
/// - Upper 3 bits: Mode (shifted left by 5)
fn signalling_bytes(mtu: u32, mode: LinkMode) -> [u8; LINK_MTU_SIZE] {
    let signalling_value = (mtu & MTU_BYTEMASK) + ((((mode as u32) << 5) & MODE_BYTEMASK) << 16);
    // Pack as big-endian 32-bit, take last 3 bytes (like Python's struct.pack(">I", ...)[1:])
    let packed = signalling_value.to_be_bytes();
    [packed[1], packed[2], packed[3]]
}

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

impl Default for LinkPayload {
    fn default() -> Self {
        Self::new()
    }
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

    pub fn new_from_vec(data: &[u8]) -> Self {
        let mut buffer = [0u8; PACKET_MDU];
        let len = min(buffer.len(), data.len());
        buffer[..len].copy_from_slice(&data[..len]);

        Self {
            buffer,
            len: data.len(),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the payload contains no data.
    pub fn is_empty(&self) -> bool {
        self.len == 0
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
                .chain_update([packet.header.to_meta() & 0b00001111])
                .chain_update(packet.destination.as_slice())
                .chain_update([packet.context as u8])
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
    /// Channel data received (for Channel message system)
    Channel(LinkPayload),
    /// Request received (path, data, request_id)
    Request(LinkPayload),
    /// Response received (request_id, data)
    Response(LinkPayload),
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
    /// Remote peer has identified themselves with their identity
    Identified(Identity),
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
    /// Whether this link was initiated by us (client) or received (server).
    initiator: bool,
    /// The remote peer's identity, if they have identified themselves.
    /// This is set when the link initiator calls identify() and the server
    /// validates the identity proof.
    remote_identity: Option<Identity>,
    /// Link encryption mode (AES-128 or AES-256 CBC).
    mode: LinkMode,
    /// Negotiated MTU for this link.
    mtu: u32,
}

impl Link {
    /// Create a new outgoing link (we are the initiator).
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
            initiator: true,
            remote_identity: None,
            mode: LinkMode::default(),
            mtu: DEFAULT_LINK_MTU,
        }
    }

    /// Create a link from an incoming request (we are the server/destination).
    pub fn new_from_request(
        packet: &Packet,
        signing_key: SigningKey,
        destination: DestinationDesc,
        event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    ) -> Result<Self, RnsError> {
        // Link request data format (matching Python):
        // - pub_bytes: 32 bytes (X25519 public key)
        // - sig_pub_bytes: 32 bytes (Ed25519 verifying key)
        // - signalling_bytes: 3 bytes (optional, MTU + mode)
        // Total: 67 bytes with signalling, 64 bytes without
        if packet.data.len() < PUBLIC_KEY_LENGTH * 2 {
            return Err(RnsError::InvalidArgument);
        }

        let peer_identity = Identity::new_from_slices(
            &packet.data.as_slice()[..PUBLIC_KEY_LENGTH],
            &packet.data.as_slice()[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2],
        );

        // Parse MTU and mode from signalling bytes if present
        let (mtu, mode) = if packet.data.len() >= PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE {
            let sig_start = PUBLIC_KEY_LENGTH * 2;
            let sig_bytes = &packet.data.as_slice()[sig_start..sig_start + LINK_MTU_SIZE];
            let mtu_value = ((sig_bytes[0] as u32) << 16)
                + ((sig_bytes[1] as u32) << 8)
                + (sig_bytes[2] as u32);
            let mtu = mtu_value & MTU_BYTEMASK;
            let mode_byte = (sig_bytes[0] >> 5) & 0x07;
            let mode = if mode_byte == 0 {
                LinkMode::Aes128Cbc
            } else {
                LinkMode::Aes256Cbc
            };
            (mtu, mode)
        } else {
            (DEFAULT_LINK_MTU, LinkMode::default())
        };

        let link_id = LinkId::from(packet);
        log::debug!("link: create from request {} (mtu={}, mode={:?})", link_id, mtu, mode);

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
            initiator: false,
            remote_identity: None,
            mode,
            mtu,
        };

        link.handshake(peer_identity);

        Ok(link)
    }

    pub fn request(&mut self) -> Packet {
        // Link request data format (matching Python):
        // - pub_bytes: 32 bytes (X25519 public key)
        // - sig_pub_bytes: 32 bytes (Ed25519 verifying key)
        // - signalling_bytes: 3 bytes (MTU + mode)
        // Total: 67 bytes
        let mut packet_data = PacketDataBuffer::new();

        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());
        packet_data.safe_write(&signalling_bytes(self.mtu, self.mode));

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

        // Link proof data format (matching Python):
        // signed_data = link_id + pub_bytes + sig_pub_bytes + signalling_bytes
        // proof_data = signature + pub_bytes + signalling_bytes
        // Total: 64 (signature) + 32 (pub_key) + 3 (signalling) = 99 bytes
        let sig_bytes = signalling_bytes(self.mtu, self.mode);

        // Build data to sign
        let mut signed_data = PacketDataBuffer::new();
        signed_data.safe_write(self.id.as_slice());
        signed_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        signed_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());
        signed_data.safe_write(&sig_bytes);

        let signature = self.priv_identity.sign(signed_data.as_slice());

        // Build proof output
        let mut packet_data = PacketDataBuffer::new();
        packet_data.safe_write(&signature.to_bytes()[..]);
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(&sig_bytes);

        Packet {
            header: Header {
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::LinkRequestProof,
            data: packet_data,
        }
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
                if !packet.data.is_empty() && packet.data.as_slice()[0] == 0xFF {
                    self.request_time = Instant::now();
                    log::trace!("link({}): keep-alive request", self.id);
                    return LinkHandleResult::KeepAlive;
                }
                if !packet.data.is_empty() && packet.data.as_slice()[0] == 0xFE {
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
                // Resource data packets are NOT encrypted at the link level.
                // The resource handles its own encryption at the data stream level.
                // We pass the data through as-is (already resource-encrypted).
                log::trace!("link({}): resource data {}B (passthrough)", self.id, packet.data.len());
                self.request_time = Instant::now();
                self.post_event(LinkEvent::ResourceData(LinkPayload::new_from_slice(packet.data.as_slice())));
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
                // Resource proof packets are NOT encrypted at the link level.
                // We pass the data through as-is.
                log::trace!("link({}): resource proof {}B (passthrough)", self.id, packet.data.len());
                self.request_time = Instant::now();
                self.post_event(LinkEvent::ResourceProof(LinkPayload::new_from_slice(packet.data.as_slice())));
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
            PacketContext::Channel => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): channel data {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::Channel(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt channel data", self.id);
                }
            }
            PacketContext::Request => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): request {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::Request(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt request", self.id);
                }
            }
            PacketContext::Response => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): response {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::Response(LinkPayload::new_from_slice(plain_text)));
                } else {
                    log::error!("link({}): can't decrypt response", self.id);
                }
            }
            PacketContext::LinkIdentify => {
                // Link identification proof from the remote initiator.
                // Only the server (non-initiator) should receive this.
                if self.initiator {
                    log::warn!("link({}): received LinkIdentify but we are the initiator", self.id);
                    return LinkHandleResult::None;
                }

                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    // Proof format: [public_key (32 bytes) | verifying_key (32 bytes) | signature (64 bytes)]
                    const EXPECTED_LEN: usize = PUBLIC_KEY_LENGTH * 2 + SIGNATURE_LENGTH;
                    if plain_text.len() < EXPECTED_LEN {
                        log::warn!("link({}): LinkIdentify packet too short: {} bytes", self.id, plain_text.len());
                        return LinkHandleResult::None;
                    }

                    let public_key = &plain_text[..PUBLIC_KEY_LENGTH];
                    let verifying_key = &plain_text[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2];
                    let signature_bytes = &plain_text[PUBLIC_KEY_LENGTH * 2..PUBLIC_KEY_LENGTH * 2 + SIGNATURE_LENGTH];

                    // Reconstruct the identity from the provided keys
                    let identity = Identity::new_from_slices(public_key, verifying_key);

                    // Verify the signature: signed_data = link_id + public_key + verifying_key
                    let mut signed_data = Vec::with_capacity(ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH * 2);
                    signed_data.extend_from_slice(self.id.as_slice());
                    signed_data.extend_from_slice(public_key);
                    signed_data.extend_from_slice(verifying_key);

                    let signature = match Signature::from_slice(signature_bytes) {
                        Ok(s) => s,
                        Err(_) => {
                            log::warn!("link({}): LinkIdentify invalid signature format", self.id);
                            return LinkHandleResult::None;
                        }
                    };

                    if identity.verify(&signed_data, &signature).is_ok() {
                        log::info!("link({}): remote peer identified as {}", self.id, identity.address_hash);
                        self.remote_identity = Some(identity);
                        self.request_time = Instant::now();
                        self.post_event(LinkEvent::Identified(identity));
                    } else {
                        log::warn!("link({}): LinkIdentify signature verification failed", self.id);
                    }
                } else {
                    log::error!("link({}): can't decrypt LinkIdentify packet", self.id);
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
                } else if self.status == LinkStatus::Active
                    && packet.context == PacketContext::ResourceProof
                {
                    // Resource proof packets are not encrypted - pass through as-is
                    log::trace!(
                        "link({}): resource proof {}B (passthrough)",
                        self.id,
                        packet.data.len()
                    );
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::ResourceProof(LinkPayload::new_from_slice(
                        packet.data.as_slice(),
                    )));
                }
            }
            _ => {}
        }

        LinkHandleResult::None
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

    /// Create a channel data packet for sending Channel messages over the link.
    /// Channel messages provide reliable, sequenced message delivery.
    pub fn channel_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            log::warn!("link: can't create channel packet for inactive link");
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
            context: PacketContext::Channel,
            data: packet_data,
        })
    }

    /// Create a request packet for sending requests to the remote destination.
    /// Request data should be msgpack-encoded: [timestamp, path_hash, request_data]
    pub fn request_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            log::warn!("link: can't create request packet for inactive link");
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
            context: PacketContext::Request,
            data: packet_data,
        })
    }

    /// Create a response packet for sending responses back to the requester.
    /// Response data should be msgpack-encoded: [request_id, response_data]
    pub fn response_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            log::warn!("link: can't create response packet for inactive link");
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
            context: PacketContext::Response,
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
            .derive_key(&self.peer_identity.public_key, Some(self.id.as_slice()));
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

    /// Whether this link was initiated by us (client) or received from remote (server).
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Get the remote peer's identity, if they have identified themselves.
    /// This is set when the remote link initiator calls identify() and the
    /// proof is validated.
    pub fn remote_identity(&self) -> Option<&Identity> {
        self.remote_identity.as_ref()
    }

    /// Get the truncated hash of the remote identity (16 bytes), if identified.
    /// This is commonly used for ACL checks.
    pub fn remote_identity_hash(&self) -> Option<[u8; 16]> {
        self.remote_identity.as_ref().map(|id| {
            let mut hash = [0u8; 16];
            hash.copy_from_slice(&id.address_hash.as_slice()[..16]);
            hash
        })
    }

    /// Identify ourselves to the remote destination over this link.
    ///
    /// This sends an identity proof packet that allows the remote side to
    /// verify who we are. This is used for access control on remote services.
    ///
    /// # Arguments
    /// * `identity` - The identity to identify as (must be a PrivateIdentity to sign)
    ///
    /// # Returns
    /// A packet to send, or an error if the link is not active or we are not the initiator.
    ///
    pub fn identify(&self, identity: &PrivateIdentity) -> Result<Packet, RnsError> {
        // Only the initiator (client) can identify
        if !self.initiator {
            log::warn!("link({}): cannot identify, we are not the initiator", self.id);
            return Err(RnsError::InvalidArgument);
        }

        if self.status != LinkStatus::Active {
            log::warn!("link({}): cannot identify on inactive link", self.id);
            return Err(RnsError::InvalidArgument);
        }

        // Create the signed data: link_id + public_key + verifying_key
        let pub_identity = identity.as_identity();
        let public_key = pub_identity.public_key.as_bytes();
        let verifying_key = pub_identity.verifying_key.as_bytes();

        let mut signed_data = Vec::with_capacity(ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH * 2);
        signed_data.extend_from_slice(self.id.as_slice());
        signed_data.extend_from_slice(public_key);
        signed_data.extend_from_slice(verifying_key);

        // Sign the data
        let signature = identity.sign(&signed_data);

        // Create proof data: public_key + verifying_key + signature
        let mut proof_data = Vec::with_capacity(PUBLIC_KEY_LENGTH * 2 + SIGNATURE_LENGTH);
        proof_data.extend_from_slice(public_key);
        proof_data.extend_from_slice(verifying_key);
        proof_data.extend_from_slice(&signature.to_bytes());

        // Encrypt and create the packet
        let mut packet_data = PacketDataBuffer::new();
        let cipher_text_len = {
            let cipher_text = self.encrypt(&proof_data, packet_data.accuire_buf_max())?;
            cipher_text.len()
        };
        packet_data.resize(cipher_text_len);

        log::debug!("link({}): identifying as {}", self.id, pub_identity.address_hash);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::LinkIdentify,
            data: packet_data,
        })
    }

    /// Get the maximum data unit size for this link.
    /// This is the maximum payload size that can be sent in a single packet.
    pub fn mdu(&self) -> usize {
        // Link MDU is determined by the underlying transport
        // For now, use the standard PACKET_MDU minus encryption overhead
        // AES-256-CBC: 16-byte IV + padding (up to 16 bytes) + HMAC (32 bytes)
        // Total overhead is approximately 64 bytes max
        PACKET_MDU.saturating_sub(64)
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
            hex::encode(resource_id)
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
            hex::encode(resource_id)
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
    /// Note: Resource data packets are NOT encrypted at the link level.
    /// The resource handles its own encryption internally.
    /// This matches Python's Packet.py line 201-204.
    pub fn resource_data_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active {
            log::warn!("link: cannot create resource data packet on inactive link");
            return Err(RnsError::InvalidArgument);
        }

        // Resource packets are NOT encrypted at link level - pass through as-is
        let mut packet_data = PacketDataBuffer::new();
        if data.len() > packet_data.accuire_buf_max().len() {
            return Err(RnsError::InvalidArgument);
        }
        packet_data.accuire_buf_max()[..data.len()].copy_from_slice(data);
        packet_data.resize(data.len());

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for LinkPayload buffer wrapper.
    mod link_payload {
        use super::*;

        #[test]
        fn test_new_creates_empty_payload() {
            let payload = LinkPayload::new();
            assert_eq!(payload.len(), 0);
            assert!(payload.is_empty());
        }

        #[test]
        fn test_default_creates_empty_payload() {
            let payload = LinkPayload::default();
            assert_eq!(payload.len(), 0);
            assert!(payload.is_empty());
        }

        #[test]
        fn test_new_from_slice_copies_data() {
            let data = [1u8, 2, 3, 4, 5];
            let payload = LinkPayload::new_from_slice(&data);
            assert_eq!(payload.len(), 5);
            assert!(!payload.is_empty());
            assert_eq!(payload.as_slice(), &data);
        }

        #[test]
        fn test_new_from_slice_empty() {
            let payload = LinkPayload::new_from_slice(&[]);
            assert_eq!(payload.len(), 0);
            assert!(payload.is_empty());
        }

        #[test]
        fn test_new_from_slice_truncates_overflow() {
            // Create data larger than PACKET_MDU
            let data = vec![0xABu8; PACKET_MDU + 100];
            let payload = LinkPayload::new_from_slice(&data);
            // Should truncate to PACKET_MDU
            assert_eq!(payload.len(), PACKET_MDU);
            assert_eq!(payload.as_slice().len(), PACKET_MDU);
        }

        #[test]
        fn test_new_from_vec_copies_data() {
            let data = vec![10u8, 20, 30, 40];
            let payload = LinkPayload::new_from_vec(&data);
            assert_eq!(payload.len(), 4);
            assert_eq!(payload.as_slice(), &[10, 20, 30, 40]);
        }

        #[test]
        fn test_new_from_vec_max_size() {
            let data = vec![0x42u8; PACKET_MDU];
            let payload = LinkPayload::new_from_vec(&data);
            assert_eq!(payload.len(), PACKET_MDU);
        }

        #[test]
        fn test_as_slice_returns_correct_portion() {
            let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
            let payload = LinkPayload::new_from_slice(&data);
            let slice = payload.as_slice();
            assert_eq!(slice.len(), 8);
            assert_eq!(slice, &data);
        }

        #[test]
        fn test_clone() {
            let data = [1u8, 2, 3];
            let payload1 = LinkPayload::new_from_slice(&data);
            let payload2 = payload1.clone();
            assert_eq!(payload1.as_slice(), payload2.as_slice());
        }
    }

    /// Tests for LinkStatus enum.
    mod link_status {
        use super::*;

        #[test]
        fn test_status_values() {
            assert_eq!(LinkStatus::Pending as u8, 0x00);
            assert_eq!(LinkStatus::Handshake as u8, 0x01);
            assert_eq!(LinkStatus::Active as u8, 0x02);
            assert_eq!(LinkStatus::Stale as u8, 0x03);
            assert_eq!(LinkStatus::Closed as u8, 0x04);
        }

        #[test]
        fn test_not_yet_active_pending() {
            assert!(LinkStatus::Pending.not_yet_active());
        }

        #[test]
        fn test_not_yet_active_handshake() {
            assert!(LinkStatus::Handshake.not_yet_active());
        }

        #[test]
        fn test_not_yet_active_active() {
            assert!(!LinkStatus::Active.not_yet_active());
        }

        #[test]
        fn test_not_yet_active_stale() {
            assert!(!LinkStatus::Stale.not_yet_active());
        }

        #[test]
        fn test_not_yet_active_closed() {
            assert!(!LinkStatus::Closed.not_yet_active());
        }

        #[test]
        fn test_status_equality() {
            assert_eq!(LinkStatus::Active, LinkStatus::Active);
            assert_ne!(LinkStatus::Active, LinkStatus::Pending);
        }

        #[test]
        fn test_status_clone_copy() {
            let status = LinkStatus::Active;
            let cloned = status.clone();
            let copied = status;
            assert_eq!(status, cloned);
            assert_eq!(status, copied);
        }
    }

    /// Tests for LinkId derivation from Packet.
    mod link_id {
        use super::*;

        #[test]
        fn test_link_id_from_packet_deterministic() {
            let mut packet = Packet::default();
            packet.data.safe_write(&[0u8; PUBLIC_KEY_LENGTH * 2]);

            let id1 = LinkId::from(&packet);
            let id2 = LinkId::from(&packet);
            assert_eq!(id1, id2);
        }

        #[test]
        fn test_link_id_from_different_packets_differ() {
            let mut packet1 = Packet::default();
            packet1.data.safe_write(&[1u8; PUBLIC_KEY_LENGTH * 2]);

            let mut packet2 = Packet::default();
            packet2.data.safe_write(&[2u8; PUBLIC_KEY_LENGTH * 2]);

            let id1 = LinkId::from(&packet1);
            let id2 = LinkId::from(&packet2);
            assert_ne!(id1, id2);
        }

        #[test]
        fn test_link_id_uses_truncated_data() {
            // Link ID only uses first PUBLIC_KEY_LENGTH * 2 bytes of data
            let mut packet1 = Packet::default();
            let mut data1 = [0u8; PUBLIC_KEY_LENGTH * 2 + 100];
            data1[..PUBLIC_KEY_LENGTH * 2].fill(0xAA);
            data1[PUBLIC_KEY_LENGTH * 2..].fill(0xBB);
            packet1.data.safe_write(&data1);

            let mut packet2 = Packet::default();
            let mut data2 = [0u8; PUBLIC_KEY_LENGTH * 2 + 100];
            data2[..PUBLIC_KEY_LENGTH * 2].fill(0xAA);
            data2[PUBLIC_KEY_LENGTH * 2..].fill(0xCC); // Different trailing bytes
            packet2.data.safe_write(&data2);

            let id1 = LinkId::from(&packet1);
            let id2 = LinkId::from(&packet2);
            // IDs should be the same because trailing bytes are ignored
            assert_eq!(id1, id2);
        }

        #[test]
        fn test_link_id_affected_by_destination() {
            let mut packet1 = Packet::default();
            packet1.destination = AddressHash::new([0u8; 16]);
            packet1.data.safe_write(&[0u8; PUBLIC_KEY_LENGTH * 2]);

            let mut packet2 = Packet::default();
            packet2.destination = AddressHash::new([1u8; 16]);
            packet2.data.safe_write(&[0u8; PUBLIC_KEY_LENGTH * 2]);

            let id1 = LinkId::from(&packet1);
            let id2 = LinkId::from(&packet2);
            assert_ne!(id1, id2);
        }

        #[test]
        fn test_link_id_affected_by_context() {
            let mut packet1 = Packet::default();
            packet1.context = PacketContext::None;
            packet1.data.safe_write(&[0u8; PUBLIC_KEY_LENGTH * 2]);

            let mut packet2 = Packet::default();
            packet2.context = PacketContext::Resource;
            packet2.data.safe_write(&[0u8; PUBLIC_KEY_LENGTH * 2]);

            let id1 = LinkId::from(&packet1);
            let id2 = LinkId::from(&packet2);
            assert_ne!(id1, id2);
        }
    }

    /// Tests for LinkEvent variants.
    mod link_event {
        use super::*;

        #[test]
        fn test_event_data_payload() {
            let payload = LinkPayload::new_from_slice(&[1, 2, 3]);
            let event = LinkEvent::Data(payload.clone());
            if let LinkEvent::Data(p) = event {
                assert_eq!(p.as_slice(), &[1, 2, 3]);
            } else {
                panic!("Expected Data event");
            }
        }

        #[test]
        fn test_event_channel_payload() {
            let payload = LinkPayload::new_from_slice(&[4, 5, 6]);
            let event = LinkEvent::Channel(payload.clone());
            if let LinkEvent::Channel(p) = event {
                assert_eq!(p.as_slice(), &[4, 5, 6]);
            } else {
                panic!("Expected Channel event");
            }
        }

        #[test]
        fn test_event_clone() {
            let event1 = LinkEvent::Activated;
            let event2 = event1.clone();
            if let (LinkEvent::Activated, LinkEvent::Activated) = (&event1, &event2) {
                // Both are Activated
            } else {
                panic!("Clone failed");
            }
        }
    }

    /// Tests for Link lifecycle and basic operations.
    mod link_lifecycle {
        use super::*;
        use crate::destination::DestinationName;

        pub(super) fn create_test_destination() -> DestinationDesc {
            let priv_identity = PrivateIdentity::new_from_rand(OsRng);
            let identity = *priv_identity.as_identity();
            DestinationDesc {
                address_hash: identity.address_hash,
                identity,
                name: DestinationName::new("test", "link"),
            }
        }

        #[test]
        fn test_link_new_initial_state() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest.clone(), tx);

            assert_eq!(link.status(), LinkStatus::Pending);
            assert!(link.is_initiator());
            assert!(link.id().as_slice().iter().all(|&b| b == 0)); // Empty ID initially
            assert_eq!(link.outgoing_resource_count(), 0);
            assert_eq!(link.incoming_resource_count(), 0);
        }

        #[test]
        fn test_link_request_creates_packet() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest.clone(), tx);

            let packet = link.request();

            assert_eq!(packet.header.packet_type, PacketType::LinkRequest);
            assert_eq!(packet.destination, dest.address_hash);
            assert_eq!(packet.context, PacketContext::None);
            // Data should contain public key + verifying key + signalling bytes (64 + 3 = 67 bytes)
            assert_eq!(packet.data.len(), PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE);
        }

        #[test]
        fn test_link_request_sets_id() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest.clone(), tx);

            // ID is empty before request
            assert!(link.id().as_slice().iter().all(|&b| b == 0));

            let packet = link.request();
            let expected_id = LinkId::from(&packet);

            // ID should be set after request
            assert_eq!(*link.id(), expected_id);
        }

        #[test]
        fn test_link_close_sets_status() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            link.close();

            assert_eq!(link.status(), LinkStatus::Closed);
        }

        #[test]
        fn test_link_restart_sets_pending() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            link.close();
            assert_eq!(link.status(), LinkStatus::Closed);

            link.restart();
            assert_eq!(link.status(), LinkStatus::Pending);
        }

        #[test]
        fn test_link_mdu() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            let mdu = link.mdu();
            // MDU should be PACKET_MDU minus encryption overhead (~64 bytes)
            assert!(mdu > 0);
            assert!(mdu < PACKET_MDU);
            assert_eq!(mdu, PACKET_MDU - 64);
        }

        #[test]
        fn test_link_ready_for_new_resource_inactive() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            // Link is not active, should not be ready
            assert!(!link.ready_for_new_resource());
        }

        #[test]
        fn test_link_keep_alive_packet() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            let packet = link.keep_alive_packet(0xFF);

            assert_eq!(packet.header.packet_type, PacketType::Data);
            assert_eq!(packet.header.destination_type, DestinationType::Link);
            assert_eq!(packet.context, PacketContext::KeepAlive);
            assert_eq!(packet.data.len(), 1);
            assert_eq!(packet.data.as_slice()[0], 0xFF);
        }

        #[test]
        fn test_link_elapsed() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            let elapsed = link.elapsed();
            // Should be very small (just created)
            assert!(elapsed.as_secs() < 1);
        }

        #[test]
        fn test_link_rtt_initial() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            assert_eq!(link.rtt(), Duration::from_secs(0));
        }

        #[test]
        fn test_link_destination() {
            let dest = create_test_destination();
            let expected_hash = dest.address_hash;
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            assert_eq!(link.destination().address_hash, expected_hash);
        }

        #[test]
        fn test_link_remote_identity_initial() {
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            assert!(link.remote_identity().is_none());
            assert!(link.remote_identity_hash().is_none());
        }
    }

    /// Tests for Link handle result.
    mod link_handle_result {
        use super::*;

        #[test]
        fn test_handle_result_variants_exist() {
            // Just verify the enum variants exist
            let _none = LinkHandleResult::None;
            let _activated = LinkHandleResult::Activated;
            let _keepalive = LinkHandleResult::KeepAlive;
        }
    }

    /// Tests for resource management constants.
    mod resource_management {
        use super::*;

        #[test]
        fn test_max_outgoing_resources_constant() {
            assert_eq!(MAX_OUTGOING_RESOURCES, 16);
        }

        #[test]
        fn test_link_resource_counts_initial() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            assert_eq!(link.outgoing_resource_count(), 0);
            assert_eq!(link.incoming_resource_count(), 0);
        }

        #[test]
        fn test_link_has_no_resources_initially() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            let resource_id: ResourceId = [0u8; 16];
            assert!(!link.has_outgoing_resource(&resource_id));
            assert!(!link.has_incoming_resource(&resource_id));
        }

        #[test]
        fn test_link_get_nonexistent_resource() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            let resource_id: ResourceId = [0u8; 16];
            assert!(link.get_outgoing_resource(&resource_id).is_none());
            assert!(link.get_incoming_resource(&resource_id).is_none());
        }

        #[test]
        fn test_link_get_last_resource_window() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            // Initial window should be the default
            let window = link.get_last_resource_window();
            assert!(window > 0);
        }

        #[test]
        fn test_link_get_last_resource_eifr_initial() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            assert!(link.get_last_resource_eifr().is_none());
        }
    }
}
