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
    destination::request_receipt::SharedRequestReceipt,
    error::RnsError,
    hash::{AddressHash, Hash, ADDRESS_HASH_SIZE},
    identity::{DecryptIdentity, DerivedKey, EncryptIdentity, Identity, PrivateIdentity},
    packet::{
        DestinationType, Header, Packet, PacketContext, PacketDataBuffer, PacketType, PACKET_MDU,
        RETICULUM_MTU,
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

/// Resource acceptance strategy for incoming resources on a link.
///
/// Matches Python's Link.ACCEPT_NONE / ACCEPT_APP / ACCEPT_ALL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResourceStrategy {
    /// Reject all incoming resources
    AcceptNone = 0x00,
    /// Accept resources based on application callback
    AcceptApp = 0x01,
    /// Accept all incoming resources
    AcceptAll = 0x02,
}

impl Default for ResourceStrategy {
    fn default() -> Self {
        ResourceStrategy::AcceptNone
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

/// Reason a link was torn down (matching Python Link.py teardown reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkTeardownReason {
    /// Link timed out (keepalive failure)
    Timeout = 0x01,
    /// Link was closed by the initiator (client)
    InitiatorClosed = 0x02,
    /// Link was closed by the destination (server)
    DestinationClosed = 0x03,
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
    /// A data packet (context NONE) was successfully decrypted and delivered
    DataReceived,
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

// Keepalive constants (matching Python Link.py)
/// Maximum keepalive interval
pub const KEEPALIVE_MAX: Duration = Duration::from_secs(360);
/// Minimum keepalive interval
pub const KEEPALIVE_MIN: Duration = Duration::from_secs(5);
/// RTT threshold for maximum keepalive
pub const KEEPALIVE_MAX_RTT: f64 = 1.75;
/// Factor to multiply keepalive by to get stale time
pub const STALE_FACTOR: u32 = 2;
/// Grace period after stale before teardown
pub const STALE_GRACE: Duration = Duration::from_secs(5);
/// Timeout factor for keepalive-based timeout
pub const KEEPALIVE_TIMEOUT_FACTOR: u32 = 4;
/// Default request timeout
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
    // Timing fields for keepalive and activity tracking
    /// Last time we received data on this link
    last_inbound: Option<Instant>,
    /// Last time we sent data on this link
    last_outbound: Option<Instant>,
    /// Last keepalive packet sent/received
    last_keepalive: Option<Instant>,
    /// Last actual data (non-keepalive) activity
    last_data: Option<Instant>,
    /// When the link became active (handshake completed)
    activated_at: Option<Instant>,
    /// Calculated keepalive interval based on RTT
    keepalive_interval: Duration,
    /// Time after which link is considered stale
    stale_time: Duration,
    /// Pending requests awaiting response
    pending_requests: HashMap<[u8; 16], SharedRequestReceipt>,
    /// Resource acceptance strategy for incoming resources
    resource_strategy: ResourceStrategy,
    /// Application callback for AcceptApp strategy
    resource_accept_callback: Option<Arc<dyn Fn(&ResourceAdvertisement) -> bool + Send + Sync>>,
    /// Teardown reason when link is closed
    teardown_reason: Option<LinkTeardownReason>,
    // Physical layer stats
    /// Received signal strength indicator (dBm)
    rssi: Option<i16>,
    /// Signal-to-noise ratio (dB)
    snr: Option<f32>,
    /// Link quality metric (0.0–1.0)
    q: Option<f32>,
    /// Whether to track physical layer statistics
    track_phy_stats: bool,
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
            last_inbound: None,
            last_outbound: None,
            last_keepalive: None,
            last_data: None,
            activated_at: None,
            keepalive_interval: KEEPALIVE_MAX,
            stale_time: KEEPALIVE_MAX * STALE_FACTOR,
            pending_requests: HashMap::new(),
            resource_strategy: ResourceStrategy::default(),
            resource_accept_callback: None,
            teardown_reason: None,
            rssi: None,
            snr: None,
            q: None,
            track_phy_stats: false,
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
        let (mut mtu, mode) = if packet.data.len() >= PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE {
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

        // Clamp MTU to Reticulum's standard MTU to match Rust packet buffer limits.
        if mtu > RETICULUM_MTU as u32 {
            mtu = RETICULUM_MTU as u32;
        }

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
            last_inbound: Some(Instant::now()),
            last_outbound: None,
            last_keepalive: None,
            last_data: None,
            activated_at: None,
            keepalive_interval: KEEPALIVE_MAX,
            stale_time: KEEPALIVE_MAX * STALE_FACTOR,
            pending_requests: HashMap::new(),
            resource_strategy: ResourceStrategy::default(),
            resource_accept_callback: None,
            teardown_reason: None,
            rssi: None,
            snr: None,
            q: None,
            track_phy_stats: false,
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
            ratchet_id: None,
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
            ratchet_id: None,
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
                    return LinkHandleResult::DataReceived;
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
                    // Try to resolve a pending request receipt with the response
                    self.handle_response(plain_text);
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
            PacketContext::LinkClose => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    // Verify decrypted content matches our link ID
                    if plain_text == self.id.as_slice() {
                        log::info!("link({}): received LINKCLOSE from remote", self.id);
                        self.teardown_reason = Some(if self.initiator {
                            LinkTeardownReason::DestinationClosed
                        } else {
                            LinkTeardownReason::InitiatorClosed
                        });
                        self.status = LinkStatus::Closed;
                        self.post_event(LinkEvent::Closed);
                    } else {
                        log::warn!("link({}): LINKCLOSE link ID mismatch", self.id);
                    }
                } else {
                    log::error!("link({}): can't decrypt LINKCLOSE packet", self.id);
                }
            }
            _ => {
                log::trace!("link({}): unhandled packet context {:?}", self.id, packet.context);
            }
        }

        LinkHandleResult::None
    }

    /// Create a proof packet for a received link data packet.
    ///
    /// Proof format: packet_hash + signature (explicit proof), not encrypted.
    pub fn proof_packet(&self, packet: &Packet) -> Packet {
        let hash = packet.hash();
        let signature = self.priv_identity.sign(hash.as_slice());

        let mut packet_data = PacketDataBuffer::new();
        packet_data.safe_write(hash.as_slice());
        packet_data.safe_write(&signature.to_bytes());

        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
            ratchet_id: None,
        }
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
            ratchet_id: None,
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
            ratchet_id: None,
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
            ratchet_id: None,
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
            ratchet_id: None,
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
            ratchet_id: None,
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
            ratchet_id: None,
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
    /// Close the link and optionally return a LINKCLOSE packet to send.
    ///
    /// If the link is active, creates a LINKCLOSE packet containing the
    /// encrypted link ID so the remote side can verify the teardown.
    /// Returns None if the link is already pending/closed (no packet needed).
    pub fn close(&mut self) -> Option<Packet> {
        // If already pending or closed, just set status
        if self.status == LinkStatus::Pending || self.status == LinkStatus::Closed {
            self.status = LinkStatus::Closed;
            self.post_event(LinkEvent::Closed);
            log::warn!("link: close {} (already {:?})", self.id, self.status);
            return None;
        }

        // Set teardown reason based on who initiated
        self.teardown_reason = Some(if self.initiator {
            LinkTeardownReason::InitiatorClosed
        } else {
            LinkTeardownReason::DestinationClosed
        });

        // Build LINKCLOSE packet: encrypt(link_id)
        let linkclose_packet = {
            let mut packet_data = PacketDataBuffer::new();
            let cipher_text_len = match self.encrypt(self.id.as_slice(), packet_data.accuire_buf_max()) {
                Ok(ct) => ct.len(),
                Err(e) => {
                    log::error!("link({}): failed to encrypt LINKCLOSE: {}", self.id, e);
                    self.status = LinkStatus::Closed;
                    self.post_event(LinkEvent::Closed);
                    return None;
                }
            };
            packet_data.resize(cipher_text_len);

            Packet {
                header: Header {
                    destination_type: DestinationType::Link,
                    packet_type: PacketType::Data,
                    ..Default::default()
                },
                ifac: None,
                destination: self.id,
                transport: None,
                context: PacketContext::LinkClose,
                data: packet_data,
                ratchet_id: None,
            }
        };

        self.status = LinkStatus::Closed;
        self.post_event(LinkEvent::Closed);
        log::warn!("link: close {}", self.id);

        Some(linkclose_packet)
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

    /// Get the peer identity used for link proof verification.
    pub fn peer_identity(&self) -> &Identity {
        &self.peer_identity
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
            ratchet_id: None,
        })
    }

    /// Get the maximum data unit size for this link.
    /// This is the maximum plaintext payload size that can be sent in a single packet.
    pub fn mdu(&self) -> usize {
        // Match Python Link.update_mdu():
        // mdu = floor((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD)/AES_BLOCKSIZE)*AES_BLOCKSIZE - 1
        use crate::packet::{AES_BLOCK_SIZE, HEADER_MIN_SIZE, IFAC_MIN_SIZE, TOKEN_OVERHEAD};

        let mtu = self.mtu as isize;
        let base = mtu - (IFAC_MIN_SIZE as isize) - (HEADER_MIN_SIZE as isize) - (TOKEN_OVERHEAD as isize);
        if base <= 0 {
            return 0;
        }

        let blocks = (base as usize) / AES_BLOCK_SIZE;
        blocks.saturating_mul(AES_BLOCK_SIZE).saturating_sub(1)
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
            ratchet_id: None,
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
            ratchet_id: None,
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
            ratchet_id: None,
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
            ratchet_id: None,
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
            ratchet_id: None,
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
            ratchet_id: None,
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
            ratchet_id: None,
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

    // ========== Timing and Keepalive Methods ==========

    /// Get the last time we received data on this link.
    pub fn last_inbound(&self) -> Option<Instant> {
        self.last_inbound
    }

    /// Get the last time we sent data on this link.
    pub fn last_outbound(&self) -> Option<Instant> {
        self.last_outbound
    }

    /// Get the last keepalive time.
    pub fn last_keepalive(&self) -> Option<Instant> {
        self.last_keepalive
    }

    /// Get the last data activity time.
    pub fn last_data(&self) -> Option<Instant> {
        self.last_data
    }

    /// Get when the link was activated.
    pub fn activated_at(&self) -> Option<Instant> {
        self.activated_at
    }

    /// Get the current keepalive interval.
    pub fn keepalive_interval(&self) -> Duration {
        self.keepalive_interval
    }

    /// Get the stale time threshold.
    pub fn stale_time(&self) -> Duration {
        self.stale_time
    }

    /// Update timing fields when data is received.
    pub(crate) fn record_inbound(&mut self) {
        let now = Instant::now();
        self.last_inbound = Some(now);
        self.last_data = Some(now);
    }

    /// Update timing fields when data is sent.
    pub(crate) fn record_outbound(&mut self) {
        let now = Instant::now();
        self.last_outbound = Some(now);
        self.last_data = Some(now);
    }

    /// Record keepalive activity.
    pub(crate) fn record_keepalive(&mut self) {
        self.last_keepalive = Some(Instant::now());
    }

    /// Mark link as activated.
    pub(crate) fn mark_activated(&mut self) {
        self.activated_at = Some(Instant::now());
        self.update_keepalive_from_rtt();
    }

    /// Update keepalive interval based on current RTT.
    ///
    /// Formula matches Python's Link._update_keepalive():
    /// keepalive = clamp(rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MIN, KEEPALIVE_MAX)
    pub(crate) fn update_keepalive_from_rtt(&mut self) {
        let rtt_secs = self.rtt.as_secs_f64();
        let keepalive_secs = (rtt_secs * (KEEPALIVE_MAX.as_secs_f64() / KEEPALIVE_MAX_RTT))
            .clamp(KEEPALIVE_MIN.as_secs_f64(), KEEPALIVE_MAX.as_secs_f64());
        self.keepalive_interval = Duration::from_secs_f64(keepalive_secs);
        self.stale_time = self.keepalive_interval * STALE_FACTOR;
    }

    /// Check if the link is stale (no activity for stale_time).
    pub fn is_stale(&self) -> bool {
        if let Some(last_data) = self.last_data {
            last_data.elapsed() > self.stale_time
        } else if let Some(activated) = self.activated_at {
            activated.elapsed() > self.stale_time
        } else {
            false
        }
    }

    // ========== Request/Response Methods ==========

    /// Get a pending request by its ID.
    pub fn get_pending_request(&self, request_id: &[u8; 16]) -> Option<SharedRequestReceipt> {
        self.pending_requests.get(request_id).cloned()
    }

    /// Add a pending request.
    pub(crate) fn add_pending_request(&mut self, request_id: [u8; 16], receipt: SharedRequestReceipt) {
        self.pending_requests.insert(request_id, receipt);
    }

    /// Remove a pending request.
    pub(crate) fn remove_pending_request(&mut self, request_id: &[u8; 16]) -> Option<SharedRequestReceipt> {
        self.pending_requests.remove(request_id)
    }

    /// Get all pending requests.
    pub fn pending_requests(&self) -> &HashMap<[u8; 16], SharedRequestReceipt> {
        &self.pending_requests
    }

    /// Send a request to the remote destination over this link.
    ///
    /// Mirrors Python's Link.request() (Link.py:478-527). Packs the request
    /// as a msgpack array `[timestamp, path_hash, data]` and sends it as a
    /// Request packet. Returns a SharedRequestReceipt for tracking the response.
    ///
    /// If the packed request exceeds the link MDU, returns
    /// `Err(RnsError::ResourceRequired)` — the caller should use a Resource
    /// transfer with a request_id instead.
    pub fn send_request(
        &mut self,
        path: &str,
        data: Option<&[u8]>,
        timeout: Option<Duration>,
    ) -> Result<(SharedRequestReceipt, Packet), RnsError> {
        if self.status != LinkStatus::Active {
            return Err(RnsError::InvalidArgument);
        }

        // Compute path_hash: truncated SHA-256 of path string
        let path_hash_full = Hash::new(
            Hash::generator()
                .chain_update(path.as_bytes())
                .finalize()
                .into(),
        );
        let path_hash = &path_hash_full.as_bytes()[..16];

        // Get current timestamp as f64
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        // Pack as msgpack array: [timestamp, path_hash, data]
        let mut packed = Vec::new();
        rmp::encode::write_array_len(&mut packed, 3).map_err(|_| RnsError::SerializationError)?;
        rmp::encode::write_f64(&mut packed, timestamp).map_err(|_| RnsError::SerializationError)?;
        rmp::encode::write_bin(&mut packed, path_hash).map_err(|_| RnsError::SerializationError)?;
        match data {
            Some(d) => rmp::encode::write_bin(&mut packed, d).map_err(|_| RnsError::SerializationError)?,
            None => rmp::encode::write_nil(&mut packed).map_err(|_| RnsError::SerializationError)?,
        }

        // Check if packed data fits within link MDU
        if packed.len() > self.mdu() {
            log::warn!(
                "link({}): request too large for link MDU ({} > {}), use Resource",
                self.id,
                packed.len(),
                self.mdu()
            );
            return Err(RnsError::ResourceRequired);
        }

        // Generate request_id from truncated hash of packed data
        let request_id_hash = Hash::new(
            Hash::generator()
                .chain_update(&packed)
                .finalize()
                .into(),
        );
        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(&request_id_hash.as_bytes()[..16]);

        // Create the request packet
        let packet = self.request_packet(&packed)?;

        // Create receipt and register it
        let request_timeout = timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT);
        let receipt = crate::destination::request_receipt::new_shared_request_receipt(
            request_id,
            request_timeout,
            Some(packed.len()),
        );

        self.pending_requests.insert(request_id, receipt.clone());

        log::debug!(
            "link({}): sent request to path '{}' (id: {})",
            self.id,
            path,
            hex::encode(request_id)
        );

        Ok((receipt, packet))
    }

    /// Handle an incoming response packet by resolving the pending request.
    ///
    /// Parses the decrypted response data as msgpack `[request_id, response_data]`,
    /// looks up the request in pending_requests, and marks it as Ready.
    pub(crate) fn handle_response(&mut self, decrypted_data: &[u8]) {
        // Parse msgpack: [request_id_bytes, response_data]
        let value = match rmpv::decode::read_value(&mut &decrypted_data[..]) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("link({}): failed to parse response msgpack: {}", self.id, e);
                return;
            }
        };

        let arr = match value {
            rmpv::Value::Array(a) if a.len() >= 2 => a,
            _ => {
                log::warn!("link({}): response is not a 2-element array", self.id);
                return;
            }
        };

        // Extract request_id
        let request_id_bytes = match &arr[0] {
            rmpv::Value::Binary(b) if b.len() == 16 => {
                let mut id = [0u8; 16];
                id.copy_from_slice(b);
                id
            }
            _ => {
                log::warn!("link({}): response request_id not a 16-byte binary", self.id);
                return;
            }
        };

        // Extract response data
        let response_data = match &arr[1] {
            rmpv::Value::Binary(b) => b.clone(),
            rmpv::Value::Nil => Vec::new(),
            _ => {
                log::warn!("link({}): response data not binary or nil", self.id);
                return;
            }
        };

        // Look up and resolve the pending request
        if let Some(receipt) = self.pending_requests.remove(&request_id_bytes) {
            let mut receipt = futures::executor::block_on(receipt.lock());
            receipt.set_ready(response_data, None);
            log::debug!(
                "link({}): resolved request {}",
                self.id,
                hex::encode(request_id_bytes)
            );
        } else {
            log::warn!(
                "link({}): no pending request for id {}",
                self.id,
                hex::encode(request_id_bytes)
            );
        }
    }

    // ========== Resource Strategy Methods ==========

    /// Set the resource acceptance strategy for this link.
    pub fn set_resource_strategy(&mut self, strategy: ResourceStrategy) {
        self.resource_strategy = strategy;
    }

    /// Get the current resource acceptance strategy.
    pub fn resource_strategy(&self) -> ResourceStrategy {
        self.resource_strategy
    }

    /// Set the application callback for AcceptApp resource strategy.
    ///
    /// The callback receives a ResourceAdvertisement and returns true to accept
    /// or false to reject the incoming resource.
    pub fn set_resource_accept_callback<F>(&mut self, callback: F)
    where
        F: Fn(&ResourceAdvertisement) -> bool + Send + Sync + 'static,
    {
        self.resource_accept_callback = Some(Arc::new(callback));
    }

    /// Check whether an incoming resource should be accepted based on the
    /// current strategy and optional application callback.
    pub fn should_accept_resource(&self, adv: &ResourceAdvertisement) -> bool {
        match self.resource_strategy {
            ResourceStrategy::AcceptNone => false,
            ResourceStrategy::AcceptAll => true,
            ResourceStrategy::AcceptApp => self
                .resource_accept_callback
                .as_ref()
                .map(|cb| cb(adv))
                .unwrap_or(false),
        }
    }

    // ========== Teardown Methods ==========

    /// Get the teardown reason, if the link has been closed.
    pub fn teardown_reason(&self) -> Option<LinkTeardownReason> {
        self.teardown_reason
    }

    // ========== Physical Layer Stats ==========

    /// Enable or disable physical layer stats tracking.
    pub fn set_track_phy_stats(&mut self, track: bool) {
        self.track_phy_stats = track;
    }

    /// Whether physical layer stats tracking is enabled.
    pub fn track_phy_stats(&self) -> bool {
        self.track_phy_stats
    }

    /// Get the last known RSSI value (dBm).
    pub fn get_rssi(&self) -> Option<i16> {
        self.rssi
    }

    /// Get the last known signal-to-noise ratio (dB).
    pub fn get_snr(&self) -> Option<f32> {
        self.snr
    }

    /// Get the last known link quality metric.
    pub fn get_q(&self) -> Option<f32> {
        self.q
    }

    /// Update physical layer stats from a received packet.
    ///
    /// Called by the transport layer when phy stats are available from the
    /// radio interface (e.g. LoRa RSSI/SNR). Only updates if tracking is enabled.
    pub fn update_phy_stats(&mut self, rssi: Option<i16>, snr: Option<f32>, q: Option<f32>) {
        if self.track_phy_stats {
            self.rssi = rssi;
            self.snr = snr;
            self.q = q;
        }
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
                name: DestinationName::new("test", "link").unwrap(),
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
        fn test_link_close_pending_returns_none() {
            // Closing a pending link should not produce a LINKCLOSE packet
            let dest = create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            let packet = link.close();

            assert_eq!(link.status(), LinkStatus::Closed);
            assert!(packet.is_none(), "pending link should not produce LINKCLOSE");
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
            // MDU should match Python formula:
            // floor((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD)/AES_BLOCKSIZE)*AES_BLOCKSIZE - 1
            use crate::packet::{AES_BLOCK_SIZE, HEADER_MIN_SIZE, IFAC_MIN_SIZE, TOKEN_OVERHEAD};
            let base = (DEFAULT_LINK_MTU as usize)
                .saturating_sub(IFAC_MIN_SIZE + HEADER_MIN_SIZE + TOKEN_OVERHEAD);
            let expected = (base / AES_BLOCK_SIZE)
                .saturating_mul(AES_BLOCK_SIZE)
                .saturating_sub(1);

            assert!(mdu > 0);
            assert!(mdu < PACKET_MDU);
            assert_eq!(mdu, expected);
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

    /// Tests for link timing methods.
    mod link_timing {
        use super::*;
        use std::time::Duration;

        #[test]
        fn test_link_timing_fields_initial() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            // All timing fields should be None initially
            assert!(link.last_inbound().is_none());
            assert!(link.last_outbound().is_none());
            assert!(link.last_keepalive().is_none());
            assert!(link.last_data().is_none());
            assert!(link.activated_at().is_none());
        }

        #[test]
        fn test_link_record_inbound() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            assert!(link.last_inbound().is_none());
            assert!(link.last_data().is_none());

            link.record_inbound();

            assert!(link.last_inbound().is_some());
            assert!(link.last_data().is_some());
            // Should have just been recorded, so elapsed time should be minimal
            assert!(link.last_inbound().unwrap().elapsed() < Duration::from_secs(1));
        }

        #[test]
        fn test_link_record_outbound() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            assert!(link.last_outbound().is_none());
            assert!(link.last_data().is_none());

            link.record_outbound();

            assert!(link.last_outbound().is_some());
            assert!(link.last_data().is_some());
        }

        #[test]
        fn test_link_record_keepalive() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            assert!(link.last_keepalive().is_none());

            link.record_keepalive();

            assert!(link.last_keepalive().is_some());
        }

        #[test]
        fn test_link_mark_activated() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            assert!(link.activated_at().is_none());

            link.mark_activated();

            assert!(link.activated_at().is_some());
            // Keepalive interval should have been calculated
            assert!(link.keepalive_interval() > Duration::ZERO);
        }

        #[test]
        fn test_link_keepalive_interval_defaults() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            // Default keepalive interval should be between min and max
            let interval = link.keepalive_interval();
            assert!(interval >= KEEPALIVE_MIN);
            assert!(interval <= KEEPALIVE_MAX);
        }

        #[test]
        fn test_link_update_keepalive_from_rtt() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            // Set a specific RTT value
            link.rtt = Duration::from_millis(100);
            link.update_keepalive_from_rtt();

            // Keepalive should be clamped between min and max
            assert!(link.keepalive_interval() >= KEEPALIVE_MIN);
            assert!(link.keepalive_interval() <= KEEPALIVE_MAX);

            // Stale time should be a factor of keepalive
            assert_eq!(link.stale_time(), link.keepalive_interval() * STALE_FACTOR);
        }

        #[test]
        fn test_link_is_stale_before_activation() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            // Without any data activity, is_stale should return false
            // (no last_data to compare against)
            assert!(!link.is_stale());
        }

        #[test]
        fn test_link_is_stale_after_recent_activity() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            link.record_inbound();

            // Just had activity, should not be stale
            assert!(!link.is_stale());
        }
    }

    /// Tests for pending request management.
    mod pending_requests {
        use super::*;
        use crate::destination::request_receipt::new_shared_request_receipt;

        #[test]
        fn test_link_pending_requests_initial() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            assert!(link.pending_requests().is_empty());
        }

        #[test]
        fn test_link_add_pending_request() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            let request_id: [u8; 16] = [1u8; 16];
            let receipt = new_shared_request_receipt(request_id, std::time::Duration::from_secs(30), None);

            link.add_pending_request(request_id, receipt);

            assert_eq!(link.pending_requests().len(), 1);
            assert!(link.get_pending_request(&request_id).is_some());
        }

        #[test]
        fn test_link_remove_pending_request() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            let request_id: [u8; 16] = [2u8; 16];
            let receipt = new_shared_request_receipt(request_id, std::time::Duration::from_secs(30), None);

            link.add_pending_request(request_id, receipt);
            assert_eq!(link.pending_requests().len(), 1);

            let removed = link.remove_pending_request(&request_id);
            assert!(removed.is_some());
            assert!(link.pending_requests().is_empty());
        }

        #[test]
        fn test_link_get_nonexistent_pending_request() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let link = Link::new(dest, tx);

            let request_id: [u8; 16] = [99u8; 16];
            assert!(link.get_pending_request(&request_id).is_none());
        }

        #[test]
        fn test_link_multiple_pending_requests() {
            let dest = super::link_lifecycle::create_test_destination();
            let (tx, _rx) = tokio::sync::broadcast::channel(16);
            let mut link = Link::new(dest, tx);

            let id1: [u8; 16] = [1u8; 16];
            let id2: [u8; 16] = [2u8; 16];
            let id3: [u8; 16] = [3u8; 16];

            link.add_pending_request(id1, new_shared_request_receipt(id1, std::time::Duration::from_secs(30), None));
            link.add_pending_request(id2, new_shared_request_receipt(id2, std::time::Duration::from_secs(30), None));
            link.add_pending_request(id3, new_shared_request_receipt(id3, std::time::Duration::from_secs(30), None));

            assert_eq!(link.pending_requests().len(), 3);
            assert!(link.get_pending_request(&id1).is_some());
            assert!(link.get_pending_request(&id2).is_some());
            assert!(link.get_pending_request(&id3).is_some());
        }
    }
}
