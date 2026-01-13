//! Discovery system for interface announcements and proof-of-work validation.
//!
//! This module implements the interface discovery protocol, allowing nodes to
//! announce their presence and capabilities, and validate incoming announcements
//! using proof-of-work.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::error::RnsError;
use crate::hash::AddressHash;
use crate::identity::{Identity, PrivateIdentity};

/// Default announcement interval
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes

/// Minimum announce interval
pub const MIN_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(60); // 1 minute

/// Default proof-of-work difficulty (number of leading zero bits)
pub const DEFAULT_POW_DIFFICULTY: u8 = 16;

/// Maximum cached announcements
pub const MAX_CACHED_ANNOUNCES: usize = 1000;

/// Announcement expiry time
pub const ANNOUNCE_EXPIRY: Duration = Duration::from_secs(3600); // 1 hour

/// Proof of work target calculation
pub const POW_TARGET_BASE: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Interface type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InterfaceType {
    /// Unknown interface type
    Unknown = 0,
    /// TCP client interface
    TcpClient = 1,
    /// TCP server interface
    TcpServer = 2,
    /// UDP interface
    Udp = 3,
    /// Serial interface
    Serial = 4,
    /// KISS TNC interface
    Kiss = 5,
    /// RNode/LoRa interface
    RNode = 6,
    /// AutoInterface (IPv6 multicast)
    Auto = 7,
    /// I2P interface
    I2p = 8,
    /// Local interface
    Local = 9,
    /// Pipe interface
    Pipe = 10,
}

impl From<u8> for InterfaceType {
    fn from(value: u8) -> Self {
        match value {
            1 => InterfaceType::TcpClient,
            2 => InterfaceType::TcpServer,
            3 => InterfaceType::Udp,
            4 => InterfaceType::Serial,
            5 => InterfaceType::Kiss,
            6 => InterfaceType::RNode,
            7 => InterfaceType::Auto,
            8 => InterfaceType::I2p,
            9 => InterfaceType::Local,
            10 => InterfaceType::Pipe,
            _ => InterfaceType::Unknown,
        }
    }
}

/// Metadata for an interface announcement
#[derive(Debug, Clone)]
pub struct InterfaceMetadata {
    /// Name of the interface
    pub name: String,
    /// Interface type
    pub iface_type: InterfaceType,
    /// Location description (optional)
    pub location: Option<String>,
    /// Custom tags (key-value pairs)
    pub tags: HashMap<String, String>,
    /// Bandwidth in bits per second (0 = unknown)
    pub bandwidth: u64,
    /// Whether interface accepts incoming connections
    pub accepts_incoming: bool,
}

impl Default for InterfaceMetadata {
    fn default() -> Self {
        Self {
            name: String::new(),
            iface_type: InterfaceType::Unknown,
            location: None,
            tags: HashMap::new(),
            bandwidth: 0,
            accepts_incoming: false,
        }
    }
}

impl InterfaceMetadata {
    /// Create new metadata with name and type
    pub fn new(name: &str, iface_type: InterfaceType) -> Self {
        Self {
            name: name.to_string(),
            iface_type,
            ..Default::default()
        }
    }

    /// Set location
    pub fn with_location(mut self, location: &str) -> Self {
        self.location = Some(location.to_string());
        self
    }

    /// Set bandwidth
    pub fn with_bandwidth(mut self, bandwidth: u64) -> Self {
        self.bandwidth = bandwidth;
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, key: &str, value: &str) -> Self {
        self.tags.insert(key.to_string(), value.to_string());
        self
    }

    /// Encode metadata to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Version byte
        data.push(0x01);

        // Interface type
        data.push(self.iface_type as u8);

        // Flags byte
        let mut flags = 0u8;
        if self.accepts_incoming {
            flags |= 0x01;
        }
        if self.location.is_some() {
            flags |= 0x02;
        }
        if !self.tags.is_empty() {
            flags |= 0x04;
        }
        data.push(flags);

        // Name (length-prefixed)
        let name_bytes = self.name.as_bytes();
        data.push(name_bytes.len().min(255) as u8);
        data.extend_from_slice(&name_bytes[..name_bytes.len().min(255)]);

        // Bandwidth (8 bytes, big-endian)
        data.extend_from_slice(&self.bandwidth.to_be_bytes());

        // Location if present
        if let Some(ref location) = self.location {
            let loc_bytes = location.as_bytes();
            data.push(loc_bytes.len().min(255) as u8);
            data.extend_from_slice(&loc_bytes[..loc_bytes.len().min(255)]);
        }

        // Tags if present
        if !self.tags.is_empty() {
            data.push(self.tags.len().min(255) as u8);
            for (key, value) in self.tags.iter().take(255) {
                let key_bytes = key.as_bytes();
                let val_bytes = value.as_bytes();
                data.push(key_bytes.len().min(255) as u8);
                data.extend_from_slice(&key_bytes[..key_bytes.len().min(255)]);
                data.push(val_bytes.len().min(255) as u8);
                data.extend_from_slice(&val_bytes[..val_bytes.len().min(255)]);
            }
        }

        data
    }

    /// Decode metadata from bytes
    pub fn decode(data: &[u8]) -> Result<Self, RnsError> {
        if data.len() < 4 {
            return Err(RnsError::InvalidArgument);
        }

        let version = data[0];
        if version != 0x01 {
            return Err(RnsError::InvalidArgument);
        }

        let iface_type = InterfaceType::from(data[1]);
        let flags = data[2];
        let accepts_incoming = (flags & 0x01) != 0;
        let has_location = (flags & 0x02) != 0;
        let has_tags = (flags & 0x04) != 0;

        let name_len = data[3] as usize;
        if data.len() < 4 + name_len {
            return Err(RnsError::InvalidArgument);
        }

        let name = String::from_utf8_lossy(&data[4..4 + name_len]).to_string();
        let mut offset = 4 + name_len;

        // Bandwidth
        if data.len() < offset + 8 {
            return Err(RnsError::InvalidArgument);
        }
        let bandwidth = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // Location
        let location = if has_location && data.len() > offset {
            let loc_len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + loc_len {
                return Err(RnsError::InvalidArgument);
            }
            let loc = String::from_utf8_lossy(&data[offset..offset + loc_len]).to_string();
            offset += loc_len;
            Some(loc)
        } else {
            None
        };

        // Tags
        let mut tags = HashMap::new();
        if has_tags && data.len() > offset {
            let tag_count = data[offset] as usize;
            offset += 1;
            for _ in 0..tag_count {
                if data.len() <= offset {
                    break;
                }
                let key_len = data[offset] as usize;
                offset += 1;
                if data.len() < offset + key_len {
                    break;
                }
                let key = String::from_utf8_lossy(&data[offset..offset + key_len]).to_string();
                offset += key_len;

                if data.len() <= offset {
                    break;
                }
                let val_len = data[offset] as usize;
                offset += 1;
                if data.len() < offset + val_len {
                    break;
                }
                let value = String::from_utf8_lossy(&data[offset..offset + val_len]).to_string();
                offset += val_len;

                tags.insert(key, value);
            }
        }

        Ok(Self {
            name,
            iface_type,
            location,
            tags,
            bandwidth,
            accepts_incoming,
        })
    }
}

/// Interface announcement with proof-of-work
#[derive(Debug, Clone)]
pub struct InterfaceAnnouncement {
    /// Interface address hash
    pub interface_hash: AddressHash,
    /// Identity public key (X25519 for encryption)
    pub public_key: [u8; 32],
    /// Identity verifying key (Ed25519 for signatures)
    pub verifying_key: [u8; 32],
    /// Announcement timestamp
    pub timestamp: u64,
    /// Interface metadata
    pub metadata: InterfaceMetadata,
    /// Proof-of-work nonce
    pub nonce: u64,
    /// Signature over the announcement
    pub signature: [u8; 64],
    /// When this announcement was received/created
    pub received_at: Instant,
}

impl InterfaceAnnouncement {
    /// Create a new announcement
    pub fn new(
        interface_hash: AddressHash,
        identity: &PrivateIdentity,
        metadata: InterfaceMetadata,
        difficulty: u8,
    ) -> Result<Self, RnsError> {
        let public_key: [u8; 32] = *identity.as_identity().public_key_bytes();
        let verifying_key: [u8; 32] = *identity.as_identity().verifying_key_bytes();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Find proof-of-work nonce
        let nonce = Self::find_pow_nonce(&interface_hash, &public_key, &verifying_key, timestamp, &metadata, difficulty)?;

        // Create data to sign
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(interface_hash.as_slice());
        sign_data.extend_from_slice(&public_key);
        sign_data.extend_from_slice(&verifying_key);
        sign_data.extend_from_slice(&timestamp.to_be_bytes());
        sign_data.extend_from_slice(&metadata.encode());
        sign_data.extend_from_slice(&nonce.to_be_bytes());

        // Sign the announcement
        let signature_obj = identity.sign(&sign_data);
        let signature: [u8; 64] = signature_obj.to_bytes();

        Ok(Self {
            interface_hash,
            public_key,
            verifying_key,
            timestamp,
            metadata,
            nonce,
            signature,
            received_at: Instant::now(),
        })
    }

    /// Find a proof-of-work nonce
    fn find_pow_nonce(
        interface_hash: &AddressHash,
        public_key: &[u8; 32],
        verifying_key: &[u8; 32],
        timestamp: u64,
        metadata: &InterfaceMetadata,
        difficulty: u8,
    ) -> Result<u64, RnsError> {
        let target = POW_TARGET_BASE >> difficulty;
        let metadata_bytes = metadata.encode();

        for nonce in 0..u64::MAX {
            let hash = Self::compute_pow_hash(interface_hash, public_key, verifying_key, timestamp, &metadata_bytes, nonce);
            let hash_value = u64::from_be_bytes(hash[..8].try_into().unwrap());

            if hash_value < target {
                return Ok(nonce);
            }

            // Safety limit - don't spin forever
            if nonce > 10_000_000 {
                return Err(RnsError::CryptoError);
            }
        }

        Err(RnsError::CryptoError)
    }

    /// Compute proof-of-work hash
    fn compute_pow_hash(
        interface_hash: &AddressHash,
        public_key: &[u8; 32],
        verifying_key: &[u8; 32],
        timestamp: u64,
        metadata_bytes: &[u8],
        nonce: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(interface_hash.as_slice());
        hasher.update(public_key);
        hasher.update(verifying_key);
        hasher.update(timestamp.to_be_bytes());
        hasher.update(metadata_bytes);
        hasher.update(nonce.to_be_bytes());
        hasher.finalize().into()
    }

    /// Verify the proof-of-work
    pub fn verify_pow(&self, difficulty: u8) -> bool {
        let target = POW_TARGET_BASE >> difficulty;
        let metadata_bytes = self.metadata.encode();
        let hash = Self::compute_pow_hash(
            &self.interface_hash,
            &self.public_key,
            &self.verifying_key,
            self.timestamp,
            &metadata_bytes,
            self.nonce,
        );
        let hash_value = u64::from_be_bytes(hash[..8].try_into().unwrap());
        hash_value < target
    }

    /// Verify the signature
    pub fn verify_signature(&self) -> bool {
        use ed25519_dalek::Signature;

        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(self.interface_hash.as_slice());
        sign_data.extend_from_slice(&self.public_key);
        sign_data.extend_from_slice(&self.verifying_key);
        sign_data.extend_from_slice(&self.timestamp.to_be_bytes());
        sign_data.extend_from_slice(&self.metadata.encode());
        sign_data.extend_from_slice(&self.nonce.to_be_bytes());

        // Create Identity from public_key and verifying_key
        let identity = Identity::new_from_slices(&self.public_key, &self.verifying_key);

        // Create Signature from bytes
        let signature = Signature::from_bytes(&self.signature);

        identity.verify(&sign_data, &signature).is_ok()
    }

    /// Check if announcement has expired
    pub fn is_expired(&self) -> bool {
        self.received_at.elapsed() > ANNOUNCE_EXPIRY
    }

    /// Encode announcement to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(self.interface_hash.as_slice());
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&self.verifying_key);
        data.extend_from_slice(&self.timestamp.to_be_bytes());

        let metadata_bytes = self.metadata.encode();
        data.extend_from_slice(&(metadata_bytes.len() as u16).to_be_bytes());
        data.extend_from_slice(&metadata_bytes);

        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.signature);

        data
    }

    /// Decode announcement from bytes
    pub fn decode(data: &[u8]) -> Result<Self, RnsError> {
        // 16 (interface_hash) + 32 (public_key) + 32 (verifying_key) + 8 (timestamp) + 2 (metadata_len)
        if data.len() < 16 + 32 + 32 + 8 + 2 {
            return Err(RnsError::InvalidArgument);
        }

        let interface_hash = AddressHash::new(data[..16].try_into().unwrap());
        let public_key: [u8; 32] = data[16..48].try_into().unwrap();
        let verifying_key: [u8; 32] = data[48..80].try_into().unwrap();
        let timestamp = u64::from_be_bytes(data[80..88].try_into().unwrap());

        let metadata_len = u16::from_be_bytes(data[88..90].try_into().unwrap()) as usize;
        if data.len() < 90 + metadata_len + 8 + 64 {
            return Err(RnsError::InvalidArgument);
        }

        let metadata = InterfaceMetadata::decode(&data[90..90 + metadata_len])?;
        let offset = 90 + metadata_len;

        let nonce = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        let signature: [u8; 64] = data[offset + 8..offset + 72].try_into().unwrap();

        Ok(Self {
            interface_hash,
            public_key,
            verifying_key,
            timestamp,
            metadata,
            nonce,
            signature,
            received_at: Instant::now(),
        })
    }
}

/// Interface announcer for broadcasting presence
pub struct InterfaceAnnouncer {
    /// Identity for signing announcements
    identity: Arc<PrivateIdentity>,
    /// Interface hash
    interface_hash: AddressHash,
    /// Interface metadata
    metadata: InterfaceMetadata,
    /// Proof-of-work difficulty
    difficulty: u8,
    /// Announcement interval
    interval: Duration,
    /// Last announcement time
    last_announce: RwLock<Instant>,
    /// Cached announcement
    cached_announce: RwLock<Option<InterfaceAnnouncement>>,
}

impl InterfaceAnnouncer {
    /// Create a new interface announcer
    pub fn new(
        identity: Arc<PrivateIdentity>,
        interface_hash: AddressHash,
        metadata: InterfaceMetadata,
    ) -> Self {
        Self {
            identity,
            interface_hash,
            metadata,
            difficulty: DEFAULT_POW_DIFFICULTY,
            interval: ANNOUNCE_INTERVAL,
            last_announce: RwLock::new(Instant::now() - ANNOUNCE_INTERVAL),
            cached_announce: RwLock::new(None),
        }
    }

    /// Set the announcement interval
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval.max(MIN_ANNOUNCE_INTERVAL);
        self
    }

    /// Set the proof-of-work difficulty
    pub fn with_difficulty(mut self, difficulty: u8) -> Self {
        self.difficulty = difficulty;
        self
    }

    /// Check if announcement should be sent
    pub fn should_announce(&self) -> bool {
        self.last_announce.read().unwrap().elapsed() > self.interval
    }

    /// Create or get cached announcement
    pub fn get_announcement(&self) -> Result<InterfaceAnnouncement, RnsError> {
        // Check if we have a valid cached announcement
        {
            let cached = self.cached_announce.read().unwrap();
            if let Some(ref announce) = *cached {
                if !announce.is_expired() {
                    return Ok(announce.clone());
                }
            }
        }

        // Create new announcement
        let announce = InterfaceAnnouncement::new(
            self.interface_hash,
            &self.identity,
            self.metadata.clone(),
            self.difficulty,
        )?;

        // Cache it
        *self.cached_announce.write().unwrap() = Some(announce.clone());
        *self.last_announce.write().unwrap() = Instant::now();

        Ok(announce)
    }

    /// Mark announcement as sent
    pub fn mark_announced(&self) {
        *self.last_announce.write().unwrap() = Instant::now();
    }
}

/// Handler for incoming interface announcements
#[allow(clippy::type_complexity)]
pub struct InterfaceAnnounceHandler {
    /// Required proof-of-work difficulty
    difficulty: u8,
    /// Cached announcements
    announcements: RwLock<HashMap<AddressHash, InterfaceAnnouncement>>,
    /// Callback for new announcements
    on_announce: RwLock<Option<Arc<dyn Fn(&InterfaceAnnouncement) + Send + Sync>>>,
}

impl Default for InterfaceAnnounceHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceAnnounceHandler {
    /// Create a new announce handler
    pub fn new() -> Self {
        Self {
            difficulty: DEFAULT_POW_DIFFICULTY,
            announcements: RwLock::new(HashMap::new()),
            on_announce: RwLock::new(None),
        }
    }

    /// Set the required difficulty
    pub fn with_difficulty(mut self, difficulty: u8) -> Self {
        self.difficulty = difficulty;
        self
    }

    /// Set callback for new announcements
    pub fn set_callback<F>(&self, callback: F)
    where
        F: Fn(&InterfaceAnnouncement) + Send + Sync + 'static,
    {
        *self.on_announce.write().unwrap() = Some(Arc::new(callback));
    }

    /// Handle an incoming announcement
    pub fn handle_announcement(&self, data: &[u8]) -> Result<bool, RnsError> {
        // Decode announcement
        let announcement = InterfaceAnnouncement::decode(data)?;

        // Verify proof-of-work
        if !announcement.verify_pow(self.difficulty) {
            return Ok(false);
        }

        // Verify signature
        if !announcement.verify_signature() {
            return Ok(false);
        }

        // Check for duplicate/older announcement
        {
            let announcements = self.announcements.read().unwrap();
            if let Some(existing) = announcements.get(&announcement.interface_hash) {
                if existing.timestamp >= announcement.timestamp {
                    return Ok(false); // Already have newer
                }
            }
        }

        // Store announcement
        {
            let mut announcements = self.announcements.write().unwrap();

            // Cleanup if too many
            if announcements.len() >= MAX_CACHED_ANNOUNCES {
                let now = Instant::now();
                announcements.retain(|_, a| now.duration_since(a.received_at) < ANNOUNCE_EXPIRY);
            }

            announcements.insert(announcement.interface_hash, announcement.clone());
        }

        // Call callback
        if let Some(ref callback) = *self.on_announce.read().unwrap() {
            callback(&announcement);
        }

        Ok(true)
    }

    /// Get all known announcements
    pub fn get_announcements(&self) -> Vec<InterfaceAnnouncement> {
        self.announcements
            .read()
            .unwrap()
            .values()
            .filter(|a| !a.is_expired())
            .cloned()
            .collect()
    }

    /// Get announcement for specific interface
    pub fn get_announcement(&self, interface_hash: &AddressHash) -> Option<InterfaceAnnouncement> {
        self.announcements
            .read()
            .unwrap()
            .get(interface_hash)
            .filter(|a| !a.is_expired())
            .cloned()
    }

    /// Clean up expired announcements
    pub fn cleanup(&self) {
        let mut announcements = self.announcements.write().unwrap();
        announcements.retain(|_, a| !a.is_expired());
    }

    /// Get number of cached announcements
    pub fn count(&self) -> usize {
        self.announcements.read().unwrap().len()
    }
}

impl std::fmt::Debug for InterfaceAnnouncer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceAnnouncer")
            .field("interface_hash", &self.interface_hash)
            .field("difficulty", &self.difficulty)
            .field("interval", &self.interval)
            .finish()
    }
}

impl std::fmt::Debug for InterfaceAnnounceHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceAnnounceHandler")
            .field("difficulty", &self.difficulty)
            .field("count", &self.count())
            .finish()
    }
}

// ============================================================================
// Python-Compatible Interface Discovery Storage
// ============================================================================
// This section implements storage compatible with Python's Discovery.py
// for reading/writing discovered interface data files.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Status thresholds matching Python's Discovery.py
pub mod status_thresholds {
    /// Status changes to "unknown" after 24 hours without hearing
    pub const THRESHOLD_UNKNOWN: f64 = 24.0 * 60.0 * 60.0;
    /// Status changes to "stale" after 3 days without hearing
    pub const THRESHOLD_STALE: f64 = 3.0 * 24.0 * 60.0 * 60.0;
    /// Interface is removed after 7 days without hearing
    pub const THRESHOLD_REMOVE: f64 = 7.0 * 24.0 * 60.0 * 60.0;
}

/// Status codes for sorting (matching Python's Discovery.py)
pub mod status_codes {
    pub const STATUS_STALE: u32 = 0;
    pub const STATUS_UNKNOWN: u32 = 100;
    pub const STATUS_AVAILABLE: u32 = 1000;
}

/// Default LXMF stamp value required for discovery
pub const DEFAULT_DISCOVERY_STAMP_VALUE: u8 = 14;

/// LXMF workblock expansion rounds
pub const WORKBLOCK_EXPAND_ROUNDS: u32 = 20;

/// LXMF stamp size in bytes
pub const STAMP_SIZE: usize = 32;

/// Discovery status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryStatus {
    Available,
    Unknown,
    Stale,
}

impl DiscoveryStatus {
    /// Create status from elapsed time since last heard
    pub fn from_elapsed(elapsed_secs: f64) -> Self {
        if elapsed_secs > status_thresholds::THRESHOLD_STALE {
            DiscoveryStatus::Stale
        } else if elapsed_secs > status_thresholds::THRESHOLD_UNKNOWN {
            DiscoveryStatus::Unknown
        } else {
            DiscoveryStatus::Available
        }
    }

    /// Get the string representation matching Python
    pub fn as_str(&self) -> &'static str {
        match self {
            DiscoveryStatus::Available => "available",
            DiscoveryStatus::Unknown => "unknown",
            DiscoveryStatus::Stale => "stale",
        }
    }

    /// Get the numeric status code for sorting
    pub fn code(&self) -> u32 {
        match self {
            DiscoveryStatus::Available => status_codes::STATUS_AVAILABLE,
            DiscoveryStatus::Unknown => status_codes::STATUS_UNKNOWN,
            DiscoveryStatus::Stale => status_codes::STATUS_STALE,
        }
    }
}

impl std::fmt::Display for DiscoveryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Discovered interface information (Python-compatible storage format).
///
/// This struct is serialized/deserialized using MessagePack to match
/// Python's storage format in `storagepath/discovery/interfaces/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredInterfaceInfo {
    /// Interface type (e.g., "BackboneInterface", "TCPServerInterface")
    #[serde(rename = "type")]
    pub interface_type: String,

    /// Whether transport is enabled on the source node
    pub transport: bool,

    /// Interface name
    pub name: String,

    /// Unix timestamp when first discovered
    pub discovered: f64,

    /// Unix timestamp when last announcement was received
    pub last_heard: f64,

    /// Number of times this interface has been heard
    pub heard_count: u32,

    /// Transport identity hash (hex string, no delimiters)
    pub transport_id: String,

    /// Network identity hash (hex string, no delimiters)
    pub network_id: String,

    /// Number of hops away
    pub hops: u8,

    /// LXMF stamp value (proof-of-work difficulty met)
    pub value: u32,

    /// The raw stamp bytes (stored as hex string for msgpack compatibility)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stamp: Option<Vec<u8>>,

    /// Discovery hash (for file naming, stored as hex string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_hash: Option<Vec<u8>>,

    /// Latitude (decimal degrees)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,

    /// Longitude (decimal degrees)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,

    /// Height (meters)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<f32>,

    /// Reachable address (IP, hostname, or I2P B32)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachable_on: Option<String>,

    /// Port number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Radio frequency (Hz) for RF interfaces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency: Option<u64>,

    /// Radio bandwidth (Hz) for RF interfaces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<u64>,

    /// Spreading factor for LoRa interfaces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sf: Option<u8>,

    /// Coding rate for LoRa interfaces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cr: Option<u8>,

    /// Modulation type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modulation: Option<String>,

    /// Channel number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<u32>,

    /// IFAC network name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_netname: Option<String>,

    /// IFAC passphrase
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_netkey: Option<String>,

    /// Generated configuration entry for easy copy-paste
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_entry: Option<String>,

    /// Status determined at load time (not persisted)
    #[serde(skip)]
    pub status: Option<DiscoveryStatus>,

    /// Status code for sorting (not persisted)
    #[serde(skip)]
    pub status_code: Option<u32>,
}

impl Default for DiscoveredInterfaceInfo {
    fn default() -> Self {
        Self {
            interface_type: String::new(),
            transport: false,
            name: String::new(),
            discovered: 0.0,
            last_heard: 0.0,
            heard_count: 0,
            transport_id: String::new(),
            network_id: String::new(),
            hops: 0,
            value: 0,
            stamp: None,
            discovery_hash: None,
            latitude: None,
            longitude: None,
            height: None,
            reachable_on: None,
            port: None,
            frequency: None,
            bandwidth: None,
            sf: None,
            cr: None,
            modulation: None,
            channel: None,
            ifac_netname: None,
            ifac_netkey: None,
            config_entry: None,
            status: None,
            status_code: None,
        }
    }
}

impl DiscoveredInterfaceInfo {
    /// Calculate and set the status based on current time
    pub fn update_status(&mut self, now: f64) {
        let elapsed = now - self.last_heard;
        let status = DiscoveryStatus::from_elapsed(elapsed);
        self.status = Some(status);
        self.status_code = Some(status.code());
    }

    /// Check if this interface should be removed based on age
    pub fn should_remove(&self, now: f64) -> bool {
        now - self.last_heard > status_thresholds::THRESHOLD_REMOVE
    }

    /// Get the discovery hash for file naming.
    /// Hash is computed from transport_id + name.
    pub fn compute_discovery_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let material = format!("{}{}", self.transport_id, self.name);
        let hash: [u8; 32] = Sha256::digest(material.as_bytes()).into();
        hash
    }

    /// Get the hex-encoded discovery hash for file naming
    pub fn discovery_hash_hex(&self) -> String {
        if let Some(ref hash) = self.discovery_hash {
            hex::encode(hash)
        } else {
            hex::encode(self.compute_discovery_hash())
        }
    }
}

/// Storage manager for discovered interfaces.
///
/// Manages persistent storage of discovered interface information
/// in a format compatible with Python's Discovery.py.
pub struct InterfaceDiscoveryStorage {
    /// Path to the storage directory (storagepath/discovery/interfaces/)
    storage_path: PathBuf,
}

impl InterfaceDiscoveryStorage {
    /// Create a new storage manager with the given base storage path.
    ///
    /// The actual storage directory will be `base_path/discovery/interfaces/`.
    pub fn new(base_path: impl AsRef<Path>) -> io::Result<Self> {
        let storage_path = base_path.as_ref().join("discovery").join("interfaces");
        fs::create_dir_all(&storage_path)?;
        Ok(Self { storage_path })
    }

    /// Create storage manager with explicit path
    pub fn with_path(storage_path: impl Into<PathBuf>) -> io::Result<Self> {
        let storage_path = storage_path.into();
        fs::create_dir_all(&storage_path)?;
        Ok(Self { storage_path })
    }

    /// Get the storage path
    pub fn storage_path(&self) -> &Path {
        &self.storage_path
    }

    /// List all discovered interfaces, applying status thresholds.
    ///
    /// This method:
    /// 1. Loads all stored interface files
    /// 2. Removes entries older than THRESHOLD_REMOVE
    /// 3. Calculates status for remaining entries
    /// 4. Optionally filters by discovery sources
    /// 5. Sorts by status_code, value, last_heard (descending)
    pub fn list_discovered(
        &self,
        discovery_sources: Option<&[Vec<u8>]>,
    ) -> io::Result<Vec<DiscoveredInterfaceInfo>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut discovered = Vec::new();
        let mut to_remove = Vec::new();

        // Read all files in storage directory
        for entry in fs::read_dir(&self.storage_path)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            match self.load_interface(&path) {
                Ok(mut info) => {
                    // Check if should be removed
                    if info.should_remove(now) {
                        to_remove.push(path);
                        continue;
                    }

                    // Check discovery sources filter
                    if let Some(sources) = discovery_sources {
                        if !sources.is_empty() {
                            let network_id_bytes = hex::decode(&info.network_id).unwrap_or_default();
                            if !sources.iter().any(|s| s == &network_id_bytes) {
                                to_remove.push(path);
                                continue;
                            }
                        }
                    }

                    // Update status
                    info.update_status(now);
                    discovered.push(info);
                }
                Err(e) => {
                    log::warn!("Failed to load discovery file {:?}: {}", path, e);
                }
            }
        }

        // Remove expired entries
        for path in to_remove {
            if let Err(e) = fs::remove_file(&path) {
                log::warn!("Failed to remove expired discovery file {:?}: {}", path, e);
            }
        }

        // Sort by status_code, value, last_heard (all descending for "best first")
        discovered.sort_by(|a, b| {
            let status_cmp = b.status_code.cmp(&a.status_code);
            if status_cmp != std::cmp::Ordering::Equal {
                return status_cmp;
            }
            let value_cmp = b.value.cmp(&a.value);
            if value_cmp != std::cmp::Ordering::Equal {
                return value_cmp;
            }
            b.last_heard.partial_cmp(&a.last_heard).unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(discovered)
    }

    /// Load a single interface from file
    fn load_interface(&self, path: &Path) -> io::Result<DiscoveredInterfaceInfo> {
        let data = fs::read(path)?;
        rmp_serde::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Save a discovered interface.
    ///
    /// If the interface already exists, updates last_heard and heard_count.
    /// If new, sets discovered = last_heard and heard_count = 1.
    pub fn save_discovered(&self, info: &DiscoveredInterfaceInfo) -> io::Result<()> {
        let filename = info.discovery_hash_hex();
        let filepath = self.storage_path.join(&filename);

        // Check if exists and merge
        let mut to_save = info.clone();
        if filepath.exists() {
            if let Ok(existing) = self.load_interface(&filepath) {
                to_save.discovered = existing.discovered;
                to_save.heard_count = existing.heard_count + 1;
            }
        } else {
            to_save.heard_count = 1;
            if to_save.discovered == 0.0 {
                to_save.discovered = to_save.last_heard;
            }
        }

        // Write atomically using temp file
        // Use to_vec_named for map format (required for structs with optional fields)
        let tmp_path = filepath.with_extension("tmp");
        let data = rmp_serde::to_vec_named(&to_save)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&tmp_path, &data)?;
        fs::rename(&tmp_path, &filepath)?;

        Ok(())
    }

    /// Get a specific discovered interface by its discovery hash
    pub fn get_discovered(&self, discovery_hash: &[u8]) -> io::Result<Option<DiscoveredInterfaceInfo>> {
        let filename = hex::encode(discovery_hash);
        let filepath = self.storage_path.join(&filename);

        if !filepath.exists() {
            return Ok(None);
        }

        let mut info = self.load_interface(&filepath)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        info.update_status(now);

        Ok(Some(info))
    }

    /// Remove a discovered interface
    pub fn remove_discovered(&self, discovery_hash: &[u8]) -> io::Result<bool> {
        let filename = hex::encode(discovery_hash);
        let filepath = self.storage_path.join(&filename);

        if filepath.exists() {
            fs::remove_file(&filepath)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Clean up expired interfaces
    pub fn cleanup_expired(&self) -> io::Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut removed = 0;

        for entry in fs::read_dir(&self.storage_path)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if let Ok(info) = self.load_interface(&path) {
                if info.should_remove(now)
                    && fs::remove_file(&path).is_ok() {
                        removed += 1;
                    }
            }
        }

        Ok(removed)
    }

    /// Get the count of stored interfaces
    pub fn count(&self) -> io::Result<usize> {
        let mut count = 0;
        for entry in fs::read_dir(&self.storage_path)? {
            let entry = entry?;
            if entry.path().is_file() {
                count += 1;
            }
        }
        Ok(count)
    }
}

// ============================================================================
// Python-Compatible Interface Announce Handler
// ============================================================================
// This section implements announce parsing compatible with Python's Discovery.py

/// MessagePack keys used in Python discovery announcements.
/// These are integer keys matching Python's Discovery.py constants.
pub mod announce_keys {
    pub const NAME: u8 = 0xFF;
    pub const TRANSPORT_ID: u8 = 0xFE;
    pub const INTERFACE_TYPE: u8 = 0x00;
    pub const TRANSPORT: u8 = 0x01;
    pub const REACHABLE_ON: u8 = 0x02;
    pub const LATITUDE: u8 = 0x03;
    pub const LONGITUDE: u8 = 0x04;
    pub const HEIGHT: u8 = 0x05;
    pub const PORT: u8 = 0x06;
    pub const IFAC_NETNAME: u8 = 0x07;
    pub const IFAC_NETKEY: u8 = 0x08;
    pub const FREQUENCY: u8 = 0x09;
    pub const BANDWIDTH: u8 = 0x0A;
    pub const SPREADINGFACTOR: u8 = 0x0B;
    pub const CODINGRATE: u8 = 0x0C;
    pub const MODULATION: u8 = 0x0D;
    pub const CHANNEL: u8 = 0x0E;
}

/// Announce data flags
pub mod announce_flags {
    pub const FLAG_SIGNED: u8 = 0b00000001;
    pub const FLAG_ENCRYPTED: u8 = 0b00000010;
}

/// Aspect filter for interface discovery announces
pub const DISCOVERY_ASPECT: &str = "rnstransport.discovery.interface";

/// Handler for Python-compatible interface discovery announcements.
///
/// This handler parses announcements from Python nodes and validates
/// the LXMF workblock stamps.
#[allow(clippy::type_complexity)]
pub struct PythonDiscoveryHandler {
    /// Required stamp value (difficulty)
    required_value: u8,
    /// Storage for discovered interfaces
    storage: Option<InterfaceDiscoveryStorage>,
    /// Optional callback for new discoveries
    callback: Option<Box<dyn Fn(&DiscoveredInterfaceInfo) + Send + Sync>>,
}

impl PythonDiscoveryHandler {
    /// Create a new handler with the specified required stamp value.
    pub fn new(required_value: u8) -> Self {
        Self {
            required_value,
            storage: None,
            callback: None,
        }
    }

    /// Set the storage backend
    pub fn with_storage(mut self, storage: InterfaceDiscoveryStorage) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set a callback for newly discovered interfaces
    pub fn with_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&DiscoveredInterfaceInfo) + Send + Sync + 'static,
    {
        self.callback = Some(Box::new(callback));
        self
    }

    /// Handle an incoming discovery announcement.
    ///
    /// # Arguments
    /// * `destination_hash` - The destination hash from the announce
    /// * `announced_identity_hash` - The identity hash of the announcer
    /// * `app_data` - The application data from the announce
    /// * `hops` - Number of hops the announce traveled
    ///
    /// # Returns
    /// Some(DiscoveredInterfaceInfo) if the announce was valid, None otherwise.
    pub fn handle_announce(
        &self,
        _destination_hash: &[u8],
        announced_identity_hash: &[u8],
        app_data: &[u8],
        hops: u8,
    ) -> Option<DiscoveredInterfaceInfo> {
        use crate::stamper::{Stamper, STAMP_SIZE, WORKBLOCK_EXPAND_ROUNDS_DISCOVERY};

        if app_data.len() <= STAMP_SIZE + 1 {
            log::debug!("Discovery announce too short");
            return None;
        }

        // Parse flags
        let flags = app_data[0];
        let payload = &app_data[1..];

        let _signed = flags & announce_flags::FLAG_SIGNED != 0;
        let encrypted = flags & announce_flags::FLAG_ENCRYPTED != 0;

        // Handle encryption (would need network identity to decrypt)
        if encrypted {
            log::debug!("Encrypted discovery announce - decryption not implemented");
            return None;
        }

        // Extract stamp (last STAMP_SIZE bytes)
        if payload.len() <= STAMP_SIZE {
            log::debug!("Discovery payload too short for stamp");
            return None;
        }

        let split_point = payload.len() - STAMP_SIZE;
        let packed = &payload[..split_point];
        let stamp = &payload[split_point..];

        // Calculate info hash and validate stamp
        let info_hash = Stamper::full_hash(packed);
        let workblock = Stamper::stamp_workblock(&info_hash, WORKBLOCK_EXPAND_ROUNDS_DISCOVERY);

        if !Stamper::stamp_valid(stamp, self.required_value, &workblock) {
            log::debug!("Discovery announce has invalid stamp");
            return None;
        }

        let stamp_value = Stamper::stamp_value(&workblock, stamp);

        // Parse msgpack data with integer keys
        // Use rmpv's decoder since rmpv::Value doesn't implement serde::Deserialize
        let value = match rmpv::decode::read_value(&mut std::io::Cursor::new(packed)) {
            Ok(v) => v,
            Err(e) => {
                log::debug!("Failed to parse discovery announce msgpack: {}", e);
                return None;
            }
        };

        // Convert Value to HashMap<u8, Value>
        let unpacked: std::collections::HashMap<u8, rmpv::Value> = match value {
            rmpv::Value::Map(pairs) => {
                pairs
                    .into_iter()
                    .filter_map(|(k, v)| {
                        if let rmpv::Value::Integer(i) = k {
                            i.as_u64().and_then(|n| u8::try_from(n).ok()).map(|key| (key, v))
                        } else {
                            None
                        }
                    })
                    .collect()
            }
            _ => {
                log::debug!("Discovery announce is not a msgpack map");
                return None;
            }
        };

        // Extract required fields
        let interface_type = unpacked
            .get(&announce_keys::INTERFACE_TYPE)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())?;

        let name = unpacked
            .get(&announce_keys::NAME)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("Discovered {}", interface_type));

        let transport = unpacked
            .get(&announce_keys::TRANSPORT)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let transport_id = unpacked
            .get(&announce_keys::TRANSPORT_ID)
            .and_then(|v| v.as_slice())
            .map(hex::encode)
            .unwrap_or_default();

        let network_id = hex::encode(announced_identity_hash);

        // Extract optional fields
        let latitude = unpacked
            .get(&announce_keys::LATITUDE)
            .and_then(|v| v.as_f64());

        let longitude = unpacked
            .get(&announce_keys::LONGITUDE)
            .and_then(|v| v.as_f64());

        let height = unpacked
            .get(&announce_keys::HEIGHT)
            .and_then(|v| v.as_f64())
            .map(|h| h as f32);

        let reachable_on = unpacked
            .get(&announce_keys::REACHABLE_ON)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let port = unpacked
            .get(&announce_keys::PORT)
            .and_then(|v| v.as_u64())
            .map(|p| p as u16);

        let frequency = unpacked
            .get(&announce_keys::FREQUENCY)
            .and_then(|v| v.as_u64());

        let bandwidth = unpacked
            .get(&announce_keys::BANDWIDTH)
            .and_then(|v| v.as_u64());

        let sf = unpacked
            .get(&announce_keys::SPREADINGFACTOR)
            .and_then(|v| v.as_u64())
            .map(|s| s as u8);

        let cr = unpacked
            .get(&announce_keys::CODINGRATE)
            .and_then(|v| v.as_u64())
            .map(|c| c as u8);

        let modulation = unpacked
            .get(&announce_keys::MODULATION)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let channel = unpacked
            .get(&announce_keys::CHANNEL)
            .and_then(|v| v.as_u64())
            .map(|c| c as u32);

        let ifac_netname = unpacked
            .get(&announce_keys::IFAC_NETNAME)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let ifac_netkey = unpacked
            .get(&announce_keys::IFAC_NETKEY)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Generate config entry
        let config_entry = generate_config_entry(
            &interface_type,
            &name,
            &transport_id,
            reachable_on.as_deref(),
            port,
            ifac_netname.as_deref(),
            ifac_netkey.as_deref(),
            frequency,
            bandwidth,
            sf,
            cr,
        );

        // Get current time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        // Build discovery hash
        let discovery_hash_material = format!("{}{}", transport_id, name);
        let discovery_hash = Stamper::full_hash(discovery_hash_material.as_bytes());

        let info = DiscoveredInterfaceInfo {
            interface_type,
            transport,
            name,
            discovered: now,
            last_heard: now,
            heard_count: 1,
            transport_id,
            network_id,
            hops,
            value: stamp_value as u32,
            stamp: Some(stamp.to_vec()),
            discovery_hash: Some(discovery_hash.to_vec()),
            latitude,
            longitude,
            height,
            reachable_on,
            port,
            frequency,
            bandwidth,
            sf,
            cr,
            modulation,
            channel,
            ifac_netname,
            ifac_netkey,
            config_entry,
            status: None,
            status_code: None,
        };

        // Save to storage if available
        if let Some(ref storage) = self.storage {
            if let Err(e) = storage.save_discovered(&info) {
                log::warn!("Failed to save discovered interface: {}", e);
            }
        }

        // Call callback if set
        if let Some(ref callback) = self.callback {
            callback(&info);
        }

        Some(info)
    }
}

/// Generate a configuration entry for an interface.
///
/// This creates a ready-to-use configuration snippet matching Python's output.
#[allow(clippy::too_many_arguments)]
fn generate_config_entry(
    interface_type: &str,
    name: &str,
    transport_id: &str,
    reachable_on: Option<&str>,
    port: Option<u16>,
    ifac_netname: Option<&str>,
    ifac_netkey: Option<&str>,
    frequency: Option<u64>,
    bandwidth: Option<u64>,
    sf: Option<u8>,
    cr: Option<u8>,
) -> Option<String> {
    let mut entry = String::new();

    // Determine connection interface type (BackboneInterface on Unix, TCPClientInterface on Windows)
    let connection_interface = if cfg!(target_os = "windows") {
        "TCPClientInterface"
    } else {
        "BackboneInterface"
    };

    let remote_str = if cfg!(target_os = "windows") {
        "target_host"
    } else {
        "remote"
    };

    match interface_type {
        "BackboneInterface" | "TCPServerInterface" => {
            let addr = reachable_on?;
            let p = port?;
            entry.push_str(&format!("[[{}]]\n", name));
            entry.push_str(&format!("  type = {}\n", connection_interface));
            entry.push_str("  enabled = yes\n");
            entry.push_str(&format!("  {} = {}\n", remote_str, addr));
            entry.push_str(&format!("  target_port = {}\n", p));
            entry.push_str(&format!("  transport_identity = {}", transport_id));
            if let Some(netname) = ifac_netname {
                entry.push_str(&format!("\n  network_name = {}", netname));
            }
            if let Some(netkey) = ifac_netkey {
                entry.push_str(&format!("\n  passphrase = {}", netkey));
            }
        }
        "I2PInterface" => {
            let addr = reachable_on?;
            entry.push_str(&format!("[[{}]]\n", name));
            entry.push_str("  type = I2PInterface\n");
            entry.push_str("  enabled = yes\n");
            entry.push_str(&format!("  peers = {}\n", addr));
            entry.push_str(&format!("  transport_identity = {}", transport_id));
            if let Some(netname) = ifac_netname {
                entry.push_str(&format!("\n  network_name = {}", netname));
            }
            if let Some(netkey) = ifac_netkey {
                entry.push_str(&format!("\n  passphrase = {}", netkey));
            }
        }
        "RNodeInterface" => {
            let freq = frequency?;
            let bw = bandwidth?;
            let spreading = sf?;
            let coding = cr?;
            entry.push_str(&format!("[[{}]]\n", name));
            entry.push_str("  type = RNodeInterface\n");
            entry.push_str("  enabled = yes\n");
            entry.push_str("  port = \n");
            entry.push_str(&format!("  frequency = {}\n", freq));
            entry.push_str(&format!("  bandwidth = {}\n", bw));
            entry.push_str(&format!("  spreadingfactor = {}\n", spreading));
            entry.push_str(&format!("  codingrate = {}\n", coding));
            entry.push_str("  txpower = ");
            if let Some(netname) = ifac_netname {
                entry.push_str(&format!("\n  network_name = {}", netname));
            }
            if let Some(netkey) = ifac_netkey {
                entry.push_str(&format!("\n  passphrase = {}", netkey));
            }
        }
        "KISSInterface" => {
            entry.push_str(&format!("[[{}]]\n", name));
            entry.push_str("  type = KISSInterface\n");
            entry.push_str("  enabled = yes\n");
            entry.push_str("  port = \n");
            if let Some(freq) = frequency {
                entry.push_str(&format!("  # Frequency: {}\n", freq));
            }
            if let Some(bw) = bandwidth {
                entry.push_str(&format!("  # Bandwidth: {}\n", bw));
            }
            entry.push_str(&format!("  transport_identity = {}", transport_id));
            if let Some(netname) = ifac_netname {
                entry.push_str(&format!("\n  network_name = {}", netname));
            }
            if let Some(netkey) = ifac_netkey {
                entry.push_str(&format!("\n  passphrase = {}", netkey));
            }
        }
        _ => return None,
    }

    Some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_metadata_encode_decode() {
        let metadata = InterfaceMetadata::new("test_interface", InterfaceType::TcpServer)
            .with_location("New York")
            .with_bandwidth(1_000_000)
            .with_tag("version", "1.0");

        let encoded = metadata.encode();
        let decoded = InterfaceMetadata::decode(&encoded).unwrap();

        assert_eq!(decoded.name, "test_interface");
        assert_eq!(decoded.iface_type, InterfaceType::TcpServer);
        assert_eq!(decoded.location, Some("New York".to_string()));
        assert_eq!(decoded.bandwidth, 1_000_000);
        assert_eq!(decoded.tags.get("version"), Some(&"1.0".to_string()));
    }

    #[test]
    fn test_interface_type_conversion() {
        assert_eq!(InterfaceType::from(1), InterfaceType::TcpClient);
        assert_eq!(InterfaceType::from(2), InterfaceType::TcpServer);
        assert_eq!(InterfaceType::from(255), InterfaceType::Unknown);
    }

    #[test]
    fn test_announce_handler_creation() {
        let handler = InterfaceAnnounceHandler::new();
        assert_eq!(handler.count(), 0);
    }

    #[test]
    fn test_pow_verification() {
        use rand_core::OsRng;

        // Test with very low difficulty for fast test
        let metadata = InterfaceMetadata::new("test", InterfaceType::TcpClient);
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let interface_hash = AddressHash::new([1u8; 16]);

        // Create announcement with difficulty 1 (very easy)
        let announce = InterfaceAnnouncement::new(
            interface_hash,
            &identity,
            metadata,
            1, // Very low difficulty for test
        )
        .unwrap();

        assert!(announce.verify_pow(1));
        assert!(announce.verify_signature());
    }

    #[test]
    fn test_announcement_encode_decode() {
        use rand_core::OsRng;

        let metadata = InterfaceMetadata::new("test", InterfaceType::Udp);
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let interface_hash = AddressHash::new([2u8; 16]);

        let announce = InterfaceAnnouncement::new(
            interface_hash.clone(),
            &identity,
            metadata,
            1,
        )
        .unwrap();

        let encoded = announce.encode();
        let decoded = InterfaceAnnouncement::decode(&encoded).unwrap();

        assert_eq!(decoded.interface_hash.as_slice(), interface_hash.as_slice());
        assert_eq!(decoded.public_key, announce.public_key);
        assert_eq!(decoded.timestamp, announce.timestamp);
        assert_eq!(decoded.nonce, announce.nonce);
    }

    #[test]
    fn test_announcer() {
        use rand_core::OsRng;

        let identity = Arc::new(PrivateIdentity::new_from_rand(OsRng));
        let interface_hash = AddressHash::new([3u8; 16]);
        let metadata = InterfaceMetadata::new("test_iface", InterfaceType::Serial);

        let announcer = InterfaceAnnouncer::new(identity, interface_hash, metadata)
            .with_difficulty(1)
            .with_interval(Duration::from_secs(60));

        // Should announce since interval has passed
        assert!(announcer.should_announce());

        // Get announcement should work
        let announce = announcer.get_announcement().unwrap();
        assert!(announce.verify_pow(1));
        assert!(announce.verify_signature());
    }

    #[test]
    fn test_handler_stores_announcement() {
        use rand_core::OsRng;

        let handler = InterfaceAnnounceHandler::new().with_difficulty(1);

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let interface_hash = AddressHash::new([4u8; 16]);
        let metadata = InterfaceMetadata::new("test", InterfaceType::TcpClient);

        let announce = InterfaceAnnouncement::new(interface_hash.clone(), &identity, metadata, 1).unwrap();
        let encoded = announce.encode();

        let result = handler.handle_announcement(&encoded).unwrap();
        assert!(result);
        assert_eq!(handler.count(), 1);

        // Get it back
        let retrieved = handler.get_announcement(&interface_hash).unwrap();
        assert_eq!(retrieved.interface_hash.as_slice(), interface_hash.as_slice());
    }

    // ========================================================================
    // Discovery Storage Tests
    // ========================================================================

    #[test]
    fn test_discovery_status_from_elapsed() {
        // Less than 24 hours = Available
        assert_eq!(
            DiscoveryStatus::from_elapsed(23.0 * 60.0 * 60.0),
            DiscoveryStatus::Available
        );

        // Between 24 hours and 3 days = Unknown
        assert_eq!(
            DiscoveryStatus::from_elapsed(25.0 * 60.0 * 60.0),
            DiscoveryStatus::Unknown
        );

        // More than 3 days = Stale
        assert_eq!(
            DiscoveryStatus::from_elapsed(4.0 * 24.0 * 60.0 * 60.0),
            DiscoveryStatus::Stale
        );
    }

    #[test]
    fn test_discovery_status_codes() {
        assert_eq!(DiscoveryStatus::Available.code(), status_codes::STATUS_AVAILABLE);
        assert_eq!(DiscoveryStatus::Unknown.code(), status_codes::STATUS_UNKNOWN);
        assert_eq!(DiscoveryStatus::Stale.code(), status_codes::STATUS_STALE);

        // Verify ordering: Available > Unknown > Stale
        assert!(DiscoveryStatus::Available.code() > DiscoveryStatus::Unknown.code());
        assert!(DiscoveryStatus::Unknown.code() > DiscoveryStatus::Stale.code());
    }

    #[test]
    fn test_discovered_interface_info_default() {
        let info = DiscoveredInterfaceInfo::default();
        assert_eq!(info.name, "");
        assert_eq!(info.interface_type, "");
        assert!(!info.transport);
        assert_eq!(info.hops, 0);
        assert_eq!(info.value, 0);
        assert!(info.status.is_none());
    }

    #[test]
    fn test_discovered_interface_info_serialization() {
        let info = DiscoveredInterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            transport: true,
            name: "Test Interface".to_string(),
            discovered: 1700000000.0,
            last_heard: 1700001000.0,
            heard_count: 5,
            transport_id: "abcd1234".to_string(),
            network_id: "efgh5678".to_string(),
            hops: 2,
            value: 14,
            reachable_on: Some("192.168.1.1".to_string()),
            port: Some(4242),
            ..Default::default()
        };

        // Serialize to msgpack with named fields (map format, not array)
        // This is critical for structs with optional fields that may be skipped
        let encoded = rmp_serde::to_vec_named(&info).unwrap();

        // Deserialize back
        let decoded: DiscoveredInterfaceInfo = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded.interface_type, "TCPServerInterface");
        assert_eq!(decoded.name, "Test Interface");
        assert!(decoded.transport);
        assert_eq!(decoded.hops, 2);
        assert_eq!(decoded.value, 14);
        assert_eq!(decoded.reachable_on, Some("192.168.1.1".to_string()));
        assert_eq!(decoded.port, Some(4242));
    }

    #[test]
    fn test_discovered_interface_should_remove() {
        let mut info = DiscoveredInterfaceInfo::default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        // Recent - should not remove
        info.last_heard = now - 1000.0;
        assert!(!info.should_remove(now));

        // 8 days old - should remove
        info.last_heard = now - (8.0 * 24.0 * 60.0 * 60.0);
        assert!(info.should_remove(now));
    }

    #[test]
    fn test_discovered_interface_compute_discovery_hash() {
        let info = DiscoveredInterfaceInfo {
            transport_id: "abcd1234".to_string(),
            name: "Test Interface".to_string(),
            ..Default::default()
        };

        let hash1 = info.compute_discovery_hash();
        let hash2 = info.compute_discovery_hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);

        // Different name/transport_id should give different hash
        let info2 = DiscoveredInterfaceInfo {
            transport_id: "different".to_string(),
            name: "Test Interface".to_string(),
            ..Default::default()
        };
        assert_ne!(hash1, info2.compute_discovery_hash());
    }

    #[test]
    fn test_discovery_storage_save_and_load() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let storage = InterfaceDiscoveryStorage::new(temp_dir.path()).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let info = DiscoveredInterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            transport: true,
            name: "Test Interface".to_string(),
            discovered: now,
            last_heard: now,
            heard_count: 1,
            transport_id: "abcd1234efgh5678".to_string(),
            network_id: "1234abcd5678efgh".to_string(),
            hops: 2,
            value: 14,
            ..Default::default()
        };

        // Save
        storage.save_discovered(&info).unwrap();

        // Verify it was saved
        assert_eq!(storage.count().unwrap(), 1);

        // Load back via list
        let loaded = storage.list_discovered(None).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Test Interface");
        assert_eq!(loaded[0].value, 14);
        assert!(loaded[0].status.is_some());
        assert_eq!(loaded[0].status.unwrap(), DiscoveryStatus::Available);
    }

    #[test]
    fn test_discovery_storage_updates_heard_count() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let storage = InterfaceDiscoveryStorage::new(temp_dir.path()).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut info = DiscoveredInterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            name: "Test Interface".to_string(),
            last_heard: now,
            transport_id: "abcd1234".to_string(),
            network_id: "efgh5678".to_string(),
            ..Default::default()
        };

        // Save first time
        storage.save_discovered(&info).unwrap();

        // Save again (simulating another announcement)
        info.last_heard = now + 100.0;
        storage.save_discovered(&info).unwrap();

        // Load and check heard_count was incremented
        let loaded = storage.list_discovered(None).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].heard_count, 2);
    }

    #[test]
    fn test_discovery_storage_cleanup_expired() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let storage = InterfaceDiscoveryStorage::new(temp_dir.path()).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        // Save one recent and one expired
        let recent = DiscoveredInterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            name: "Recent".to_string(),
            last_heard: now,
            transport_id: "recent1234".to_string(),
            network_id: "net1234".to_string(),
            ..Default::default()
        };

        let expired = DiscoveredInterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            name: "Expired".to_string(),
            last_heard: now - (10.0 * 24.0 * 60.0 * 60.0), // 10 days ago
            transport_id: "expired1234".to_string(),
            network_id: "net5678".to_string(),
            ..Default::default()
        };

        storage.save_discovered(&recent).unwrap();
        storage.save_discovered(&expired).unwrap();

        // Both should be stored initially
        assert_eq!(storage.count().unwrap(), 2);

        // List should filter out expired
        let loaded = storage.list_discovered(None).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Recent");

        // Expired file should have been removed
        assert_eq!(storage.count().unwrap(), 1);
    }

    #[test]
    fn test_discovery_storage_sorting() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let storage = InterfaceDiscoveryStorage::new(temp_dir.path()).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        // Create interfaces with different values
        let high_value = DiscoveredInterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            name: "HighValue".to_string(),
            last_heard: now,
            value: 20,
            transport_id: "high1234".to_string(),
            network_id: "net1234".to_string(),
            ..Default::default()
        };

        let low_value = DiscoveredInterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            name: "LowValue".to_string(),
            last_heard: now,
            value: 10,
            transport_id: "low1234".to_string(),
            network_id: "net5678".to_string(),
            ..Default::default()
        };

        storage.save_discovered(&low_value).unwrap();
        storage.save_discovered(&high_value).unwrap();

        // List should be sorted by value (descending)
        let loaded = storage.list_discovered(None).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "HighValue"); // Higher value first
        assert_eq!(loaded[1].name, "LowValue");
    }
}
