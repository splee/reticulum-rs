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
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(metadata_bytes);
        hasher.update(&nonce.to_be_bytes());
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
            self.interface_hash.clone(),
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

            announcements.insert(announcement.interface_hash.clone(), announcement.clone());
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
}
