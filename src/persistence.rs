//! Persistence layer for Reticulum
//!
//! This module handles saving and loading of identities, known destinations,
//! ratchet keys, and other persistent data to disk using MessagePack format.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{Identity, RATCHET_ID_LENGTH};

/// Length of truncated hash in bytes (128 bits / 8)
pub const TRUNCATED_HASH_LENGTH: usize = 16;

/// Length of public key in bytes (256 bits / 8)
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Full public key (encryption + signing) length in bytes
pub const FULL_PUBLIC_KEY_LENGTH: usize = 64;

/// Ratchet expiry time in seconds (30 days)
pub const RATCHET_EXPIRY: u64 = 60 * 60 * 24 * 30;

/// Information about a known destination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownDestination {
    /// When this destination was last seen (Unix timestamp)
    pub timestamp: f64,
    /// Hash of the packet that announced this destination
    pub packet_hash: Vec<u8>,
    /// Public key of the destination (64 bytes: encryption + signing)
    pub public_key: Vec<u8>,
    /// Optional application data from announce
    pub app_data: Option<Vec<u8>>,
}

/// Information about a stored ratchet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRatchet {
    /// The ratchet key bytes
    pub ratchet: Vec<u8>,
    /// When this ratchet was received (Unix timestamp)
    pub received: f64,
}

/// Manager for known destinations cache
#[derive(Debug)]
pub struct KnownDestinations {
    /// The cache of known destinations (destination_hash -> KnownDestination)
    cache: RwLock<HashMap<[u8; TRUNCATED_HASH_LENGTH], KnownDestination>>,
    /// Path to the storage file
    storage_path: PathBuf,
    /// Whether a save operation is in progress
    saving: RwLock<bool>,
}

impl KnownDestinations {
    /// Create a new known destinations manager
    pub fn new(storage_path: impl AsRef<Path>) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            storage_path: storage_path.as_ref().join("known_destinations"),
            saving: RwLock::new(false),
        }
    }

    /// Load known destinations from disk
    pub fn load(&self) -> io::Result<()> {
        if !self.storage_path.exists() {
            return Ok(());
        }

        let file = File::open(&self.storage_path)?;
        let reader = BufReader::new(file);

        // Read the msgpack data
        let loaded: HashMap<Vec<u8>, KnownDestination> =
            rmp_serde::from_read(reader).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("MessagePack error: {}", e))
            })?;

        let mut cache = self.cache.write().map_err(|_| {
            io::Error::other("Failed to acquire write lock")
        })?;

        cache.clear();

        // Filter and convert keys to fixed-size arrays
        for (key, value) in loaded {
            if key.len() == TRUNCATED_HASH_LENGTH {
                let mut hash = [0u8; TRUNCATED_HASH_LENGTH];
                hash.copy_from_slice(&key);
                cache.insert(hash, value);
            }
        }

        Ok(())
    }

    /// Save known destinations to disk
    pub fn save(&self) -> io::Result<()> {
        // Check if already saving
        {
            let mut saving = self.saving.write().map_err(|_| {
                io::Error::other("Failed to acquire saving lock")
            })?;
            if *saving {
                return Ok(()); // Already saving, skip
            }
            *saving = true;
        }

        let result = (|| {
            let cache = self.cache.read().map_err(|_| {
                io::Error::other("Failed to acquire read lock")
            })?;

            // Convert to Vec<u8> keys for serialization
            let serializable: HashMap<Vec<u8>, &KnownDestination> = cache
                .iter()
                .map(|(k, v)| (k.to_vec(), v))
                .collect();

            // Ensure directory exists
            if let Some(parent) = self.storage_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Write to temporary file first
            let temp_path = self.storage_path.with_extension("tmp");
            let file = File::create(&temp_path)?;
            let mut writer = BufWriter::new(file);

            rmp_serde::encode::write(&mut writer, &serializable).map_err(|e| {
                io::Error::other(format!("MessagePack error: {}", e))
            })?;

            writer.flush()?;
            drop(writer);

            // Atomically replace the old file
            fs::rename(&temp_path, &self.storage_path)?;

            Ok(())
        })();

        // Clear saving flag
        if let Ok(mut saving) = self.saving.write() {
            *saving = false;
        }

        result
    }

    /// Remember a destination
    pub fn remember(
        &self,
        destination_hash: &[u8; TRUNCATED_HASH_LENGTH],
        packet_hash: &[u8],
        public_key: &[u8],
        app_data: Option<&[u8]>,
    ) -> io::Result<()> {
        if public_key.len() != FULL_PUBLIC_KEY_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid public key length: {} (expected {})",
                    public_key.len(),
                    FULL_PUBLIC_KEY_LENGTH
                ),
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let known = KnownDestination {
            timestamp: now,
            packet_hash: packet_hash.to_vec(),
            public_key: public_key.to_vec(),
            app_data: app_data.map(|d| d.to_vec()),
        };

        let mut cache = self.cache.write().map_err(|_| {
            io::Error::other("Failed to acquire write lock")
        })?;

        cache.insert(*destination_hash, known);

        Ok(())
    }

    /// Recall a destination by its hash
    pub fn recall(&self, destination_hash: &[u8; TRUNCATED_HASH_LENGTH]) -> Option<KnownDestination> {
        self.cache
            .read()
            .ok()
            .and_then(|cache| cache.get(destination_hash).cloned())
    }

    /// Recall app_data for a destination
    pub fn recall_app_data(&self, destination_hash: &[u8; TRUNCATED_HASH_LENGTH]) -> Option<Vec<u8>> {
        self.recall(destination_hash)
            .and_then(|kd| kd.app_data)
    }

    /// Recall an Identity for a destination.
    ///
    /// This creates an `Identity` object from the stored public key bytes.
    /// Mirrors Python's `Identity.recall(destination_hash)`.
    pub fn recall_identity(&self, destination_hash: &[u8; TRUNCATED_HASH_LENGTH]) -> Option<Identity> {
        self.recall(destination_hash).and_then(|kd| {
            if kd.public_key.len() >= FULL_PUBLIC_KEY_LENGTH {
                Some(Identity::from_bytes(&kd.public_key).ok()?)
            } else {
                None
            }
        })
    }

    /// Get the number of known destinations
    pub fn len(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Manager for ratchet keys
#[derive(Debug)]
pub struct RatchetManager {
    /// In-memory cache of ratchets (destination_hash -> ratchet public bytes)
    cache: RwLock<HashMap<[u8; TRUNCATED_HASH_LENGTH], Vec<u8>>>,
    /// Path to ratchet storage directory
    storage_dir: PathBuf,
}

impl RatchetManager {
    /// Create a new ratchet manager
    pub fn new(storage_path: impl AsRef<Path>) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            storage_dir: storage_path.as_ref().join("ratchets"),
        }
    }

    /// Get the ratchet directory, creating it if needed
    fn ensure_ratchet_dir(&self) -> io::Result<&Path> {
        fs::create_dir_all(&self.storage_dir)?;
        Ok(&self.storage_dir)
    }

    /// Load all ratchets from disk
    pub fn load(&self) -> io::Result<()> {
        if !self.storage_dir.exists() {
            return Ok(());
        }

        let mut cache = self.cache.write().map_err(|_| {
            io::Error::other("Failed to acquire write lock")
        })?;

        cache.clear();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        for entry in fs::read_dir(&self.storage_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Skip temporary files
            if path.extension().is_some_and(|e| e == "out") {
                continue;
            }

            if let Ok(hex_name) = path.file_name().and_then(|n| n.to_str()).ok_or(()) {
                // Try to parse as hex destination hash
                if hex_name.len() == TRUNCATED_HASH_LENGTH * 2 {
                    if let Ok(file) = File::open(&path) {
                        let reader = BufReader::new(file);
                        if let Ok(stored_ratchet) = rmp_serde::from_read::<_, StoredRatchet>(reader) {
                            // Check if expired
                            if now <= stored_ratchet.received + RATCHET_EXPIRY as f64 {
                                // Parse the destination hash from filename
                                if let Ok(hash) = hex_to_bytes(hex_name) {
                                    if hash.len() == TRUNCATED_HASH_LENGTH {
                                        let mut dest_hash = [0u8; TRUNCATED_HASH_LENGTH];
                                        dest_hash.copy_from_slice(&hash);
                                        cache.insert(dest_hash, stored_ratchet.ratchet);
                                    }
                                }
                            } else {
                                // Remove expired ratchet file
                                let _ = fs::remove_file(&path);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Remember a ratchet for a destination
    pub fn remember(&self, destination_hash: &[u8; TRUNCATED_HASH_LENGTH], ratchet: &[u8]) -> io::Result<()> {
        // Check if we already have this exact ratchet
        {
            let cache = self.cache.read().map_err(|_| {
                io::Error::other("Failed to acquire read lock")
            })?;

            if let Some(existing) = cache.get(destination_hash) {
                if existing == ratchet {
                    return Ok(()); // Already have this ratchet
                }
            }
        }

        // Update cache
        {
            let mut cache = self.cache.write().map_err(|_| {
                io::Error::other("Failed to acquire write lock")
            })?;
            cache.insert(*destination_hash, ratchet.to_vec());
        }

        // Persist to disk
        self.persist_ratchet(destination_hash, ratchet)
    }

    /// Persist a ratchet to disk
    fn persist_ratchet(&self, destination_hash: &[u8; TRUNCATED_HASH_LENGTH], ratchet: &[u8]) -> io::Result<()> {
        self.ensure_ratchet_dir()?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let stored = StoredRatchet {
            ratchet: ratchet.to_vec(),
            received: now,
        };

        let hex_hash = bytes_to_hex(destination_hash);
        let final_path = self.storage_dir.join(&hex_hash);
        let temp_path = self.storage_dir.join(format!("{}.out", hex_hash));

        let file = File::create(&temp_path)?;
        let mut writer = BufWriter::new(file);

        rmp_serde::encode::write(&mut writer, &stored).map_err(|e| {
            io::Error::other(format!("MessagePack error: {}", e))
        })?;

        writer.flush()?;
        drop(writer);

        fs::rename(&temp_path, &final_path)?;

        Ok(())
    }

    /// Get the ratchet for a destination
    pub fn get(&self, destination_hash: &[u8; TRUNCATED_HASH_LENGTH]) -> Option<Vec<u8>> {
        self.cache
            .read()
            .ok()
            .and_then(|cache| cache.get(destination_hash).cloned())
    }

    /// Get the current ratchet ID for a destination.
    ///
    /// The ratchet ID is the first 10 bytes of SHA-256 hash of the ratchet public key.
    /// This matches Python's `Identity._get_ratchet_id()`.
    pub fn current_ratchet_id(
        &self,
        destination_hash: &[u8; TRUNCATED_HASH_LENGTH],
    ) -> Option<[u8; RATCHET_ID_LENGTH]> {
        self.get(destination_hash).map(|ratchet| {
            let mut hasher = Sha256::new();
            hasher.update(&ratchet);
            let hash = hasher.finalize();

            let mut id = [0u8; RATCHET_ID_LENGTH];
            id.copy_from_slice(&hash[..RATCHET_ID_LENGTH]);
            id
        })
    }

    /// Clean expired ratchets from memory and disk
    pub fn clean_expired(&self) -> io::Result<()> {
        if !self.storage_dir.exists() {
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let mut to_remove = Vec::new();

        for entry in fs::read_dir(&self.storage_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Skip temporary files
            if path.extension().is_some_and(|e| e == "out") {
                let _ = fs::remove_file(&path); // Clean up stale temp files
                continue;
            }

            if let Ok(file) = File::open(&path) {
                let reader = BufReader::new(file);
                if let Ok(stored) = rmp_serde::from_read::<_, StoredRatchet>(reader) {
                    if now > stored.received + RATCHET_EXPIRY as f64 {
                        to_remove.push(path.clone());

                        // Also remove from cache
                        if let Some(hex_name) = path.file_name().and_then(|n| n.to_str()) {
                            if let Ok(hash) = hex_to_bytes(hex_name) {
                                if hash.len() == TRUNCATED_HASH_LENGTH {
                                    let mut dest_hash = [0u8; TRUNCATED_HASH_LENGTH];
                                    dest_hash.copy_from_slice(&hash);
                                    if let Ok(mut cache) = self.cache.write() {
                                        cache.remove(&dest_hash);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Remove corrupted ratchet files
                    to_remove.push(path);
                }
            }
        }

        for path in to_remove {
            let _ = fs::remove_file(&path);
        }

        Ok(())
    }

    /// Get the number of known ratchets
    pub fn len(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Check if there are no ratchets
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Identity file persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedIdentity {
    /// Private encryption key bytes (32 bytes)
    pub private_key: Vec<u8>,
    /// Private signing key bytes (32 bytes)
    pub sign_key: Vec<u8>,
}

impl PersistedIdentity {
    /// Create from raw key bytes
    pub fn new(private_key: &[u8], sign_key: &[u8]) -> Self {
        Self {
            private_key: private_key.to_vec(),
            sign_key: sign_key.to_vec(),
        }
    }

    /// Save identity to a file
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }

        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        rmp_serde::encode::write(&mut writer, self).map_err(|e| {
            io::Error::other(format!("MessagePack error: {}", e))
        })?;

        writer.flush()?;
        Ok(())
    }

    /// Load identity from a file
    pub fn load_from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        rmp_serde::from_read(reader).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("MessagePack error: {}", e))
        })
    }
}

/// Convert bytes to hexadecimal string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert hexadecimal string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn test_known_destinations_remember_recall() {
        let temp = temp_dir().join("rns_test_kd");
        let _ = fs::remove_dir_all(&temp);
        let kd = KnownDestinations::new(&temp);

        let dest_hash = [0u8; TRUNCATED_HASH_LENGTH];
        let packet_hash = vec![1u8; 32];
        let public_key = vec![2u8; FULL_PUBLIC_KEY_LENGTH];
        let app_data = Some(b"test app data".as_slice());

        kd.remember(&dest_hash, &packet_hash, &public_key, app_data)
            .unwrap();

        let recalled = kd.recall(&dest_hash).unwrap();
        assert_eq!(recalled.public_key, public_key);
        assert_eq!(recalled.app_data, Some(b"test app data".to_vec()));

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_ratchet_manager() {
        let temp = temp_dir().join("rns_test_ratchet");
        let _ = fs::remove_dir_all(&temp);
        let rm = RatchetManager::new(&temp);

        let dest_hash = [0u8; TRUNCATED_HASH_LENGTH];
        let ratchet = vec![3u8; 32];

        rm.remember(&dest_hash, &ratchet).unwrap();

        let recalled = rm.get(&dest_hash).unwrap();
        assert_eq!(recalled, ratchet);

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_persisted_identity() {
        let temp = temp_dir().join("rns_test_identity");
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();

        let identity = PersistedIdentity::new(&[1u8; 32], &[2u8; 32]);

        let path = temp.join("test_identity");
        identity.save_to_file(&path).unwrap();

        let loaded = PersistedIdentity::load_from_file(&path).unwrap();
        assert_eq!(loaded.private_key, vec![1u8; 32]);
        assert_eq!(loaded.sign_key, vec![2u8; 32]);

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_hex_conversion() {
        let bytes = vec![0xab, 0xcd, 0xef, 0x12, 0x34];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "abcdef1234");

        let converted = hex_to_bytes(&hex).unwrap();
        assert_eq!(converted, bytes);
    }

    #[test]
    fn test_recall_identity() {
        use rand_core::OsRng;
        use crate::identity::PrivateIdentity;

        let temp = temp_dir().join("rns_test_recall_identity");
        let _ = fs::remove_dir_all(&temp);
        let kd = KnownDestinations::new(&temp);

        // Create a real identity and get its public key bytes
        let priv_id = PrivateIdentity::new_from_rand(OsRng);
        let pub_id = priv_id.as_identity();
        let public_key_bytes = pub_id.to_bytes();

        let dest_hash = [0xAAu8; TRUNCATED_HASH_LENGTH];
        let packet_hash = vec![0xBBu8; 32];

        // Remember the destination with proper public key
        kd.remember(&dest_hash, &packet_hash, &public_key_bytes, None)
            .unwrap();

        // Recall should return a valid Identity
        let recalled_identity = kd.recall_identity(&dest_hash);
        assert!(recalled_identity.is_some());

        let recalled = recalled_identity.unwrap();
        // Verify the public keys match
        assert_eq!(recalled.public_key.as_bytes(), pub_id.public_key.as_bytes());
        assert_eq!(recalled.verifying_key.as_bytes(), pub_id.verifying_key.as_bytes());

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_recall_identity_nonexistent() {
        let temp = temp_dir().join("rns_test_recall_identity_nonexistent");
        let _ = fs::remove_dir_all(&temp);
        let kd = KnownDestinations::new(&temp);

        let dest_hash = [0xFFu8; TRUNCATED_HASH_LENGTH];

        // Should return None for non-existent destination
        let recalled = kd.recall_identity(&dest_hash);
        assert!(recalled.is_none());

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_current_ratchet_id() {
        use rand_core::OsRng;
        use crate::identity::{generate_ratchet, ratchet_public_bytes, get_ratchet_id};

        let temp = temp_dir().join("rns_test_current_ratchet_id");
        let _ = fs::remove_dir_all(&temp);
        let rm = RatchetManager::new(&temp);

        let dest_hash = [0x11u8; TRUNCATED_HASH_LENGTH];

        // Generate a ratchet and get its public bytes
        let ratchet_priv = generate_ratchet(OsRng);
        let ratchet_pub = ratchet_public_bytes(&ratchet_priv);

        // Remember the ratchet public key
        rm.remember(&dest_hash, &ratchet_pub).unwrap();

        // Get the ratchet ID from the manager
        let ratchet_id = rm.current_ratchet_id(&dest_hash);
        assert!(ratchet_id.is_some());

        // It should match what get_ratchet_id produces
        let expected_id = get_ratchet_id(&ratchet_pub);
        assert_eq!(ratchet_id.unwrap(), expected_id);

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_current_ratchet_id_nonexistent() {
        let temp = temp_dir().join("rns_test_ratchet_id_nonexistent");
        let _ = fs::remove_dir_all(&temp);
        let rm = RatchetManager::new(&temp);

        let dest_hash = [0x22u8; TRUNCATED_HASH_LENGTH];

        // Should return None for non-existent ratchet
        let ratchet_id = rm.current_ratchet_id(&dest_hash);
        assert!(ratchet_id.is_none());

        let _ = fs::remove_dir_all(&temp);
    }
}
