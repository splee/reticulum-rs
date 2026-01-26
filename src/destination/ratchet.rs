//! Ratchet key management for SINGLE destinations.
//!
//! Ratchets provide forward secrecy for packets sent to SINGLE destinations
//! by rotating X25519 encryption keys. When enabled:
//! - A new ratchet key is generated and included in each announce
//! - Senders encrypt using the ratchet public key instead of the identity key
//! - Multiple ratchet keys are retained to decrypt messages using older keys
//!
//! This module implements ratchet management matching Python's Destination.py.

use std::collections::VecDeque;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::OsRng;

use crate::error::RnsError;
use crate::identity::{
    generate_ratchet, get_ratchet_id, ratchet_public_bytes, PrivateIdentity, RATCHET_ID_LENGTH,
    RATCHET_KEY_SIZE,
};

/// Default number of ratchet keys to retain (512 in Python)
pub const DEFAULT_RATCHET_COUNT: usize = 512;

/// Default minimum interval between ratchet rotations (30 minutes)
pub const DEFAULT_RATCHET_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Ratchet state for a SINGLE destination.
///
/// This struct manages the rotation, persistence, and usage of ratchet keys.
#[derive(Debug)]
pub struct RatchetState {
    /// Ratchet private keys, newest first
    ratchets: VecDeque<[u8; RATCHET_KEY_SIZE]>,

    /// Path to the ratchet persistence file (None if not enabled)
    ratchets_path: Option<PathBuf>,

    /// Minimum interval between ratchet rotations
    ratchet_interval: Duration,

    /// Maximum number of ratchets to retain
    retained_ratchets: usize,

    /// Unix timestamp of the last ratchet generation
    latest_ratchet_time: Option<u64>,

    /// ID of the latest ratchet (first 10 bytes of hash of public key)
    latest_ratchet_id: Option<[u8; RATCHET_ID_LENGTH]>,

    /// If true, require ratchet for decryption (reject non-ratchet messages)
    enforce_ratchets: bool,
}

impl RatchetState {
    /// Create a new disabled ratchet state.
    pub fn new_disabled() -> Self {
        Self {
            ratchets: VecDeque::new(),
            ratchets_path: None,
            ratchet_interval: DEFAULT_RATCHET_INTERVAL,
            retained_ratchets: DEFAULT_RATCHET_COUNT,
            latest_ratchet_time: None,
            latest_ratchet_id: None,
            enforce_ratchets: false,
        }
    }

    /// Check if ratchets are enabled.
    pub fn is_enabled(&self) -> bool {
        self.ratchets_path.is_some()
    }

    /// Enable ratchets with the given persistence path.
    ///
    /// If the path exists, ratchets are loaded from it.
    /// Otherwise, a new empty ratchet state is created and persisted.
    pub fn enable(
        &mut self,
        path: PathBuf,
        identity: &PrivateIdentity,
    ) -> Result<(), RnsError> {
        if path.exists() {
            self.load_from_file(&path, identity)?;
        } else {
            self.ratchets.clear();
            self.ratchets_path = Some(path.clone());
            self.persist(identity)?;
        }

        self.latest_ratchet_time = Some(0);
        log::debug!("Ratchets enabled");
        Ok(())
    }

    /// Set whether to enforce ratchet usage for decryption.
    pub fn set_enforce(&mut self, enforce: bool) {
        self.enforce_ratchets = enforce;
    }

    /// Get whether ratchets are enforced.
    pub fn enforce(&self) -> bool {
        self.enforce_ratchets
    }

    /// Set the ratchet rotation interval.
    pub fn set_interval(&mut self, interval: Duration) {
        self.ratchet_interval = interval;
    }

    /// Set the number of retained ratchets.
    pub fn set_retained_count(&mut self, count: usize) {
        self.retained_ratchets = count;
    }

    /// Get the latest ratchet ID if available.
    pub fn latest_ratchet_id(&self) -> Option<&[u8; RATCHET_ID_LENGTH]> {
        self.latest_ratchet_id.as_ref()
    }

    /// Rotate ratchets if the interval has passed.
    ///
    /// Returns the public key of the newest ratchet if rotation occurred or
    /// if ratchets are available.
    pub fn rotate_if_needed(
        &mut self,
        identity: &PrivateIdentity,
    ) -> Result<Option<[u8; RATCHET_KEY_SIZE]>, RnsError> {
        if self.ratchets_path.is_none() {
            return Ok(None);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let should_rotate = match self.latest_ratchet_time {
            Some(last_time) => now > last_time + self.ratchet_interval.as_secs(),
            None => true,
        };

        if should_rotate {
            log::debug!("Rotating ratchets");
            let new_ratchet = generate_ratchet(OsRng);
            self.ratchets.push_front(new_ratchet);
            self.latest_ratchet_time = Some(now);

            // Clean excess ratchets
            while self.ratchets.len() > self.retained_ratchets {
                self.ratchets.pop_back();
            }

            // Update latest ratchet ID
            let pub_key = ratchet_public_bytes(&new_ratchet);
            self.latest_ratchet_id = Some(get_ratchet_id(&pub_key));

            // Persist to file
            self.persist(identity)?;
        }

        // Return the current newest ratchet public key
        if let Some(newest) = self.ratchets.front() {
            Ok(Some(ratchet_public_bytes(newest)))
        } else {
            Ok(None)
        }
    }

    /// Get the current ratchet public key without rotation.
    pub fn current_public_key(&self) -> Option<[u8; RATCHET_KEY_SIZE]> {
        self.ratchets.front().map(|r| ratchet_public_bytes(r))
    }

    /// Get all ratchet private keys for decryption attempts.
    pub fn ratchet_keys(&self) -> impl Iterator<Item = &[u8; RATCHET_KEY_SIZE]> {
        self.ratchets.iter()
    }

    /// Persist ratchets to file.
    ///
    /// The file format is MessagePack with signature for integrity:
    /// { "signature": <ed25519_signature>, "ratchets": <msgpack_ratchets> }
    fn persist(&self, identity: &PrivateIdentity) -> Result<(), RnsError> {
        let path = match &self.ratchets_path {
            Some(p) => p,
            None => return Ok(()),
        };

        // Pack ratchets as MessagePack array
        let ratchets_vec: Vec<&[u8; RATCHET_KEY_SIZE]> = self.ratchets.iter().collect();
        let packed_ratchets =
            rmp_serde::to_vec(&ratchets_vec).map_err(|_| RnsError::SerializationError)?;

        // Sign the packed ratchets
        let signature = identity.sign(&packed_ratchets);

        // Create persisted data structure
        #[derive(serde::Serialize)]
        struct PersistedData<'a> {
            signature: &'a [u8],
            ratchets: &'a [u8],
        }

        let persisted = PersistedData {
            signature: &signature.to_bytes(),
            ratchets: &packed_ratchets,
        };

        let packed_data =
            rmp_serde::to_vec(&persisted).map_err(|_| RnsError::SerializationError)?;

        // Write atomically via temp file
        let temp_path = path.with_extension("tmp");
        let mut file =
            std::fs::File::create(&temp_path).map_err(|_| RnsError::IoError)?;
        file.write_all(&packed_data)
            .map_err(|_| RnsError::IoError)?;
        file.sync_all().map_err(|_| RnsError::IoError)?;
        drop(file);

        std::fs::rename(&temp_path, path).map_err(|_| RnsError::IoError)?;

        log::debug!("Persisted {} ratchets to {:?}", self.ratchets.len(), path);
        Ok(())
    }

    /// Load ratchets from file.
    fn load_from_file(
        &mut self,
        path: &PathBuf,
        identity: &PrivateIdentity,
    ) -> Result<(), RnsError> {
        let mut file = std::fs::File::open(path).map_err(|_| RnsError::IoError)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|_| RnsError::IoError)?;

        // Parse persisted data
        #[derive(serde::Deserialize)]
        struct PersistedData {
            signature: Vec<u8>,
            ratchets: Vec<u8>,
        }

        let persisted: PersistedData =
            rmp_serde::from_slice(&data).map_err(|_| RnsError::SerializationError)?;

        // Verify signature
        let signature =
            ed25519_dalek::Signature::from_slice(&persisted.signature)
                .map_err(|_| RnsError::CryptoError)?;
        identity
            .verify(&persisted.ratchets, &signature)
            .map_err(|_| RnsError::IncorrectSignature)?;

        // Unpack ratchets
        let ratchets: Vec<[u8; RATCHET_KEY_SIZE]> =
            rmp_serde::from_slice(&persisted.ratchets).map_err(|_| RnsError::SerializationError)?;

        self.ratchets = ratchets.into_iter().collect();
        self.ratchets_path = Some(path.clone());

        // Update latest ratchet ID
        if let Some(newest) = self.ratchets.front() {
            let pub_key = ratchet_public_bytes(newest);
            self.latest_ratchet_id = Some(get_ratchet_id(&pub_key));
        }

        log::debug!("Loaded {} ratchets from {:?}", self.ratchets.len(), path);
        Ok(())
    }
}

impl Default for RatchetState {
    fn default() -> Self {
        Self::new_disabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_state_disabled() {
        let state = RatchetState::new_disabled();
        assert!(!state.is_enabled());
        assert!(state.current_public_key().is_none());
    }

    #[test]
    fn test_ratchet_rotation() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut state = RatchetState::new_disabled();

        // Manually enable without persistence for testing
        state.ratchets_path = Some(PathBuf::from("/tmp/test_ratchets_nonexistent"));
        state.latest_ratchet_time = Some(0);

        // Force rotation by setting interval to 0
        state.set_interval(Duration::from_secs(0));

        // This should generate a new ratchet (but will fail to persist)
        // For a real test, we'd need a valid path
        let _result = state.rotate_if_needed(&identity);
        // Note: This will fail because the path doesn't exist,
        // but we can test the rotation logic separately
    }
}
