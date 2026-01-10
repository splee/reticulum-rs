//! GROUP destination type implementation
//!
//! GROUP destinations use symmetric encryption with a pre-shared key,
//! allowing multiple parties to communicate using the same key.
//!
//! The key format is compatible with Python Reticulum's Token class:
//! - 64 bytes total for AES-256-CBC mode
//! - First 32 bytes: signing key (HMAC-SHA256)
//! - Last 32 bytes: encryption key (AES-256)

use rand_core::CryptoRngCore;
use sha2::Digest;

use crate::crypt::fernet::{Fernet, PlainText, Token};
use crate::error::RnsError;
use crate::hash::{AddressHash, Hash};

/// Length of the group key in bytes (64 bytes for AES-256-CBC mode)
/// This matches Python's Token.generate_key() for AES_256_CBC
pub const GROUP_KEY_LENGTH: usize = 64;

/// Length of each half of the key (32 bytes each for signing and encryption)
const GROUP_KEY_HALF: usize = GROUP_KEY_LENGTH / 2;

/// A symmetric key for GROUP destinations
/// Compatible with Python Reticulum's Token class (AES-256-CBC mode)
#[derive(Clone)]
pub struct GroupKey {
    /// Signing key (first half - 32 bytes for HMAC-SHA256)
    signing_key: [u8; GROUP_KEY_HALF],
    /// Encryption key (second half - 32 bytes for AES-256)
    encryption_key: [u8; GROUP_KEY_HALF],
    /// Full key bytes for storage
    full_key: [u8; GROUP_KEY_LENGTH],
}

impl GroupKey {
    /// Generate a new random group key (64 bytes for AES-256-CBC)
    pub fn generate<R: CryptoRngCore>(mut rng: R) -> Self {
        let mut full_key = [0u8; GROUP_KEY_LENGTH];
        rng.fill_bytes(&mut full_key);

        let mut signing_key = [0u8; GROUP_KEY_HALF];
        let mut encryption_key = [0u8; GROUP_KEY_HALF];

        signing_key.copy_from_slice(&full_key[..GROUP_KEY_HALF]);
        encryption_key.copy_from_slice(&full_key[GROUP_KEY_HALF..]);

        Self {
            signing_key,
            encryption_key,
            full_key,
        }
    }

    /// Create a group key from bytes (expects 64 bytes for AES-256-CBC)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RnsError> {
        if bytes.len() != GROUP_KEY_LENGTH {
            return Err(RnsError::InvalidArgument);
        }

        let mut full_key = [0u8; GROUP_KEY_LENGTH];
        full_key.copy_from_slice(bytes);

        let mut signing_key = [0u8; GROUP_KEY_HALF];
        let mut encryption_key = [0u8; GROUP_KEY_HALF];

        signing_key.copy_from_slice(&full_key[..GROUP_KEY_HALF]);
        encryption_key.copy_from_slice(&full_key[GROUP_KEY_HALF..]);

        Ok(Self {
            signing_key,
            encryption_key,
            full_key,
        })
    }

    /// Get the key as bytes (64 bytes)
    pub fn as_bytes(&self) -> &[u8; GROUP_KEY_LENGTH] {
        &self.full_key
    }

    /// Encrypt data with this group key
    pub fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        plaintext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let fernet = Fernet::new_from_slices(&self.signing_key, &self.encryption_key, rng);

        let token = fernet.encrypt(PlainText::from(plaintext), out_buf)?;
        Ok(token.as_bytes())
    }

    /// Decrypt data with this group key
    pub fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        ciphertext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let fernet = Fernet::new_from_slices(&self.signing_key, &self.encryption_key, rng);

        let token = Token::from(ciphertext);
        let verified_token = fernet.verify(token)?;
        let plaintext = fernet.decrypt(verified_token, out_buf)?;

        Ok(plaintext.as_slice())
    }

    /// Get the hash of this key for identification
    pub fn hash(&self) -> Hash {
        Hash::new(Hash::generator().chain_update(&self.full_key).finalize().into())
    }
}

impl std::fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupKey([REDACTED])")
    }
}

/// A GROUP destination that uses symmetric encryption
#[derive(Clone)]
pub struct GroupDestination {
    /// The group key for encryption/decryption
    key: GroupKey,
    /// Address hash for this destination
    address_hash: AddressHash,
    /// Application name
    app_name: String,
    /// Aspects
    aspects: String,
}

impl GroupDestination {
    /// Create a new group destination with a generated key
    pub fn new<R: CryptoRngCore>(rng: R, app_name: &str, aspects: &str) -> Self {
        let key = GroupKey::generate(rng);
        let address_hash = Self::compute_address_hash(&key, app_name, aspects);

        Self {
            key,
            address_hash,
            app_name: app_name.to_string(),
            aspects: aspects.to_string(),
        }
    }

    /// Create a group destination with an existing key
    pub fn with_key(key: GroupKey, app_name: &str, aspects: &str) -> Self {
        let address_hash = Self::compute_address_hash(&key, app_name, aspects);

        Self {
            key,
            address_hash,
            app_name: app_name.to_string(),
            aspects: aspects.to_string(),
        }
    }

    /// Compute the address hash for a group destination
    fn compute_address_hash(key: &GroupKey, app_name: &str, aspects: &str) -> AddressHash {
        // For GROUP destinations, the address hash is derived from the key hash and name
        let name_hash = Hash::new(
            Hash::generator()
                .chain_update(app_name.as_bytes())
                .chain_update(b".")
                .chain_update(aspects.as_bytes())
                .finalize()
                .into(),
        );

        let key_hash = key.hash();

        AddressHash::new_from_hash(&Hash::new(
            Hash::generator()
                .chain_update(&name_hash.as_bytes()[..10])
                .chain_update(key_hash.as_bytes())
                .finalize()
                .into(),
        ))
    }

    /// Get the address hash
    pub fn address_hash(&self) -> &AddressHash {
        &self.address_hash
    }

    /// Get the group key
    pub fn key(&self) -> &GroupKey {
        &self.key
    }

    /// Encrypt data for this group
    pub fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        plaintext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        self.key.encrypt(rng, plaintext, out_buf)
    }

    /// Decrypt data from this group
    pub fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        ciphertext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        self.key.decrypt(rng, ciphertext, out_buf)
    }
}

impl std::fmt::Debug for GroupDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupDestination")
            .field("address_hash", &self.address_hash)
            .field("app_name", &self.app_name)
            .field("aspects", &self.aspects)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_group_key_generation() {
        let key = GroupKey::generate(OsRng);
        assert_eq!(key.as_bytes().len(), GROUP_KEY_LENGTH);
    }

    #[test]
    fn test_group_key_from_bytes() {
        let original = GroupKey::generate(OsRng);
        let restored = GroupKey::from_bytes(original.as_bytes()).unwrap();
        assert_eq!(original.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_group_encrypt_decrypt() {
        let key = GroupKey::generate(OsRng);
        let plaintext = b"Hello, GROUP destination!";

        let mut encrypt_buf = [0u8; 256];
        let ciphertext = key.encrypt(OsRng, plaintext, &mut encrypt_buf).unwrap();

        let mut decrypt_buf = [0u8; 256];
        let decrypted = key.decrypt(OsRng, ciphertext, &mut decrypt_buf).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_group_destination_creation() {
        let dest = GroupDestination::new(OsRng, "test_app", "group.test");
        assert!(!dest.address_hash().as_slice().is_empty());
    }

    #[test]
    fn test_group_destination_encrypt_decrypt() {
        let dest = GroupDestination::new(OsRng, "test_app", "group.test");
        let plaintext = b"Secret group message";

        let mut encrypt_buf = [0u8; 256];
        let ciphertext = dest.encrypt(OsRng, plaintext, &mut encrypt_buf).unwrap();

        let mut decrypt_buf = [0u8; 256];
        let decrypted = dest.decrypt(OsRng, ciphertext, &mut decrypt_buf).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_same_key_produces_same_address() {
        let key = GroupKey::generate(OsRng);

        let dest1 = GroupDestination::with_key(key.clone(), "app", "aspect");
        let dest2 = GroupDestination::with_key(key, "app", "aspect");

        assert_eq!(dest1.address_hash().as_slice(), dest2.address_hash().as_slice());
    }
}
