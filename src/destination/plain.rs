//! PLAIN destination type implementation
//!
//! PLAIN destinations do not use encryption or authentication.
//! They are used for unencrypted broadcast or multicast communication.
//!
//! Key characteristics:
//! - No identity (cannot hold an identity)
//! - No encryption/decryption (data passed through as-is)
//! - Address hash derived only from app name and aspects

use sha2::Digest;

use crate::hash::{AddressHash, Hash};

/// A PLAIN destination that does not use encryption
#[derive(Clone, Debug)]
pub struct PlainDestination {
    /// Address hash for this destination
    address_hash: AddressHash,
    /// Application name
    app_name: String,
    /// Aspects
    aspects: String,
    /// Full name (app_name.aspects)
    full_name: String,
}

impl PlainDestination {
    /// Create a new PLAIN destination
    ///
    /// PLAIN destinations do not require an identity - their address hash
    /// is computed solely from the app name and aspects.
    pub fn new(app_name: &str, aspects: &str) -> Self {
        let full_name = format!("{}.{}", app_name, aspects);
        let address_hash = Self::compute_address_hash(app_name, aspects);

        Self {
            address_hash,
            app_name: app_name.to_string(),
            aspects: aspects.to_string(),
            full_name,
        }
    }

    /// Compute the address hash for a PLAIN destination
    ///
    /// For PLAIN destinations, the hash is computed as:
    /// truncated_hash(full_hash(expand_name(None, app_name, aspects)))
    fn compute_address_hash(app_name: &str, aspects: &str) -> AddressHash {
        // Compute name hash: full_hash("app_name.aspects")
        let full_name = format!("{}.{}", app_name, aspects);
        let name_hash = Hash::new(
            Hash::generator()
                .chain_update(full_name.as_bytes())
                .finalize()
                .into(),
        );

        // For PLAIN destinations (no identity), address hash = truncated(full_hash(name_hash))
        // Note: In Python, NAME_HASH_LENGTH//8 = 10 bytes are used from name_hash
        let name_hash_truncated = &name_hash.as_bytes()[..10];

        AddressHash::new_from_hash(&Hash::new(
            Hash::generator()
                .chain_update(name_hash_truncated)
                .finalize()
                .into(),
        ))
    }

    /// Get the address hash
    pub fn address_hash(&self) -> &AddressHash {
        &self.address_hash
    }

    /// Get the full name (app_name.aspects)
    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    /// Get the app name
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Get the aspects
    pub fn aspects(&self) -> &str {
        &self.aspects
    }

    /// "Encrypt" data for this PLAIN destination (no-op, returns input)
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        plaintext.to_vec()
    }

    /// "Decrypt" data from this PLAIN destination (no-op, returns input)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        ciphertext.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_destination_creation() {
        let dest = PlainDestination::new("test_app", "plain.test");
        assert!(!dest.address_hash().as_slice().is_empty());
        assert_eq!(dest.app_name(), "test_app");
        assert_eq!(dest.aspects(), "plain.test");
        assert_eq!(dest.full_name(), "test_app.plain.test");
    }

    #[test]
    fn test_plain_encrypt_decrypt() {
        let dest = PlainDestination::new("test_app", "plain.test");
        let data = b"Hello, PLAIN world!";

        let encrypted = dest.encrypt(data);
        let decrypted = dest.decrypt(&encrypted);

        // PLAIN destinations don't encrypt - data should be unchanged
        assert_eq!(encrypted, data);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_same_name_produces_same_address() {
        let dest1 = PlainDestination::new("app", "aspect");
        let dest2 = PlainDestination::new("app", "aspect");

        assert_eq!(dest1.address_hash().as_slice(), dest2.address_hash().as_slice());
    }

    #[test]
    fn test_different_name_produces_different_address() {
        let dest1 = PlainDestination::new("app1", "aspect");
        let dest2 = PlainDestination::new("app2", "aspect");

        assert_ne!(dest1.address_hash().as_slice(), dest2.address_hash().as_slice());
    }
}
