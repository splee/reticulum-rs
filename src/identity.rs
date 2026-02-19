use alloc::fmt::Write;
use rand_core::CryptoRngCore;
use std::fs::File;
use std::io::{Read, Write as IoWrite};
use std::path::Path;

use ed25519_dalek::{ed25519::signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

use crate::crypt::hkdf::hkdf_into;

use crate::{
    crypt::fernet::{Fernet, PlainText, Token},
    error::RnsError,
    hash::{AddressHash, Hash},
};

pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// X25519 key size in bytes (matches Python's ratchet key size)
pub const RATCHET_KEY_SIZE: usize = 32;

/// Ratchet ID length in bytes (NAME_HASH_LENGTH / 8 from Python)
pub const RATCHET_ID_LENGTH: usize = 10;

#[cfg(feature = "fernet-aes128")]
pub const DERIVED_KEY_LENGTH: usize = 256 / 8;

#[cfg(not(feature = "fernet-aes128"))]
pub const DERIVED_KEY_LENGTH: usize = 512 / 8;

// =============================================================================
// Ratchet Key Functions
// =============================================================================
// These functions provide forward secrecy for SINGLE destinations by rotating
// encryption keys. The ratchet public key is included in announces when enabled.

/// Generate a new ratchet private key.
///
/// Returns the 32-byte X25519 private key bytes.
/// This matches Python's `Identity._generate_ratchet()`.
pub fn generate_ratchet<R: CryptoRngCore>(mut rng: R) -> [u8; RATCHET_KEY_SIZE] {
    let private_key = StaticSecret::random_from_rng(&mut rng);
    *private_key.as_bytes()
}

/// Derive the public key bytes from a ratchet private key.
///
/// Returns the 32-byte X25519 public key bytes.
/// This matches Python's `Identity._ratchet_public_bytes()`.
pub fn ratchet_public_bytes(ratchet_priv: &[u8; RATCHET_KEY_SIZE]) -> [u8; RATCHET_KEY_SIZE] {
    let private_key = StaticSecret::from(*ratchet_priv);
    let public_key = PublicKey::from(&private_key);
    *public_key.as_bytes()
}

/// Calculate the ratchet ID from a ratchet public key.
///
/// Returns the first 10 bytes of the SHA-256 hash of the public key.
/// This matches Python's `Identity._get_ratchet_id()`.
pub fn get_ratchet_id(ratchet_pub: &[u8; RATCHET_KEY_SIZE]) -> [u8; RATCHET_ID_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(ratchet_pub);
    let hash = hasher.finalize();

    let mut id = [0u8; RATCHET_ID_LENGTH];
    id.copy_from_slice(&hash[..RATCHET_ID_LENGTH]);
    id
}

/// Perform X25519 key exchange with a ratchet private key and peer public key.
///
/// Returns the derived shared secret that can be used for encryption.
pub fn ratchet_exchange(
    ratchet_priv: &[u8; RATCHET_KEY_SIZE],
    peer_pub: &[u8; RATCHET_KEY_SIZE],
) -> [u8; RATCHET_KEY_SIZE] {
    let private_key = StaticSecret::from(*ratchet_priv);
    let peer_public = PublicKey::from(*peer_pub);
    let shared = private_key.diffie_hellman(&peer_public);
    *shared.as_bytes()
}

pub trait EncryptIdentity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError>;
}

pub trait DecryptIdentity {
    fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        data: &[u8],
        derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError>;
}

pub trait HashIdentity {
    fn as_address_hash_slice(&self) -> &[u8];
}

#[derive(Copy, Clone)]
pub struct Identity {
    pub public_key: PublicKey,
    pub verifying_key: VerifyingKey,
    pub address_hash: AddressHash,
}

impl Identity {
    pub fn new(public_key: PublicKey, verifying_key: VerifyingKey) -> Self {
        let hash = Hash::new(
            Hash::generator()
                .chain_update(public_key.as_bytes())
                .chain_update(verifying_key.as_bytes())
                .finalize()
                .into(),
        );

        let address_hash = AddressHash::new_from_hash(&hash);

        Self {
            public_key,
            verifying_key,
            address_hash,
        }
    }

    pub fn new_from_slices(public_key: &[u8], verifying_key: &[u8]) -> Self {
        let public_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(public_key);
            PublicKey::from(key_data)
        };

        let verifying_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(verifying_key);
            VerifyingKey::from_bytes(&key_data).unwrap_or_default()
        };

        Self::new(public_key, verifying_key)
    }

    pub fn new_from_hex_string(hex_string: &str) -> Result<Self, RnsError> {
        if hex_string.len() < PUBLIC_KEY_LENGTH * 2 * 2 {
            return Err(RnsError::IncorrectHash);
        }

        let mut public_key_bytes = [0u8; PUBLIC_KEY_LENGTH];
        let mut verifying_key_bytes = [0u8; PUBLIC_KEY_LENGTH];

        for i in 0..PUBLIC_KEY_LENGTH {
            public_key_bytes[i] = u8::from_str_radix(&hex_string[i * 2..(i * 2) + 2], 16).unwrap();
            verifying_key_bytes[i] = u8::from_str_radix(
                &hex_string[PUBLIC_KEY_LENGTH * 2 + (i * 2)..PUBLIC_KEY_LENGTH * 2 + (i * 2) + 2],
                16,
            )
            .unwrap();
        }

        Ok(Self::new_from_slices(
            &public_key_bytes[..],
            &verifying_key_bytes[..],
        ))
    }

    pub fn to_hex_string(&self) -> String {
        let mut hex_string = String::with_capacity((PUBLIC_KEY_LENGTH * 2) * 2);

        for byte in self.public_key.as_bytes() {
            write!(&mut hex_string, "{:02x}", byte).unwrap();
        }

        for byte in self.verifying_key.as_bytes() {
            write!(&mut hex_string, "{:02x}", byte).unwrap();
        }

        hex_string
    }

    pub fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.public_key.as_bytes()
    }

    pub fn verifying_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.verifying_key.as_bytes()
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), RnsError> {
        self.verifying_key
            .verify_strict(data, signature)
            .map_err(|_| RnsError::IncorrectSignature)
    }

    pub fn derive_key<R: CryptoRngCore + Copy>(&self, rng: R, salt: Option<&[u8]>) -> DerivedKey {
        DerivedKey::new_from_ephemeral_key(rng, &self.public_key, salt)
    }

    /// Create a public Identity from 64-byte raw data.
    ///
    /// Format: [32 bytes X25519 public key][32 bytes Ed25519 verifying key]
    ///
    /// This matches Python's public identity format used in announces and
    /// stored in known_destinations.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RnsError> {
        if bytes.len() < PUBLIC_KEY_LENGTH * 2 {
            return Err(RnsError::IncorrectHash);
        }

        Ok(Self::new_from_slices(
            &bytes[0..PUBLIC_KEY_LENGTH],
            &bytes[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2],
        ))
    }

    /// Load a public Identity from a file.
    ///
    /// The file should contain 64 bytes of raw binary data in the format:
    /// [32 bytes X25519 public key][32 bytes Ed25519 verifying key]
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RnsError> {
        let mut file = File::open(path).map_err(|_| RnsError::IoError)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| RnsError::IoError)?;

        Self::from_bytes(&bytes)
    }

    /// Export the public identity as 64 bytes.
    ///
    /// Format: [32 bytes X25519 public key][32 bytes Ed25519 verifying key]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH * 2] {
        let mut bytes = [0u8; PUBLIC_KEY_LENGTH * 2];
        bytes[0..PUBLIC_KEY_LENGTH].copy_from_slice(self.public_key.as_bytes());
        bytes[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2]
            .copy_from_slice(self.verifying_key.as_bytes());
        bytes
    }

    /// Save the public identity to a file.
    pub fn to_file(&self, path: impl AsRef<Path>) -> Result<(), RnsError> {
        let mut file = File::create(path).map_err(|_| RnsError::IoError)?;
        file.write_all(&self.to_bytes()).map_err(|_| RnsError::IoError)
    }
}

impl Default for Identity {
    fn default() -> Self {
        let empty_key = [0u8; PUBLIC_KEY_LENGTH];
        Self::new(PublicKey::from(empty_key), VerifyingKey::default())
    }
}

impl HashIdentity for Identity {
    fn as_address_hash_slice(&self) -> &[u8] {
        self.address_hash.as_slice()
    }
}

impl EncryptIdentity for Identity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let mut out_offset = 0;
        let ephemeral_key = EphemeralSecret::random_from_rng(rng);
        {
            let ephemeral_public = PublicKey::from(&ephemeral_key);
            let ephemeral_public_bytes = ephemeral_public.as_bytes();

            if out_buf.len() >= ephemeral_public_bytes.len() {
                out_buf[..ephemeral_public_bytes.len()].copy_from_slice(ephemeral_public_bytes);
                out_offset += ephemeral_public_bytes.len();
            } else {
                return Err(RnsError::InvalidArgument);
            }
        }

        // Split derived key into signing and encryption keys (matching Python's Fernet key handling).
        // For AES-256 (default): 64-byte key split into 32-byte signing + 32-byte encryption.
        // For AES-128 (feature): 32-byte key split into 16-byte signing + 16-byte encryption.
        let token = Fernet::new_from_slices(
            &derived_key.as_bytes()[..DERIVED_KEY_LENGTH / 2],
            &derived_key.as_bytes()[DERIVED_KEY_LENGTH / 2..],
            rng,
        )
        .encrypt(PlainText::from(text), &mut out_buf[out_offset..])?;

        out_offset += token.as_bytes().len();

        Ok(&out_buf[..out_offset])
    }
}

pub struct EmptyIdentity;

impl HashIdentity for EmptyIdentity {
    fn as_address_hash_slice(&self) -> &[u8] {
        &[]
    }
}

impl EncryptIdentity for EmptyIdentity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        _rng: R,
        text: &[u8],
        _derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        if text.len() > out_buf.len() {
            return Err(RnsError::OutOfMemory);
        }

        let result = &mut out_buf[..text.len()];
        result.copy_from_slice(text);
        Ok(result)
    }
}

impl DecryptIdentity for EmptyIdentity {
    fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        _rng: R,
        data: &[u8],
        _derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        if data.len() > out_buf.len() {
            return Err(RnsError::OutOfMemory);
        }

        let result = &mut out_buf[..data.len()];
        result.copy_from_slice(data);
        Ok(result)
    }
}

#[derive(Clone)]
pub struct PrivateIdentity {
    identity: Identity,
    private_key: StaticSecret,
    sign_key: SigningKey,
}

impl PrivateIdentity {
    pub fn new(private_key: StaticSecret, sign_key: SigningKey) -> Self {
        Self {
            identity: Identity::new((&private_key).into(), sign_key.verifying_key()),
            private_key,
            sign_key,
        }
    }

    pub fn new_from_rand<R: CryptoRngCore>(mut rng: R) -> Self {
        let sign_key = SigningKey::generate(&mut rng);
        let private_key = StaticSecret::random_from_rng(rng);

        Self::new(private_key, sign_key)
    }

    pub fn new_from_name(name: &str) -> Self {
        let hash = Hash::new_from_slice(name.as_bytes());
        let private_key = StaticSecret::from(hash.to_bytes());

        let hash = Hash::new_from_slice(hash.as_bytes());
        let sign_key = SigningKey::from_bytes(hash.as_bytes());

        Self::new(private_key, sign_key)
    }

    pub fn new_from_hex_string(hex_string: &str) -> Result<Self, RnsError> {
        if hex_string.len() < PUBLIC_KEY_LENGTH * 2 * 2 {
            return Err(RnsError::IncorrectHash);
        }

        let mut private_key_bytes = [0u8; PUBLIC_KEY_LENGTH];
        let mut sign_key_bytes = [0u8; PUBLIC_KEY_LENGTH];

        for i in 0..PUBLIC_KEY_LENGTH {
            private_key_bytes[i] = u8::from_str_radix(&hex_string[i * 2..(i * 2) + 2], 16).unwrap();
            sign_key_bytes[i] = u8::from_str_radix(
                &hex_string[PUBLIC_KEY_LENGTH * 2 + (i * 2)..PUBLIC_KEY_LENGTH * 2 + (i * 2) + 2],
                16,
            )
            .unwrap();
        }

        Ok(Self::new(
            StaticSecret::from(private_key_bytes),
            SigningKey::from_bytes(&sign_key_bytes),
        ))
    }

    /// Create from raw 64-byte binary data (Python-compatible format).
    ///
    /// Format: [32 bytes X25519 private key][32 bytes Ed25519 signing key seed]
    pub fn new_from_bytes(bytes: &[u8]) -> Result<Self, RnsError> {
        if bytes.len() < PUBLIC_KEY_LENGTH * 2 {
            return Err(RnsError::IncorrectHash);
        }

        let mut prv_bytes = [0u8; PUBLIC_KEY_LENGTH];
        let mut sign_bytes = [0u8; PUBLIC_KEY_LENGTH];
        prv_bytes.copy_from_slice(&bytes[0..PUBLIC_KEY_LENGTH]);
        sign_bytes.copy_from_slice(&bytes[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2]);

        Ok(Self::new(
            StaticSecret::from(prv_bytes),
            SigningKey::from_bytes(&sign_bytes),
        ))
    }

    pub fn sign_key(&self) -> &SigningKey {
        &self.sign_key
    }

    pub fn into(&self) -> &Identity {
        &self.identity
    }

    pub fn as_identity(&self) -> &Identity {
        &self.identity
    }

    pub fn address_hash(&self) -> &AddressHash {
        &self.identity.address_hash
    }

    pub fn to_hex_string(&self) -> String {
        let mut hex_string = String::with_capacity((PUBLIC_KEY_LENGTH * 2) * 2);

        for byte in self.private_key.as_bytes() {
            write!(&mut hex_string, "{:02x}", byte).unwrap();
        }

        for byte in self.sign_key.as_bytes() {
            write!(&mut hex_string, "{:02x}", byte).unwrap();
        }

        hex_string
    }

    /// Export as raw 64-byte binary data (Python-compatible format).
    ///
    /// Format: [32 bytes X25519 private key][32 bytes Ed25519 signing key seed]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH * 2] {
        let mut bytes = [0u8; PUBLIC_KEY_LENGTH * 2];
        bytes[0..PUBLIC_KEY_LENGTH].copy_from_slice(self.private_key.as_bytes());
        bytes[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2].copy_from_slice(self.sign_key.as_bytes());
        bytes
    }

    /// Load a private identity from a file (Python-compatible format).
    ///
    /// The file should contain 64 bytes of raw binary data.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RnsError> {
        let mut file = File::open(path).map_err(|_| RnsError::IoError)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| RnsError::IoError)?;

        Self::new_from_bytes(&bytes)
    }

    /// Save the private identity to a file.
    ///
    /// Writes 64 bytes of raw binary data in Python-compatible format.
    pub fn to_file(&self, path: impl AsRef<Path>) -> Result<(), RnsError> {
        let mut file = File::create(path).map_err(|_| RnsError::IoError)?;
        file.write_all(&self.to_bytes()).map_err(|_| RnsError::IoError)
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), RnsError> {
        self.identity.verify(data, signature)
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        self.sign_key.try_sign(data).expect("signature")
    }

    pub fn exchange(&self, public_key: &PublicKey) -> SharedSecret {
        self.private_key.diffie_hellman(public_key)
    }

    pub fn derive_key(&self, public_key: &PublicKey, salt: Option<&[u8]>) -> DerivedKey {
        DerivedKey::new_from_private_key(&self.private_key, public_key, salt)
    }
}

impl HashIdentity for PrivateIdentity {
    fn as_address_hash_slice(&self) -> &[u8] {
        self.identity.address_hash.as_slice()
    }
}

impl EncryptIdentity for PrivateIdentity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let mut out_offset = 0;

        let token = Fernet::new_from_slices(
            &derived_key.as_bytes()[..DERIVED_KEY_LENGTH / 2],
            &derived_key.as_bytes()[DERIVED_KEY_LENGTH / 2..],
            rng,
        )
        .encrypt(PlainText::from(text), &mut out_buf[out_offset..])?;

        out_offset += token.len();

        Ok(&out_buf[..out_offset])
    }
}

impl DecryptIdentity for PrivateIdentity {
    fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        data: &[u8],
        derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let fernet = Fernet::new_from_slices(
            &derived_key.as_bytes()[..DERIVED_KEY_LENGTH / 2],
            &derived_key.as_bytes()[DERIVED_KEY_LENGTH / 2..],
            rng,
        );

        let token = Token::from(data);

        let token = fernet.verify(token)?;

        let plain_text = fernet.decrypt(token, out_buf)?;

        Ok(plain_text.as_slice())
    }
}

pub struct GroupIdentity {}

pub struct DerivedKey {
    key: [u8; DERIVED_KEY_LENGTH],
}

impl DerivedKey {
    /// Create a new derived key from a shared secret using Python-compatible HKDF.
    ///
    /// Uses the custom HKDF implementation that matches Python's RNS/Cryptography/HKDF.py.
    pub fn new(shared_key: &SharedSecret, salt: Option<&[u8]>) -> Self {
        let mut key = [0u8; DERIVED_KEY_LENGTH];

        // Use Python-compatible HKDF with empty context (matching Python's default)
        hkdf_into(shared_key.as_bytes(), salt, None, &mut key[..]);

        Self { key }
    }

    pub fn new_empty() -> Self {
        Self {
            key: [0u8; DERIVED_KEY_LENGTH],
        }
    }

    pub fn new_from_private_key(
        priv_key: &StaticSecret,
        pub_key: &PublicKey,
        salt: Option<&[u8]>,
    ) -> Self {
        Self::new(&priv_key.diffie_hellman(pub_key), salt)
    }

    pub fn new_from_ephemeral_key<R: CryptoRngCore + Copy>(
        rng: R,
        pub_key: &PublicKey,
        salt: Option<&[u8]>,
    ) -> Self {
        let secret = EphemeralSecret::random_from_rng(rng);
        let shared_key = secret.diffie_hellman(pub_key);
        Self::new(&shared_key, salt)
    }

    pub fn as_bytes(&self) -> &[u8; DERIVED_KEY_LENGTH] {
        &self.key
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key[..]
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn private_identity_hex_string() {
        let original_id = PrivateIdentity::new_from_rand(OsRng);
        let original_hex = original_id.to_hex_string();

        let actual_id =
            PrivateIdentity::new_from_hex_string(&original_hex).expect("valid identity");

        assert_eq!(
            actual_id.private_key.as_bytes(),
            original_id.private_key.as_bytes()
        );

        assert_eq!(
            actual_id.sign_key.as_bytes(),
            original_id.sign_key.as_bytes()
        );
    }

    #[test]
    fn test_generate_ratchet() {
        let ratchet1 = generate_ratchet(OsRng);
        let ratchet2 = generate_ratchet(OsRng);

        // Each generated ratchet should be unique
        assert_ne!(ratchet1, ratchet2);

        // Should be 32 bytes
        assert_eq!(ratchet1.len(), RATCHET_KEY_SIZE);
    }

    #[test]
    fn test_ratchet_public_bytes() {
        let ratchet_priv = generate_ratchet(OsRng);
        let ratchet_pub = ratchet_public_bytes(&ratchet_priv);

        // Public key should be 32 bytes
        assert_eq!(ratchet_pub.len(), RATCHET_KEY_SIZE);

        // Same private key should produce same public key
        let ratchet_pub2 = ratchet_public_bytes(&ratchet_priv);
        assert_eq!(ratchet_pub, ratchet_pub2);

        // Different private key should produce different public key
        let ratchet_priv2 = generate_ratchet(OsRng);
        let ratchet_pub3 = ratchet_public_bytes(&ratchet_priv2);
        assert_ne!(ratchet_pub, ratchet_pub3);
    }

    #[test]
    fn test_get_ratchet_id() {
        let ratchet_priv = generate_ratchet(OsRng);
        let ratchet_pub = ratchet_public_bytes(&ratchet_priv);
        let ratchet_id = get_ratchet_id(&ratchet_pub);

        // Ratchet ID should be 10 bytes
        assert_eq!(ratchet_id.len(), RATCHET_ID_LENGTH);

        // Same public key should produce same ratchet ID
        let ratchet_id2 = get_ratchet_id(&ratchet_pub);
        assert_eq!(ratchet_id, ratchet_id2);
    }

    #[test]
    fn test_ratchet_exchange() {
        // Generate two ratchet key pairs (simulating two parties)
        let alice_priv = generate_ratchet(OsRng);
        let alice_pub = ratchet_public_bytes(&alice_priv);

        let bob_priv = generate_ratchet(OsRng);
        let bob_pub = ratchet_public_bytes(&bob_priv);

        // Both parties should derive the same shared secret
        let alice_shared = ratchet_exchange(&alice_priv, &bob_pub);
        let bob_shared = ratchet_exchange(&bob_priv, &alice_pub);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_identity_to_bytes_from_bytes_roundtrip() {
        // Create a private identity and extract its public identity
        let private_id = PrivateIdentity::new_from_rand(OsRng);
        let public_id = private_id.as_identity();

        // Convert to bytes
        let bytes = public_id.to_bytes();
        assert_eq!(bytes.len(), PUBLIC_KEY_LENGTH * 2); // 64 bytes

        // Convert back from bytes
        let recovered = Identity::from_bytes(&bytes).expect("valid identity bytes");

        // Verify keys match
        assert_eq!(
            recovered.public_key.as_bytes(),
            public_id.public_key.as_bytes()
        );
        assert_eq!(
            recovered.verifying_key.as_bytes(),
            public_id.verifying_key.as_bytes()
        );
    }

    #[test]
    fn test_identity_from_bytes_invalid_length() {
        // Too short
        let short_bytes = [0u8; 32];
        let result = Identity::from_bytes(&short_bytes);
        assert!(result.is_err());

        // Empty
        let empty_bytes: [u8; 0] = [];
        let result = Identity::from_bytes(&empty_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_identity_file_roundtrip() {
        use std::fs;
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_identity_roundtrip.bin");

        // Create identity and save to file
        let private_id = PrivateIdentity::new_from_rand(OsRng);
        let public_id = private_id.as_identity();
        public_id.to_file(&test_file).expect("save identity");

        // Load from file
        let loaded = Identity::from_file(&test_file).expect("load identity");

        // Verify keys match
        assert_eq!(
            loaded.public_key.as_bytes(),
            public_id.public_key.as_bytes()
        );
        assert_eq!(
            loaded.verifying_key.as_bytes(),
            public_id.verifying_key.as_bytes()
        );

        // Cleanup
        fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_private_identity_to_bytes_from_bytes_roundtrip() {
        let original = PrivateIdentity::new_from_rand(OsRng);

        // Convert to bytes
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 64); // 32 bytes private key + 32 bytes sign key

        // Convert back
        let recovered = PrivateIdentity::new_from_bytes(&bytes).expect("valid private identity");

        // Verify keys match
        assert_eq!(
            recovered.private_key.as_bytes(),
            original.private_key.as_bytes()
        );
        assert_eq!(recovered.sign_key.as_bytes(), original.sign_key.as_bytes());
    }

    #[test]
    fn test_private_identity_file_roundtrip() {
        use std::fs;
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_private_identity_roundtrip.bin");

        // Create and save
        let original = PrivateIdentity::new_from_rand(OsRng);
        original.to_file(&test_file).expect("save private identity");

        // Load
        let loaded = PrivateIdentity::from_file(&test_file).expect("load private identity");

        // Verify
        assert_eq!(
            loaded.private_key.as_bytes(),
            original.private_key.as_bytes()
        );
        assert_eq!(loaded.sign_key.as_bytes(), original.sign_key.as_bytes());

        // Cleanup
        fs::remove_file(&test_file).ok();
    }
}
