use alloc::fmt::Write;
use rand_core::CryptoRngCore;
use std::fs::File;
use std::io::{Read, Write as IoWrite};
use std::path::Path;

use ed25519_dalek::{ed25519::signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

use crate::crypt::hkdf::hkdf_into;
use crate::destination::group::GroupKey;

use crate::{
    crypt::fernet::{Fernet, PlainText, Token},
    error::RnsError,
    hash::{AddressHash, Hash},
    packet::{DestinationType, Header, Packet, PacketContext, PacketDataBuffer, PacketType},
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

        // Reject non-ASCII input to prevent panics on UTF-8 boundary slicing
        if !hex_string.is_ascii() {
            return Err(RnsError::IncorrectHash);
        }

        for i in 0..PUBLIC_KEY_LENGTH {
            public_key_bytes[i] = u8::from_str_radix(&hex_string[i * 2..(i * 2) + 2], 16)
                .map_err(|_| RnsError::IncorrectHash)?;
            verifying_key_bytes[i] = u8::from_str_radix(
                &hex_string[PUBLIC_KEY_LENGTH * 2 + (i * 2)..PUBLIC_KEY_LENGTH * 2 + (i * 2) + 2],
                16,
            )
            .map_err(|_| RnsError::IncorrectHash)?;
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

    /// Get the full 32-byte SHA-256 hash of this identity's public key material.
    ///
    /// This is the full hash before truncation to the 16-byte address_hash.
    /// Equivalent to Python's `Identity.get_public_key()` hashed via
    /// `Identity.full_hash()`.
    pub fn full_hash(&self) -> [u8; crate::hash::HASH_SIZE] {
        Hash::new(
            Hash::generator()
                .chain_update(self.public_key.as_bytes())
                .chain_update(self.verifying_key.as_bytes())
                .finalize()
                .into(),
        )
        .to_bytes()
    }

    /// Encrypt plaintext for this identity, matching Python's `Identity.encrypt()`.
    ///
    /// Wire format: `[ephemeral_public_key(32) || Fernet_token]`
    ///
    /// The HKDF salt is the identity's `address_hash`, matching Python's
    /// `Identity.get_salt()` which returns `Identity.hash`.
    pub fn encrypt_for<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, crate::error::RnsError> {
        crate::destination::encrypt_single(rng, &self.public_key, self.address_hash.as_slice(), plaintext)
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
        // Use derived_key directly for Fernet (symmetric encryption).
        // For asymmetric encryption targeting this identity, use Identity::encrypt_for() instead.
        let token = Fernet::new_from_slices(
            &derived_key.as_bytes()[..DERIVED_KEY_LENGTH / 2],
            &derived_key.as_bytes()[DERIVED_KEY_LENGTH / 2..],
            rng,
        )
        .encrypt(PlainText::from(text), out_buf)?;

        let len = token.len();
        Ok(&out_buf[..len])
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

        // Reject non-ASCII input to prevent panics on UTF-8 boundary slicing
        if !hex_string.is_ascii() {
            return Err(RnsError::IncorrectHash);
        }

        for i in 0..PUBLIC_KEY_LENGTH {
            private_key_bytes[i] = u8::from_str_radix(&hex_string[i * 2..(i * 2) + 2], 16)
                .map_err(|_| RnsError::IncorrectHash)?;
            sign_key_bytes[i] = u8::from_str_radix(
                &hex_string[PUBLIC_KEY_LENGTH * 2 + (i * 2)..PUBLIC_KEY_LENGTH * 2 + (i * 2) + 2],
                16,
            )
            .map_err(|_| RnsError::IncorrectHash)?;
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

    /// Decrypt ciphertext encrypted for this identity, matching Python's `Identity.decrypt()`.
    ///
    /// Extracts the ephemeral public key from the first 32 bytes, performs ECDH,
    /// derives the Fernet key via HKDF, and decrypts. No ratchet support — use
    /// `SingleInputDestination::decrypt()` for ratchet-aware decryption.
    pub fn decrypt_for<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, crate::error::RnsError> {
        let result = crate::destination::decrypt_single(
            rng,
            self.as_identity().address_hash.as_slice(),
            self,
            ciphertext,
            None,
            false,
        )?;
        Ok(result.plaintext)
    }

    pub fn derive_key(&self, public_key: &PublicKey, salt: Option<&[u8]>) -> DerivedKey {
        DerivedKey::new_from_private_key(&self.private_key, public_key, salt)
    }

    /// Create a proof packet for a received data packet.
    ///
    /// Matches Python's `Identity.prove(packet, destination)`.
    /// Signs the packet hash and creates a proof with either implicit
    /// (signature only) or explicit (hash + signature) format.
    ///
    /// # Arguments
    ///
    /// * `packet` - The packet to prove receipt of
    /// * `use_implicit_proof` - If true, proof contains only the signature (64 bytes).
    ///   If false, proof contains hash + signature (96 bytes).
    pub fn prove(&self, packet: &Packet, use_implicit_proof: bool) -> Packet {
        let hash = packet.hash();
        let signature = self.sign(hash.as_slice());

        let mut packet_data = PacketDataBuffer::new();
        if !use_implicit_proof {
            packet_data.safe_write(hash.as_slice());
        }
        packet_data.safe_write(&signature.to_bytes());

        Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new_from_hash(&hash),
            transport: None,
            context: PacketContext::None,
            data: packet_data,
            ratchet_id: None,
        }
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

/// Identity type for GROUP destinations.
///
/// Wraps an optional `GroupKey` for symmetric encryption. The key is optional
/// because GROUP IN destinations may create it later via `create_keys()`.
///
/// For address hashing, GROUP destinations use name-only hashing (like PLAIN) —
/// `as_address_hash_slice()` returns `&[]` so the symmetric key does not
/// contribute to the destination address hash.
#[derive(Clone, Debug)]
pub struct GroupIdentity {
    key: Option<GroupKey>,
}

impl GroupIdentity {
    /// Create a GroupIdentity with no key (key created later via `create_keys()`).
    pub fn new() -> Self {
        Self { key: None }
    }

    /// Create a GroupIdentity with an existing group key.
    pub fn with_key(key: GroupKey) -> Self {
        Self { key: Some(key) }
    }

    /// Get a reference to the group key, if set.
    pub fn key(&self) -> Option<&GroupKey> {
        self.key.as_ref()
    }

    /// Set or replace the group key.
    pub fn set_key(&mut self, key: GroupKey) {
        self.key = Some(key);
    }
}

impl Default for GroupIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl HashIdentity for GroupIdentity {
    fn as_address_hash_slice(&self) -> &[u8] {
        // GROUP destinations compute address hash from name only (like PLAIN).
        // The symmetric key does not contribute to the address hash.
        &[]
    }
}

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

    /// Reconstruct a `DerivedKey` from raw bytes.
    ///
    /// Used when building standalone encryption closures that need to
    /// capture key material without holding a reference to the original key.
    pub fn from_raw(key: [u8; DERIVED_KEY_LENGTH]) -> Self {
        Self { key }
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

    /// Helper to build a minimal test Packet for proof tests.
    fn make_test_packet() -> Packet {
        use crate::hash::AddressHash;
        use crate::packet::{DestinationType, Header, PacketDataBuffer, PacketType};

        let mut data = PacketDataBuffer::new();
        data.safe_write(b"test payload");

        Packet {
            header: Header {
                packet_type: PacketType::Data,
                destination_type: DestinationType::Single,
                ..Default::default()
            },
            destination: AddressHash::new([0xAB; 16]),
            data,
            ..Default::default()
        }
    }

    #[test]
    fn test_prove_implicit_proof() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let packet = make_test_packet();

        let proof = identity.prove(&packet, true);

        // Implicit proof: signature only (64 bytes)
        assert_eq!(proof.data.as_slice().len(), ed25519_dalek::SIGNATURE_LENGTH);
        assert_eq!(proof.header.packet_type, PacketType::Proof);
        assert_eq!(proof.header.destination_type, DestinationType::Single);
    }

    #[test]
    fn test_prove_explicit_proof() {
        use crate::hash::HASH_SIZE;

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let packet = make_test_packet();

        let proof = identity.prove(&packet, false);

        // Explicit proof: hash (32 bytes) + signature (64 bytes) = 96 bytes
        assert_eq!(
            proof.data.as_slice().len(),
            HASH_SIZE + ed25519_dalek::SIGNATURE_LENGTH
        );

        // First 32 bytes should match the packet hash
        let hash = packet.hash();
        assert_eq!(&proof.data.as_slice()[..HASH_SIZE], hash.as_slice());
    }

    #[test]
    fn test_prove_destination_is_truncated_hash() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let packet = make_test_packet();

        let proof = identity.prove(&packet, true);

        // Proof packet's destination should be the truncated hash of the proved packet
        let expected = AddressHash::new_from_hash(&packet.hash());
        assert_eq!(proof.destination.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_prove_signature_validates() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let packet = make_test_packet();
        let hash = packet.hash();

        // Test implicit proof signature
        let implicit_proof = identity.prove(&packet, true);
        let sig_bytes = implicit_proof.data.as_slice();
        let sig = ed25519_dalek::Signature::from_slice(sig_bytes).expect("valid signature bytes");
        identity.verify(hash.as_slice(), &sig).expect("implicit proof signature should validate");

        // Test explicit proof signature
        let explicit_proof = identity.prove(&packet, false);
        let sig_bytes = &explicit_proof.data.as_slice()[32..]; // skip hash
        let sig = ed25519_dalek::Signature::from_slice(sig_bytes).expect("valid signature bytes");
        identity.verify(hash.as_slice(), &sig).expect("explicit proof signature should validate");
    }

    // =========================================================================
    // encrypt_for / decrypt_for Tests
    // =========================================================================

    #[test]
    fn test_encrypt_for_decrypt_for_roundtrip() {
        let private_id = PrivateIdentity::new_from_rand(OsRng);
        let public_id = private_id.as_identity();
        let plaintext = b"Hello from encrypt_for!";

        let ciphertext = public_id.encrypt_for(OsRng, plaintext).unwrap();
        let decrypted = private_id.decrypt_for(OsRng, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_for_decrypt_for_empty() {
        let private_id = PrivateIdentity::new_from_rand(OsRng);
        let public_id = private_id.as_identity();

        let ciphertext = public_id.encrypt_for(OsRng, b"").unwrap();
        let decrypted = private_id.decrypt_for(OsRng, &ciphertext).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_for_wrong_identity_fails() {
        let id1 = PrivateIdentity::new_from_rand(OsRng);
        let id2 = PrivateIdentity::new_from_rand(OsRng);

        let ciphertext = id1.as_identity().encrypt_for(OsRng, b"secret").unwrap();
        let result = id2.decrypt_for(OsRng, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_for_too_short_ciphertext_fails() {
        let private_id = PrivateIdentity::new_from_rand(OsRng);
        let result = private_id.decrypt_for(OsRng, &[0u8; 16]);

        assert!(result.is_err());
    }

    // =========================================================================
    // full_hash Tests
    // =========================================================================

    #[test]
    fn test_full_hash_length() {
        let private_id = PrivateIdentity::new_from_rand(OsRng);
        let full = private_id.as_identity().full_hash();
        assert_eq!(full.len(), crate::hash::HASH_SIZE);
    }

    #[test]
    fn test_full_hash_prefix_matches_address_hash() {
        let private_id = PrivateIdentity::new_from_rand(OsRng);
        let public_id = private_id.as_identity();

        let full = public_id.full_hash();
        let addr = public_id.address_hash.as_slice();

        // address_hash is the first 16 bytes of the full 32-byte hash
        assert_eq!(&full[..addr.len()], addr);
    }

    #[test]
    fn test_full_hash_deterministic() {
        let private_id = PrivateIdentity::new_from_rand(OsRng);
        let public_id = private_id.as_identity();

        let h1 = public_id.full_hash();
        let h2 = public_id.full_hash();

        assert_eq!(h1, h2);
    }

    // =========================================================================
    // EncryptIdentity / DecryptIdentity symmetric round-trip
    // =========================================================================

    #[test]
    fn test_encrypt_identity_symmetric_roundtrip() {
        // Verify that EncryptIdentity for Identity and DecryptIdentity for PrivateIdentity
        // work together with a shared derived key (symmetric/link-level encryption).
        let private_id = PrivateIdentity::new_from_rand(OsRng);
        let public_id = *private_id.as_identity();

        // Create a shared derived key (simulating link key exchange)
        let peer = PrivateIdentity::new_from_rand(OsRng);
        let derived_key = private_id.derive_key(&peer.as_identity().public_key, None);

        let plaintext = b"symmetric encryption test";
        let mut enc_buf = vec![0u8; plaintext.len() + 128];
        let mut dec_buf = vec![0u8; plaintext.len() + 128];

        let encrypted = public_id.encrypt(OsRng, plaintext, &derived_key, &mut enc_buf).unwrap();
        let decrypted = private_id.decrypt(OsRng, encrypted, &derived_key, &mut dec_buf).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted);
    }

    // =========================================================================
    // Hex parsing error handling (panic prevention)
    // =========================================================================

    #[test]
    fn test_identity_hex_string_invalid_chars_returns_error() {
        // 128 hex chars but with invalid characters — should return Err, not panic
        let bad_hex = "zz".repeat(64);
        assert!(Identity::new_from_hex_string(&bad_hex).is_err());
    }

    #[test]
    fn test_identity_hex_string_non_ascii_returns_error() {
        let non_ascii = "ñ".repeat(64);
        assert!(Identity::new_from_hex_string(&non_ascii).is_err());
    }

    #[test]
    fn test_private_identity_hex_string_invalid_chars_returns_error() {
        let bad_hex = "gg".repeat(64);
        assert!(PrivateIdentity::new_from_hex_string(&bad_hex).is_err());
    }

    #[test]
    fn test_private_identity_hex_string_non_ascii_returns_error() {
        let non_ascii = "ö".repeat(64);
        assert!(PrivateIdentity::new_from_hex_string(&non_ascii).is_err());
    }

    // =========================================================================
    // GroupIdentity Tests
    // =========================================================================

    #[test]
    fn test_group_identity_new_has_no_key() {
        let gi = GroupIdentity::new();
        assert!(gi.key().is_none());
    }

    #[test]
    fn test_group_identity_with_key() {
        let key = GroupKey::generate(OsRng);
        let gi = GroupIdentity::with_key(key);
        assert!(gi.key().is_some());
    }

    #[test]
    fn test_group_identity_set_key() {
        let mut gi = GroupIdentity::new();
        assert!(gi.key().is_none());
        gi.set_key(GroupKey::generate(OsRng));
        assert!(gi.key().is_some());
    }

    #[test]
    fn test_group_identity_hash_is_empty() {
        let gi = GroupIdentity::new();
        assert_eq!(gi.as_address_hash_slice(), &[] as &[u8]);

        let gi_with_key = GroupIdentity::with_key(GroupKey::generate(OsRng));
        assert_eq!(gi_with_key.as_address_hash_slice(), &[] as &[u8]);
    }

    #[test]
    fn test_group_identity_default() {
        let gi = GroupIdentity::default();
        assert!(gi.key().is_none());
    }
}
