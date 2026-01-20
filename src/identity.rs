use alloc::fmt::Write;
use hkdf::Hkdf;
use rand_core::CryptoRngCore;

use ed25519_dalek::{ed25519::signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

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
        if data.len() <= PUBLIC_KEY_LENGTH {
            return Err(RnsError::InvalidArgument);
        }

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
    pub fn new(shared_key: &SharedSecret, salt: Option<&[u8]>) -> Self {
        let mut key = [0u8; DERIVED_KEY_LENGTH];

        let _ = Hkdf::<Sha256>::new(salt, shared_key.as_bytes()).expand(&[], &mut key[..]);

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
}
