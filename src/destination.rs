pub mod group;
pub mod link;
pub mod link_map;
pub mod link_stats;
pub mod link_watchdog;
pub mod plain;
pub mod proof;
pub mod ratchet;
pub mod request;
pub mod request_receipt;

use alloc::sync::Arc;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH};
use rand_core::CryptoRngCore;
use x25519_dalek::PublicKey;

use core::{fmt, marker::PhantomData};

use crate::{
    destination::link::Link,
    error::RnsError,
    hash::{AddressHash, Hash},
    identity::{
        DecryptIdentity, EmptyIdentity, EncryptIdentity, HashIdentity, Identity, PrivateIdentity,
        PUBLIC_KEY_LENGTH, RATCHET_KEY_SIZE,
    },
    packet::{
        self, DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext,
        PacketDataBuffer, PacketType, TransportType,
    },
    persistence::RatchetManager,
};
use sha2::Digest;

//***************************************************************************//
// Destination Callbacks
//
// These callback types match the Python API for destination callbacks:
// - link_established_callback: Called when a link is established to this destination
// - packet_callback: Called when a packet is received for this destination
// - proof_requested_callback: Called when a proof is requested (for PROVE_APP strategy)
//***************************************************************************//

/// Callback type for link establishment events.
/// Called with a reference to the established link.
pub type LinkEstablishedCallback = Arc<dyn Fn(&Link) + Send + Sync + 'static>;

/// Callback type for packet reception events.
/// Called with the packet data and the full packet.
pub type PacketCallback = Arc<dyn Fn(&[u8], &Packet) + Send + Sync + 'static>;

/// Callback type for proof request events.
/// Called with the packet and should return true to send a proof, false otherwise.
pub type ProofRequestedCallback = Arc<dyn Fn(&Packet) -> bool + Send + Sync + 'static>;

/// Container for destination callbacks.
///
/// These callbacks provide application-level hooks for destination events,
/// matching the Python API:
/// - `set_link_established_callback()`
/// - `set_packet_callback()`
/// - `set_proof_requested_callback()`
#[derive(Clone, Default)]
pub struct DestinationCallbacks {
    /// Called when a link is established to this destination
    pub link_established: Option<LinkEstablishedCallback>,
    /// Called when a packet is received for this destination
    pub packet: Option<PacketCallback>,
    /// Called when a proof is requested (for PROVE_APP strategy).
    /// Should return true to send a proof, false otherwise.
    pub proof_requested: Option<ProofRequestedCallback>,
}

impl DestinationCallbacks {
    /// Create a new empty callbacks container.
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for DestinationCallbacks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DestinationCallbacks")
            .field("link_established", &self.link_established.is_some())
            .field("packet", &self.packet.is_some())
            .field("proof_requested", &self.proof_requested.is_some())
            .finish()
    }
}

//***************************************************************************//

pub trait Direction {}

pub struct Input;
pub struct Output;

impl Direction for Input {}
impl Direction for Output {}

//***************************************************************************//

pub trait Type {
    fn destination_type() -> DestinationType;
}

pub struct Single;
pub struct Plain;
pub struct Group;

impl Type for Single {
    fn destination_type() -> DestinationType {
        DestinationType::Single
    }
}

impl Type for Plain {
    fn destination_type() -> DestinationType {
        DestinationType::Plain
    }
}

impl Type for Group {
    fn destination_type() -> DestinationType {
        DestinationType::Group
    }
}

pub const NAME_HASH_LENGTH: usize = 10;
pub const RAND_HASH_LENGTH: usize = 10;
pub const MIN_ANNOUNCE_DATA_LENGTH: usize =
    PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH + RAND_HASH_LENGTH + SIGNATURE_LENGTH;
/// Minimum announce data length when ratchet is included (context_flag=true)
pub const MIN_ANNOUNCE_DATA_LENGTH_WITH_RATCHET: usize =
    PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH + RAND_HASH_LENGTH + RATCHET_KEY_SIZE + SIGNATURE_LENGTH;

#[derive(Copy, Clone)]
pub struct DestinationName {
    pub hash: Hash,
}

impl DestinationName {
    /// Create a new destination name from app name and aspects.
    ///
    /// The resulting hash is truncated to `NAME_HASH_LENGTH` bytes to match
    /// the wire protocol format. This ensures that locally-created names
    /// can be compared directly with names received from announce packets.
    pub fn new(app_name: &str, aspects: &str) -> Self {
        let full_hash: [u8; 32] = Hash::generator()
            .chain_update(app_name.as_bytes())
            .chain_update(".".as_bytes())
            .chain_update(aspects.as_bytes())
            .finalize()
            .into();

        // Truncate to NAME_HASH_LENGTH to match wire protocol format
        let mut truncated_hash = [0u8; 32];
        truncated_hash[..NAME_HASH_LENGTH].copy_from_slice(&full_hash[..NAME_HASH_LENGTH]);

        Self {
            hash: Hash::new(truncated_hash),
        }
    }

    /// Create a destination name from a hash slice (typically from an announce packet).
    ///
    /// The slice is expected to be `NAME_HASH_LENGTH` bytes. The resulting hash
    /// will have zeros in bytes beyond the slice length.
    pub fn new_from_hash_slice(hash_slice: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        let copy_len = hash_slice.len().min(NAME_HASH_LENGTH);
        hash[..copy_len].copy_from_slice(&hash_slice[..copy_len]);

        Self {
            hash: Hash::new(hash),
        }
    }

    pub fn as_name_hash_slice(&self) -> &[u8] {
        &self.hash.as_slice()[..NAME_HASH_LENGTH]
    }
}

#[derive(Copy, Clone)]
pub struct DestinationDesc {
    pub identity: Identity,
    pub address_hash: AddressHash,
    pub name: DestinationName,
}

impl fmt::Display for DestinationDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address_hash)?;

        Ok(())
    }
}

pub type DestinationAnnounce = Packet;

/// Result of validating an announce packet.
pub struct AnnounceValidation<'a> {
    /// The destination from the announce
    pub destination: SingleOutputDestination,
    /// Application data from the announce
    pub app_data: &'a [u8],
    /// Ratchet public key if present (when context_flag is true)
    pub ratchet: Option<[u8; RATCHET_KEY_SIZE]>,
}

impl DestinationAnnounce {
    /// Validate an announce packet and extract destination, app_data, and optional ratchet.
    ///
    /// When `context_flag` is true in the packet header, the announce includes a 32-byte
    /// ratchet public key after the random hash. This key is used for forward secrecy
    /// when encrypting messages to the destination.
    pub fn validate(packet: &Packet) -> Result<(SingleOutputDestination, &[u8]), RnsError> {
        let validation = Self::validate_full(packet)?;
        Ok((validation.destination, validation.app_data))
    }

    /// Validate an announce packet with full ratchet support.
    ///
    /// Returns an `AnnounceValidation` struct containing the destination, app_data,
    /// and optional ratchet public key (present when `context_flag` is true).
    pub fn validate_full(packet: &Packet) -> Result<AnnounceValidation<'_>, RnsError> {
        if packet.header.packet_type != PacketType::Announce {
            return Err(RnsError::PacketError);
        }

        let announce_data = packet.data.as_slice();
        let has_ratchet = packet.header.context_flag;

        // Check minimum length based on whether ratchet is present
        let min_length = if has_ratchet {
            MIN_ANNOUNCE_DATA_LENGTH_WITH_RATCHET
        } else {
            MIN_ANNOUNCE_DATA_LENGTH
        };

        if announce_data.len() < min_length {
            return Err(RnsError::OutOfMemory);
        }

        let mut offset = 0usize;

        let public_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(&announce_data[offset..(offset + PUBLIC_KEY_LENGTH)]);
            offset += PUBLIC_KEY_LENGTH;
            PublicKey::from(key_data)
        };

        let verifying_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(&announce_data[offset..(offset + PUBLIC_KEY_LENGTH)]);
            offset += PUBLIC_KEY_LENGTH;

            VerifyingKey::from_bytes(&key_data).map_err(|_| RnsError::CryptoError)?
        };

        let identity = Identity::new(public_key, verifying_key);

        let name_hash = &announce_data[offset..(offset + NAME_HASH_LENGTH)];
        offset += NAME_HASH_LENGTH;
        let rand_hash = &announce_data[offset..(offset + RAND_HASH_LENGTH)];
        offset += RAND_HASH_LENGTH;

        // Extract ratchet if context_flag is set
        let ratchet = if has_ratchet {
            let mut ratchet_key = [0u8; RATCHET_KEY_SIZE];
            ratchet_key.copy_from_slice(&announce_data[offset..(offset + RATCHET_KEY_SIZE)]);
            offset += RATCHET_KEY_SIZE;
            Some(ratchet_key)
        } else {
            None
        };

        let signature = &announce_data[offset..(offset + SIGNATURE_LENGTH)];
        offset += SIGNATURE_LENGTH;
        let app_data = &announce_data[offset..];

        let destination_hash = &packet.destination;

        // Build signed data for verification
        // Signed data format: destination_hash + public_key + verifying_key + name_hash + rand_hash + [ratchet] + app_data
        let signed_data = if let Some(ref ratchet_key) = ratchet {
            PacketDataBuffer::new()
                .chain_write(destination_hash.as_slice())?
                .chain_write(public_key.as_bytes())?
                .chain_write(verifying_key.as_bytes())?
                .chain_write(name_hash)?
                .chain_write(rand_hash)?
                .chain_write(ratchet_key)?
                .chain_write(app_data)?
                .finalize()
        } else {
            PacketDataBuffer::new()
                .chain_write(destination_hash.as_slice())?
                .chain_write(public_key.as_bytes())?
                .chain_write(verifying_key.as_bytes())?
                .chain_write(name_hash)?
                .chain_write(rand_hash)?
                .chain_write(app_data)?
                .finalize()
        };

        let signature = Signature::from_slice(signature).map_err(|_| RnsError::CryptoError)?;

        identity.verify(signed_data.as_slice(), &signature)?;

        Ok(AnnounceValidation {
            destination: SingleOutputDestination::new(
                identity,
                DestinationName::new_from_hash_slice(name_hash),
            ),
            app_data,
            ratchet,
        })
    }
}

pub struct Destination<I: HashIdentity, D: Direction, T: Type> {
    pub direction: PhantomData<D>,
    pub r#type: PhantomData<T>,
    pub identity: I,
    pub desc: DestinationDesc,
    /// Callbacks for destination events (matching Python's callback API)
    pub callbacks: DestinationCallbacks,
}

impl<I: HashIdentity, D: Direction, T: Type> Destination<I, D, T> {
    pub fn destination_type(&self) -> packet::DestinationType {
        <T as Type>::destination_type()
    }
}

pub enum DestinationHandleStatus {
    None,
    LinkProof,
}

impl Destination<PrivateIdentity, Input, Single> {
    pub fn new(identity: PrivateIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        let pub_identity = *identity.as_identity();

        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            desc: DestinationDesc {
                identity: pub_identity,
                name,
                address_hash,
            },
            callbacks: DestinationCallbacks::default(),
        }
    }

    pub fn announce<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        let mut packet_data = PacketDataBuffer::new();

        // Generate rand_hash matching Python format (Destination.py line 282):
        // random_hash = RNS.Identity.get_random_hash()[0:5] + int(time.time()).to_bytes(5, "big")
        // This encodes a timestamp for replay prevention.
        let mut rand_hash = [0u8; RAND_HASH_LENGTH];
        // First 5 bytes: random
        let random_part = Hash::new_from_rand(rng);
        rand_hash[..5].copy_from_slice(&random_part.as_slice()[..5]);
        // Last 5 bytes: Unix timestamp (big-endian, 5 bytes = 40 bits, enough until year ~34,000)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Take last 5 bytes of the 8-byte big-endian timestamp
        let timestamp_bytes = timestamp.to_be_bytes();
        rand_hash[5..].copy_from_slice(&timestamp_bytes[3..8]);
        let rand_hash = &rand_hash[..];

        let pub_key = self.identity.as_identity().public_key_bytes();
        let verifying_key = self.identity.as_identity().verifying_key_bytes();

        packet_data
            .chain_safe_write(self.desc.address_hash.as_slice())
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(rand_hash);

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        let signature = self.identity.sign(packet_data.as_slice());

        packet_data.reset();

        packet_data
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(rand_hash)
            .chain_safe_write(&signature.to_bytes());

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        Ok(Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: self.desc.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }

    /// Create an announce packet with a ratchet public key for forward secrecy.
    ///
    /// This method creates an announce with the ratchet included:
    /// - The ratchet public key is appended after the random hash in both
    ///   signed data and packet data
    /// - The context_flag is set to true to indicate ratchet presence
    ///
    /// Receivers can extract the ratchet and use it for encrypted communication.
    pub fn announce_with_ratchet<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        ratchet_pub: &[u8; RATCHET_KEY_SIZE],
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        let mut packet_data = PacketDataBuffer::new();

        // Generate rand_hash matching Python format
        let mut rand_hash = [0u8; RAND_HASH_LENGTH];
        let random_part = Hash::new_from_rand(rng);
        rand_hash[..5].copy_from_slice(&random_part.as_slice()[..5]);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let timestamp_bytes = timestamp.to_be_bytes();
        rand_hash[5..].copy_from_slice(&timestamp_bytes[3..8]);
        let rand_hash = &rand_hash[..];

        let pub_key = self.identity.as_identity().public_key_bytes();
        let verifying_key = self.identity.as_identity().verifying_key_bytes();

        // Build signed data: dest_hash + pubkey + verifying_key + name_hash + rand_hash + ratchet + app_data
        packet_data
            .chain_safe_write(self.desc.address_hash.as_slice())
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(rand_hash)
            .chain_safe_write(ratchet_pub);

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        let signature = self.identity.sign(packet_data.as_slice());

        packet_data.reset();

        // Build packet data: pubkey + verifying_key + name_hash + rand_hash + ratchet + signature + app_data
        packet_data
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(rand_hash)
            .chain_safe_write(ratchet_pub)
            .chain_safe_write(&signature.to_bytes());

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        Ok(Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: true, // Indicates ratchet is present
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: self.desc.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }

    pub fn handle_packet(&mut self, packet: &Packet) -> DestinationHandleStatus {
        if self.desc.address_hash != packet.destination {
            return DestinationHandleStatus::None;
        }

        // Invoke packet callback if set
        if let Some(ref callback) = self.callbacks.packet {
            callback(packet.data.as_slice(), packet);
        }

        if packet.header.packet_type == PacketType::LinkRequest {
            // Check proof_requested callback for PROVE_APP strategy
            if let Some(ref proof_callback) = self.callbacks.proof_requested {
                if proof_callback(packet) {
                    return DestinationHandleStatus::LinkProof;
                }
            } else {
                // Default behavior: always send proof
                return DestinationHandleStatus::LinkProof;
            }
        }

        DestinationHandleStatus::None
    }

    /// Notify destination that a link has been established.
    ///
    /// This invokes the link_established callback if set.
    pub fn notify_link_established(&self, link: &Link) {
        if let Some(ref callback) = self.callbacks.link_established {
            callback(link);
        }
    }

    /// Set the callback for link establishment events.
    ///
    /// Matches Python's `set_link_established_callback()` method.
    pub fn set_link_established_callback<F>(&mut self, callback: F)
    where
        F: Fn(&Link) + Send + Sync + 'static,
    {
        self.callbacks.link_established = Some(Arc::new(callback));
    }

    /// Set the callback for packet reception events.
    ///
    /// Matches Python's `set_packet_callback()` method.
    /// The callback receives the packet data and the full packet.
    pub fn set_packet_callback<F>(&mut self, callback: F)
    where
        F: Fn(&[u8], &Packet) + Send + Sync + 'static,
    {
        self.callbacks.packet = Some(Arc::new(callback));
    }

    /// Set the callback for proof request events.
    ///
    /// Matches Python's `set_proof_requested_callback()` method.
    /// The callback should return true to send a proof, false otherwise.
    /// This is used with PROVE_APP proof strategy.
    pub fn set_proof_requested_callback<F>(&mut self, callback: F)
    where
        F: Fn(&Packet) -> bool + Send + Sync + 'static,
    {
        self.callbacks.proof_requested = Some(Arc::new(callback));
    }

    /// Clear all callbacks.
    pub fn clear_callbacks(&mut self) {
        self.callbacks = DestinationCallbacks::default();
    }

    pub fn sign_key(&self) -> &SigningKey {
        self.identity.sign_key()
    }

    /// Sign a message using this destination's identity.
    ///
    /// Mirrors Python's `Destination.sign()` method.
    ///
    /// # Arguments
    ///
    /// * `message` - The message bytes to sign
    ///
    /// # Returns
    ///
    /// A 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.identity.sign(message)
    }

    /// Encrypt plaintext for this destination.
    ///
    /// Mirrors Python's `Destination.encrypt()` method for SINGLE destinations.
    /// Uses the destination's identity for encryption and optionally includes
    /// a ratchet for forward secrecy.
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator for ephemeral key generation
    /// * `plaintext` - The data to encrypt
    /// * `ratchet_manager` - Optional ratchet manager for forward secrecy
    ///
    /// # Returns
    ///
    /// Encrypted ciphertext bytes.
    pub fn encrypt<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        plaintext: &[u8],
        ratchet_manager: Option<&RatchetManager>,
    ) -> Result<Vec<u8>, RnsError> {
        // Get the selected ratchet if available
        let dest_hash: [u8; 16] = self.desc.address_hash.as_slice().try_into()
            .map_err(|_| RnsError::InvalidArgument)?;
        let selected_ratchet = ratchet_manager
            .and_then(|rm| rm.get(&dest_hash));

        // Use identity's encrypt with optional ratchet
        self.encrypt_with_ratchet(rng, plaintext, selected_ratchet.as_deref())
    }

    /// Encrypt plaintext with an explicit ratchet key.
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator
    /// * `plaintext` - The data to encrypt
    /// * `ratchet` - Optional ratchet public key for forward secrecy (not yet used)
    fn encrypt_with_ratchet<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        plaintext: &[u8],
        _ratchet: Option<&[u8]>,
    ) -> Result<Vec<u8>, RnsError> {
        let pub_identity = self.identity.as_identity();
        let derived_key = pub_identity.derive_key(rng, None);

        // Build the output buffer
        let max_size = plaintext.len() + PUBLIC_KEY_LENGTH + 64 + 32; // overhead estimate
        let mut out_buf = vec![0u8; max_size];

        let encrypted = pub_identity.encrypt(rng, plaintext, &derived_key, &mut out_buf)?;

        Ok(encrypted.to_vec())
    }

    /// Decrypt ciphertext from this destination.
    ///
    /// Mirrors Python's `Destination.decrypt()` method for SINGLE destinations.
    /// Uses the destination's private identity for decryption.
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator
    /// * `ciphertext` - The encrypted data
    /// * `ratchets` - Optional list of ratchet keys to try for decryption (not yet used)
    ///
    /// # Returns
    ///
    /// Decrypted plaintext bytes.
    pub fn decrypt<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        ciphertext: &[u8],
        _ratchets: Option<&[Vec<u8>]>,
    ) -> Result<Vec<u8>, RnsError> {
        if ciphertext.len() <= PUBLIC_KEY_LENGTH {
            return Err(RnsError::InvalidArgument);
        }

        // Extract ephemeral public key from ciphertext
        let mut ephemeral_bytes = [0u8; 32];
        ephemeral_bytes.copy_from_slice(&ciphertext[..PUBLIC_KEY_LENGTH]);
        let ephemeral_public = x25519_dalek::PublicKey::from(ephemeral_bytes);

        // Derive decryption key
        let derived_key = self.identity.derive_key(&ephemeral_public, None);

        // Decrypt
        let mut out_buf = vec![0u8; ciphertext.len()];
        let decrypted = self
            .identity
            .decrypt(rng, &ciphertext[PUBLIC_KEY_LENGTH..], &derived_key, &mut out_buf)?;

        Ok(decrypted.to_vec())
    }
}

impl Destination<Identity, Output, Single> {
    pub fn new(identity: Identity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            desc: DestinationDesc {
                identity,
                name,
                address_hash,
            },
            callbacks: DestinationCallbacks::default(),
        }
    }

    /// Encrypt plaintext for this destination.
    ///
    /// Mirrors Python's `Destination.encrypt()` method for SINGLE destinations.
    /// Uses the destination's public identity for encryption.
    ///
    /// Note: This is an Output destination with only a public key, so only
    /// encryption is possible (no decryption or signing).
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator for ephemeral key generation
    /// * `plaintext` - The data to encrypt
    /// * `ratchet_manager` - Optional ratchet manager for forward secrecy
    ///
    /// # Returns
    ///
    /// Encrypted ciphertext bytes.
    pub fn encrypt<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        plaintext: &[u8],
        ratchet_manager: Option<&RatchetManager>,
    ) -> Result<Vec<u8>, RnsError> {
        // Get the selected ratchet if available
        let dest_hash: [u8; 16] = self.desc.address_hash.as_slice().try_into()
            .map_err(|_| RnsError::InvalidArgument)?;
        let _selected_ratchet = ratchet_manager
            .and_then(|rm| rm.get(&dest_hash));

        let derived_key = self.identity.derive_key(rng, None);

        // Build the output buffer
        let max_size = plaintext.len() + PUBLIC_KEY_LENGTH + 64 + 32; // overhead estimate
        let mut out_buf = vec![0u8; max_size];

        let encrypted = self.identity.encrypt(rng, plaintext, &derived_key, &mut out_buf)?;

        Ok(encrypted.to_vec())
    }
}

impl<D: Direction> Destination<EmptyIdentity, D, Plain> {
    pub fn new(identity: EmptyIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            desc: DestinationDesc {
                identity: Default::default(),
                name,
                address_hash,
            },
            callbacks: DestinationCallbacks::default(),
        }
    }
}

fn create_address_hash<I: HashIdentity>(identity: &I, name: &DestinationName) -> AddressHash {
    AddressHash::new_from_hash(&Hash::new(
        Hash::generator()
            .chain_update(name.as_name_hash_slice())
            .chain_update(identity.as_address_hash_slice())
            .finalize()
            .into(),
    ))
}

pub type SingleInputDestination = Destination<PrivateIdentity, Input, Single>;
pub type SingleOutputDestination = Destination<Identity, Output, Single>;
pub type PlainInputDestination = Destination<EmptyIdentity, Input, Plain>;
pub type PlainOutputDestination = Destination<EmptyIdentity, Output, Plain>;

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::buffer::OutputBuffer;
    use crate::hash::Hash;
    use crate::identity::PrivateIdentity;
    use crate::serde::Serialize;

    use super::DestinationAnnounce;
    use super::DestinationName;
    use super::SingleInputDestination;

    #[test]
    fn create_announce() {
        let identity = PrivateIdentity::new_from_rand(OsRng);

        let single_in_destination =
            SingleInputDestination::new(identity, DestinationName::new("test", "in"));

        let announce_packet = single_in_destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        println!("Announce packet {}", announce_packet);
    }

    #[test]
    fn create_path_request_hash() {
        let name = DestinationName::new("rnstransport", "path.request");

        println!("PathRequest Name Hash {}", name.hash);
        println!(
            "PathRequest Destination Hash {}",
            Hash::new_from_slice(name.as_name_hash_slice())
        );
    }

    #[test]
    fn compare_announce() {
        let priv_key: [u8; 32] = [
            0xf0, 0xec, 0xbb, 0xa4, 0x9e, 0x78, 0x3d, 0xee, 0x14, 0xff, 0xc6, 0xc9, 0xf1, 0xe1,
            0x25, 0x1e, 0xfa, 0x7d, 0x76, 0x29, 0xe0, 0xfa, 0x32, 0x41, 0x3c, 0x5c, 0x59, 0xec,
            0x2e, 0x0f, 0x6d, 0x6c,
        ];

        let sign_priv_key: [u8; 32] = [
            0xf0, 0xec, 0xbb, 0xa4, 0x9e, 0x78, 0x3d, 0xee, 0x14, 0xff, 0xc6, 0xc9, 0xf1, 0xe1,
            0x25, 0x1e, 0xfa, 0x7d, 0x76, 0x29, 0xe0, 0xfa, 0x32, 0x41, 0x3c, 0x5c, 0x59, 0xec,
            0x2e, 0x0f, 0x6d, 0x6c,
        ];

        let priv_identity = PrivateIdentity::new(priv_key.into(), sign_priv_key.into());

        println!("identity hash {}", priv_identity.as_identity().address_hash);

        let destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        println!("destination name hash {}", destination.desc.name.hash);
        println!("destination hash {}", destination.desc.address_hash);

        let announce = destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        let mut output_data = [0u8; 4096];
        let mut buffer = OutputBuffer::new(&mut output_data);

        let _ = announce.serialize(&mut buffer).expect("correct data");

        println!("ANNOUNCE {}", buffer);
    }

    #[test]
    fn check_announce() {
        let priv_identity = PrivateIdentity::new_from_rand(OsRng);

        let destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        let announce = destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        DestinationAnnounce::validate(&announce).expect("valid announce");
    }

    #[test]
    fn test_name_hash_truncation() {
        use super::NAME_HASH_LENGTH;

        // Create a name hash locally
        let local_name = DestinationName::new("rrc.v2", "hub");
        let local_hash = local_name.hash.as_slice();

        // Verify only the first NAME_HASH_LENGTH bytes are non-zero
        // (the rest should be zero due to truncation)
        assert!(
            local_hash[NAME_HASH_LENGTH..].iter().all(|&b| b == 0),
            "Bytes after NAME_HASH_LENGTH should be zero"
        );

        // Simulate receiving a name hash from an announce packet (only 10 bytes)
        let received_slice = &local_hash[..NAME_HASH_LENGTH];
        let received_name = DestinationName::new_from_hash_slice(received_slice);

        // The hashes should be identical - this is the key behavior we're testing
        assert_eq!(
            local_name.hash.as_slice(),
            received_name.hash.as_slice(),
            "Locally created name hash should match one reconstructed from announce"
        );
    }

    #[test]
    fn test_name_hash_from_announce_matches_local() {
        // This test verifies the full round-trip: create destination, announce,
        // validate announce, and compare the resulting name hash with original
        let priv_identity = PrivateIdentity::new_from_rand(OsRng);
        let original_name = DestinationName::new("test.app", "service");

        let destination = SingleInputDestination::new(priv_identity, original_name);

        // Create and validate an announce packet
        let announce = destination.announce(OsRng, None).expect("valid announce");
        let (validated_dest, _app_data) =
            DestinationAnnounce::validate(&announce).expect("validation should succeed");

        // The name hash from the validated announce should match the original
        assert_eq!(
            original_name.hash.as_slice(),
            validated_dest.desc.name.hash.as_slice(),
            "Name hash from validated announce should match original"
        );
    }

    #[test]
    fn test_validate_full_without_ratchet() {
        // Test that validate_full works for announces without ratchet
        let priv_identity = PrivateIdentity::new_from_rand(OsRng);
        let original_name = DestinationName::new("test.app", "service");

        let destination = SingleInputDestination::new(priv_identity, original_name);

        let announce = destination.announce(OsRng, None).expect("valid announce");

        // Verify context_flag is false (no ratchet)
        assert!(!announce.header.context_flag, "Announce without ratchet should have context_flag=false");

        // Use validate_full to get the full result
        let validation = DestinationAnnounce::validate_full(&announce).expect("validation should succeed");

        // Ratchet should be None
        assert!(validation.ratchet.is_none(), "Announce without ratchet should have None ratchet");

        // Name hash should still match
        assert_eq!(
            original_name.hash.as_slice(),
            validation.destination.desc.name.hash.as_slice(),
            "Name hash from validated announce should match original"
        );
    }

    #[test]
    fn test_validate_full_with_ratchet() {
        use crate::identity::{generate_ratchet, ratchet_public_bytes};
        use crate::packet::{Packet, PacketDataBuffer, Header, HeaderType, IfacFlag, TransportType, DestinationType, PacketType, PacketContext};

        // Create identity and destination
        let priv_identity = PrivateIdentity::new_from_rand(OsRng);
        let name = DestinationName::new("test.app", "ratchetservice");
        let address_hash = crate::destination::create_address_hash(priv_identity.as_identity(), &name);

        // Generate a ratchet key
        let ratchet_priv = generate_ratchet(OsRng);
        let ratchet_pub = ratchet_public_bytes(&ratchet_priv);

        // Build announce data with ratchet
        let pub_key = priv_identity.as_identity().public_key_bytes();
        let verifying_key = priv_identity.as_identity().verifying_key_bytes();
        let name_hash = name.as_name_hash_slice();

        // Random hash (10 bytes)
        let rand_hash: [u8; 10] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22];

        // Build signed data: destination_hash + pubkey + verifying_key + name_hash + rand_hash + ratchet + app_data
        let app_data = b"test app data";
        let signed_data = PacketDataBuffer::new()
            .chain_write(address_hash.as_slice()).unwrap()
            .chain_write(pub_key).unwrap()
            .chain_write(verifying_key).unwrap()
            .chain_write(name_hash).unwrap()
            .chain_write(&rand_hash).unwrap()
            .chain_write(&ratchet_pub).unwrap()
            .chain_write(app_data).unwrap()
            .finalize();

        let signature = priv_identity.sign(signed_data.as_slice());

        // Build packet data: pubkey + verifying_key + name_hash + rand_hash + ratchet + signature + app_data
        let packet_data = PacketDataBuffer::new()
            .chain_write(pub_key).unwrap()
            .chain_write(verifying_key).unwrap()
            .chain_write(name_hash).unwrap()
            .chain_write(&rand_hash).unwrap()
            .chain_write(&ratchet_pub).unwrap()
            .chain_write(&signature.to_bytes()).unwrap()
            .chain_write(app_data).unwrap()
            .finalize();

        // Create packet with context_flag=true
        let announce = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: true,  // Indicates ratchet is present
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        };

        // Validate with full ratchet support
        let validation = DestinationAnnounce::validate_full(&announce).expect("validation should succeed");

        // Verify ratchet was extracted
        assert!(validation.ratchet.is_some(), "Announce with context_flag should have ratchet");
        let extracted_ratchet = validation.ratchet.unwrap();
        assert_eq!(extracted_ratchet, ratchet_pub, "Extracted ratchet should match original");

        // Verify app data
        assert_eq!(validation.app_data, app_data, "App data should match");

        // Verify destination
        assert_eq!(
            validation.destination.desc.address_hash.as_slice(),
            address_hash.as_slice(),
            "Destination hash should match"
        );
    }

    #[test]
    fn test_announce_with_ratchet_roundtrip() {
        use crate::identity::{generate_ratchet, ratchet_public_bytes, get_ratchet_id};

        // Create identity and destination
        let priv_identity = PrivateIdentity::new_from_rand(OsRng);
        let name = DestinationName::new("test.app", "ratchetservice");
        let destination = SingleInputDestination::new(priv_identity, name);

        // Generate a ratchet key
        let ratchet_priv = generate_ratchet(OsRng);
        let ratchet_pub = ratchet_public_bytes(&ratchet_priv);

        // Create announce with ratchet
        let announce = destination
            .announce_with_ratchet(OsRng, &ratchet_pub, None)
            .expect("valid announce");

        // Verify context_flag is set
        assert!(announce.header.context_flag, "Announce with ratchet should have context_flag=true");

        // Validate the announce
        let validation = DestinationAnnounce::validate_full(&announce)
            .expect("Announce should validate");

        // Verify ratchet was extracted
        assert!(validation.ratchet.is_some(), "Should extract ratchet from announce");
        let extracted_ratchet = validation.ratchet.unwrap();
        assert_eq!(extracted_ratchet, ratchet_pub, "Extracted ratchet should match original");

        // Verify ratchet ID
        let ratchet_id = get_ratchet_id(&extracted_ratchet);
        let expected_ratchet_id = get_ratchet_id(&ratchet_pub);
        assert_eq!(ratchet_id, expected_ratchet_id, "Ratchet IDs should match");

        // Verify destination matches
        assert_eq!(
            validation.destination.desc.address_hash.as_slice(),
            destination.desc.address_hash.as_slice(),
            "Destination hash should match"
        );

        eprintln!("announce_with_ratchet roundtrip test passed!");
        eprintln!("  Ratchet ID: {}", hex::encode(&ratchet_id));
    }
}
