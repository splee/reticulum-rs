//! Tunnel support for transport layer.
//!
//! Tunnels allow transport instances to route packets through intermediary nodes.
//! When a tunnel interface goes down and comes back, its cached paths can be
//! restored without re-announcing.
//!
//! Matches Python's Transport.py tunnel logic: synthesize_tunnel(),
//! tunnel_synthesize_handler(), handle_tunnel(), save_tunnel_table(),
//! and void_tunnel_interface().

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::hash::{AddressHash, Hash};
use crate::identity::{Identity, PrivateIdentity, PUBLIC_KEY_LENGTH};
use crate::transport::path_table::RandomBlob;

/// Tunnel/path expiry time: 7 days.
/// Matches Python's DESTINATION_TIMEOUT = 60*60*24*7 = 604800 seconds.
pub const TUNNEL_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24 * 7);

/// Maximum number of random blobs to persist per tunnel path entry.
/// Python: Transport.PERSIST_RANDOM_BLOBS = 32
pub const PERSIST_RANDOM_BLOBS: usize = 32;

/// Interval between periodic tunnel table saves.
/// Python saves tunnel table periodically during cleanup cycles.
pub const INTERVAL_TUNNEL_PERSIST: Duration = Duration::from_secs(300);

/// Size constants for tunnel synthesis packets.
/// Python: KEYSIZE//8 = 64, HASHLENGTH//8 = 32, TRUNCATED_HASHLENGTH//8 = 16, SIGLENGTH//8 = 64
const SYNTHESIS_PUBLIC_KEY_LEN: usize = PUBLIC_KEY_LENGTH * 2; // 64 bytes (X25519 + Ed25519)
const SYNTHESIS_INTERFACE_HASH_LEN: usize = 32; // Full SHA256 hash
const SYNTHESIS_RANDOM_HASH_LEN: usize = 16; // Truncated hash
const SYNTHESIS_SIGNATURE_LEN: usize = 64; // Ed25519 signature
const SYNTHESIS_PACKET_LEN: usize =
    SYNTHESIS_PUBLIC_KEY_LEN + SYNTHESIS_INTERFACE_HASH_LEN + SYNTHESIS_RANDOM_HASH_LEN + SYNTHESIS_SIGNATURE_LEN;

/// A path entry within a tunnel, matching Python's 7-element tunnel path list:
/// `[timestamp, received_from, hops, expires, random_blobs, receiving_interface, packet_hash]`
///
/// The `receiving_interface` (index 5) is always `None` in Python's tunnel paths
/// dict — the interface is tracked at the tunnel level, so we omit it.
#[derive(Debug, Clone)]
pub struct TunnelPathEntry {
    /// Unix timestamp when this path was recorded
    pub timestamp: f64,
    /// Next hop address hash (who we received the announce from)
    pub received_from: AddressHash,
    /// Hop count for this path
    pub hops: u8,
    /// Unix timestamp when this path expires
    pub expires: f64,
    /// Random blobs from announces, for replay detection
    pub random_blobs: Vec<RandomBlob>,
    /// Hash of the original announce packet
    pub packet_hash: Hash,
}

/// Information about a tunnel to another transport instance.
/// Matches Python's tunnel entry: `[tunnel_id, interface, paths_dict, expires]`
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    /// Tunnel ID (32-byte SHA256 hash of public_key + interface_hash)
    pub id: Hash,
    /// Interface address hash for this tunnel (None if voided)
    pub interface_hash: Option<AddressHash>,
    /// Destination hash -> path entry (reachable destinations through this tunnel)
    pub paths: HashMap<AddressHash, TunnelPathEntry>,
    /// Unix timestamp when this tunnel expires
    pub expires: f64,
}

/// Tunnel manager for transport layer.
///
/// Manages the tunnel table, providing registration, path tracking,
/// synthesis validation, and persistence.
#[derive(Debug)]
pub struct TunnelManager {
    /// Map of tunnel ID -> tunnel info
    tunnels: HashMap<Hash, TunnelInfo>,
    /// Map of destination hash -> tunnel ID (reverse lookup optimization)
    destination_to_tunnel: HashMap<AddressHash, Hash>,
    /// Storage path for tunnel persistence
    storage_path: Option<PathBuf>,
    /// Whether a save operation is in progress (prevents concurrent saves)
    saving: bool,
}

impl TunnelManager {
    /// Create a new tunnel manager with optional persistence path.
    pub fn new(storage_path: Option<PathBuf>) -> Self {
        Self {
            tunnels: HashMap::new(),
            destination_to_tunnel: HashMap::new(),
            storage_path,
            saving: false,
        }
    }

    /// Register a new tunnel with the given ID and interface.
    /// Creates an entry with empty paths and 7-day expiry.
    pub fn register(&mut self, tunnel_id: Hash, interface_hash: AddressHash) {
        let now = now_unix_f64();
        let tunnel = TunnelInfo {
            id: tunnel_id,
            interface_hash: Some(interface_hash),
            paths: HashMap::new(),
            expires: now + TUNNEL_EXPIRY.as_secs_f64(),
        };
        self.tunnels.insert(tunnel_id, tunnel);
    }

    /// Handle a tunnel establishment or reappearance.
    ///
    /// For new tunnels: creates entry with empty paths and 7-day expiry.
    /// For existing tunnels: restores interface reference, resets expiry,
    /// and returns valid path candidates for path_table restoration.
    ///
    /// Returns `(dest_hash, path_entry)` pairs for paths that should be
    /// considered for restoration into the main path table. The caller
    /// (transport.rs) performs the hop-count comparison.
    ///
    /// Matches Python's Transport.handle_tunnel() (Transport.py:2171-2217).
    pub fn handle_tunnel(
        &mut self,
        tunnel_id: Hash,
        interface_hash: AddressHash,
    ) -> Vec<(AddressHash, TunnelPathEntry)> {
        let now = now_unix_f64();
        let expires = now + TUNNEL_EXPIRY.as_secs_f64();

        if !self.tunnels.contains_key(&tunnel_id) {
            // New tunnel — create entry with empty paths
            log::debug!("Tunnel endpoint {} established", tunnel_id);
            let tunnel = TunnelInfo {
                id: tunnel_id,
                interface_hash: Some(interface_hash),
                paths: HashMap::new(),
                expires,
            };
            self.tunnels.insert(tunnel_id, tunnel);
            return Vec::new();
        }

        // Existing tunnel — restore interface and return path candidates
        log::debug!(
            "Tunnel endpoint {} reappeared. Restoring paths...",
            tunnel_id
        );
        let tunnel = self.tunnels.get_mut(&tunnel_id).unwrap();
        tunnel.interface_hash = Some(interface_hash);
        tunnel.expires = expires;

        let mut candidates = Vec::new();
        let mut deprecated = Vec::new();

        for (dest_hash, path_entry) in tunnel.paths.iter() {
            if now > path_entry.expires {
                // Path has expired — mark for removal
                log::debug!(
                    "Did not restore path to {} because it has expired",
                    dest_hash
                );
                deprecated.push(*dest_hash);
            } else {
                // Valid path — return as candidate for restoration
                candidates.push((*dest_hash, path_entry.clone()));
            }
        }

        // Remove deprecated paths from the tunnel
        for dest_hash in deprecated {
            log::debug!(
                "Removing path to {} from tunnel {}",
                dest_hash,
                tunnel_id
            );
            tunnel.paths.remove(&dest_hash);
            self.destination_to_tunnel.remove(&dest_hash);
        }

        candidates
    }

    /// Record a path in a tunnel (called when announces arrive on tunneled interfaces).
    ///
    /// Inserts the path entry, updates the reverse lookup, and resets the tunnel expiry.
    /// Matches Python's Transport.py:1872-1880.
    pub fn record_path(
        &mut self,
        tunnel_id: &Hash,
        dest_hash: AddressHash,
        entry: TunnelPathEntry,
    ) {
        if let Some(tunnel) = self.tunnels.get_mut(tunnel_id) {
            tunnel.paths.insert(dest_hash, entry);
            tunnel.expires = now_unix_f64() + TUNNEL_EXPIRY.as_secs_f64();
            self.destination_to_tunnel.insert(dest_hash, *tunnel_id);
            log::debug!(
                "Path to {} associated with tunnel {}",
                dest_hash,
                tunnel_id
            );
        }
    }

    /// Void a tunnel's interface reference (set to None) while preserving paths.
    ///
    /// Called when a tunnel interface disconnects. The tunnel and its paths are
    /// preserved so they can be restored when the interface reappears.
    /// Matches Python's Transport.void_tunnel_interface() (Transport.py:2165-2168).
    pub fn void_interface(&mut self, tunnel_id: &Hash) {
        if let Some(tunnel) = self.tunnels.get_mut(tunnel_id) {
            log::debug!("Voiding tunnel interface for tunnel {}", tunnel_id);
            tunnel.interface_hash = None;
        }
    }

    /// Reset expiry for a tunnel to now + TUNNEL_EXPIRY.
    pub fn reset_expiry(&mut self, tunnel_id: &Hash) {
        if let Some(tunnel) = self.tunnels.get_mut(tunnel_id) {
            tunnel.expires = now_unix_f64() + TUNNEL_EXPIRY.as_secs_f64();
        }
    }

    /// Clean up expired tunnels and per-path expiry within surviving tunnels.
    ///
    /// Matches Python's cleanup logic (Transport.py:733-810):
    /// 1. Remove whole tunnels where now > tunnel.expires
    /// 2. Within surviving tunnels, remove individual paths where
    ///    now > path.timestamp + TUNNEL_EXPIRY
    /// 3. Void interface if it's no longer in the active interface set
    pub fn cleanup(&mut self, active_interfaces: &[AddressHash]) {
        let now = now_unix_f64();

        // Collect stale tunnels
        let stale_tunnels: Vec<Hash> = self
            .tunnels
            .iter()
            .filter(|(_, t)| now > t.expires)
            .map(|(id, _)| *id)
            .collect();

        for id in &stale_tunnels {
            log::trace!("Tunnel {} timed out and was removed", id);
            self.remove(id);
        }

        if !stale_tunnels.is_empty() {
            log::trace!("Removed {} tunnel(s)", stale_tunnels.len());
        }

        // Per-path cleanup within surviving tunnels + interface voiding
        let tunnel_ids: Vec<Hash> = self.tunnels.keys().copied().collect();
        for tunnel_id in tunnel_ids {
            let tunnel = self.tunnels.get_mut(&tunnel_id).unwrap();

            // Void interface if it no longer exists in the active interface set
            if let Some(iface_hash) = tunnel.interface_hash {
                if !active_interfaces.contains(&iface_hash) {
                    log::trace!(
                        "Removing non-existent tunnel interface {} from tunnel {}",
                        iface_hash,
                        tunnel_id
                    );
                    tunnel.interface_hash = None;
                }
            }

            // Remove individual expired paths
            let stale_paths: Vec<AddressHash> = tunnel
                .paths
                .iter()
                .filter(|(_, entry)| now > entry.timestamp + TUNNEL_EXPIRY.as_secs_f64())
                .map(|(dest, _)| *dest)
                .collect();

            for dest in &stale_paths {
                log::trace!(
                    "Tunnel path to {} timed out and was removed from tunnel {}",
                    dest,
                    tunnel_id
                );
                tunnel.paths.remove(dest);
                self.destination_to_tunnel.remove(dest);
            }
        }
    }

    /// Get a tunnel by ID.
    pub fn get(&self, tunnel_id: &Hash) -> Option<&TunnelInfo> {
        self.tunnels.get(tunnel_id)
    }

    /// Get a mutable reference to a tunnel.
    pub fn get_mut(&mut self, tunnel_id: &Hash) -> Option<&mut TunnelInfo> {
        self.tunnels.get_mut(tunnel_id)
    }

    /// Find tunnel for a destination.
    pub fn find_for_destination(&self, destination: &AddressHash) -> Option<&TunnelInfo> {
        self.destination_to_tunnel
            .get(destination)
            .and_then(|id| self.tunnels.get(id))
    }

    /// Remove a tunnel and clean up all its destination mappings.
    pub fn remove(&mut self, tunnel_id: &Hash) -> Option<TunnelInfo> {
        if let Some(tunnel) = self.tunnels.remove(tunnel_id) {
            for dest in tunnel.paths.keys() {
                self.destination_to_tunnel.remove(dest);
            }
            Some(tunnel)
        } else {
            None
        }
    }

    /// Get number of tunnels.
    pub fn len(&self) -> usize {
        self.tunnels.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.tunnels.is_empty()
    }

    /// Iterate over all tunnels.
    pub fn iter(&self) -> impl Iterator<Item = (&Hash, &TunnelInfo)> {
        self.tunnels.iter()
    }

    // =========================================================================
    // Persistence
    // =========================================================================

    /// Save the tunnel table to disk.
    ///
    /// Serializes tunnels as MessagePack matching Python's save_tunnel_table()
    /// format: `[[tunnel_id, interface_hash, [[path_entries...]], expires], ...]`
    ///
    /// Matches Python's Transport.save_tunnel_table() (Transport.py:3066-3137).
    pub fn save(&mut self) -> std::io::Result<()> {
        let storage_path = match &self.storage_path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        if self.saving {
            log::warn!("Tunnel table save already in progress, skipping");
            return Ok(());
        }
        self.saving = true;

        let result = self.save_inner(&storage_path);

        self.saving = false;
        result
    }

    fn save_inner(&self, storage_path: &PathBuf) -> std::io::Result<()> {
        log::debug!("Saving tunnel table to storage...");

        let mut serialised_tunnels: Vec<SerialisedTunnel> = Vec::new();

        for tunnel in self.tunnels.values() {
            let interface_hash = tunnel.interface_hash.map(|h| h.as_slice().to_vec());

            let mut serialised_paths: Vec<SerialisedPathEntry> = Vec::new();
            for (dest_hash, entry) in &tunnel.paths {
                // Trim random_blobs to PERSIST_RANDOM_BLOBS
                let blobs: Vec<Vec<u8>> = entry
                    .random_blobs
                    .iter()
                    .rev()
                    .take(PERSIST_RANDOM_BLOBS)
                    .rev()
                    .map(|b| b.to_vec())
                    .collect();

                serialised_paths.push(SerialisedPathEntry {
                    destination_hash: dest_hash.as_slice().to_vec(),
                    timestamp: entry.timestamp,
                    received_from: entry.received_from.as_slice().to_vec(),
                    hops: entry.hops,
                    expires: entry.expires,
                    random_blobs: blobs,
                    interface_hash: interface_hash.clone(),
                    packet_hash: entry.packet_hash.as_slice().to_vec(),
                });
            }

            serialised_tunnels.push(SerialisedTunnel {
                tunnel_id: tunnel.id.as_slice().to_vec(),
                interface_hash,
                paths: serialised_paths,
                expires: tunnel.expires,
            });
        }

        // Ensure storage directory exists
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tunnels_path = storage_path.join("tunnels");
        let temp_path = tunnels_path.with_extension("tmp");

        let file = File::create(&temp_path)?;
        let mut writer = BufWriter::new(file);
        rmp_serde::encode::write(&mut writer, &serialised_tunnels).map_err(|e| {
            std::io::Error::other(format!("MessagePack encode error: {}", e))
        })?;
        writer.flush()?;
        drop(writer);

        // Atomic rename
        fs::rename(&temp_path, &tunnels_path)?;

        log::debug!(
            "Saved {} tunnel table entries",
            serialised_tunnels.len()
        );
        Ok(())
    }

    /// Load tunnel table from disk.
    ///
    /// Deserializes tunnels from MessagePack format. All loaded tunnels have
    /// their interface_hash set to None (will be restored when tunnel reappears).
    ///
    /// Matches Python's tunnel table loading (Transport.py:314-361).
    pub fn load(&mut self) -> std::io::Result<()> {
        let storage_path = match &self.storage_path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        let tunnels_path = storage_path.join("tunnels");
        if !tunnels_path.exists() {
            return Ok(());
        }

        let file = File::open(&tunnels_path)?;
        let reader = BufReader::new(file);

        let serialised_tunnels: Vec<SerialisedTunnel> =
            rmp_serde::from_read(reader).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("MessagePack decode error: {}", e),
                )
            })?;

        for st in serialised_tunnels {
            if st.tunnel_id.len() != 32 {
                continue;
            }

            let tunnel_id = Hash::new({
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&st.tunnel_id);
                buf
            });

            let mut tunnel_paths: HashMap<AddressHash, TunnelPathEntry> = HashMap::new();

            for sp in &st.paths {
                if sp.destination_hash.len() < 16
                    || sp.received_from.len() < 16
                    || sp.packet_hash.len() < 32
                {
                    continue;
                }

                let dest_hash = AddressHash::new({
                    let mut buf = [0u8; 16];
                    buf.copy_from_slice(&sp.destination_hash[..16]);
                    buf
                });

                let received_from = AddressHash::new({
                    let mut buf = [0u8; 16];
                    buf.copy_from_slice(&sp.received_from[..16]);
                    buf
                });

                let packet_hash = Hash::new({
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(&sp.packet_hash[..32]);
                    buf
                });

                let random_blobs: Vec<RandomBlob> = sp
                    .random_blobs
                    .iter()
                    .filter_map(|b| {
                        if b.len() >= 10 {
                            let mut blob: RandomBlob = [0u8; 10];
                            blob.copy_from_slice(&b[..10]);
                            Some(blob)
                        } else {
                            None
                        }
                    })
                    .collect();

                let path_entry = TunnelPathEntry {
                    timestamp: sp.timestamp,
                    received_from,
                    hops: sp.hops,
                    expires: sp.expires,
                    random_blobs,
                    packet_hash,
                };

                tunnel_paths.insert(dest_hash, path_entry);
                self.destination_to_tunnel.insert(dest_hash, tunnel_id);
            }

            // Skip tunnels with zero remaining paths (matches Python behavior)
            if tunnel_paths.is_empty() {
                continue;
            }

            let tunnel = TunnelInfo {
                id: tunnel_id,
                interface_hash: None, // Will be restored when tunnel reappears
                paths: tunnel_paths,
                expires: st.expires,
            };

            self.tunnels.insert(tunnel_id, tunnel);
        }

        log::debug!("Loaded {} tunnels from storage", self.tunnels.len());
        Ok(())
    }
}

// =============================================================================
// Tunnel synthesis protocol
// =============================================================================

/// Build a tunnel synthesis packet.
///
/// Creates the 176-byte signed data packet used to establish a tunnel:
/// `data = public_key(64) + interface_hash(32) + random_hash(16) + signature(64)`
///
/// Returns `(tunnel_id, data)` where tunnel_id is SHA256(public_key + interface_hash).
///
/// Matches Python's Transport.synthesize_tunnel() (Transport.py:2120-2138).
pub fn build_synthesis_data(identity: &PrivateIdentity, interface_name: &str) -> (Hash, Vec<u8>) {
    // public_key = X25519 pub (32) + Ed25519 verifying (32) = 64 bytes
    let pub_identity = identity.as_identity();
    let mut public_key = Vec::with_capacity(SYNTHESIS_PUBLIC_KEY_LEN);
    public_key.extend_from_slice(pub_identity.public_key_bytes());
    public_key.extend_from_slice(pub_identity.verifying_key_bytes());

    // interface_hash = full SHA256 of interface name string = 32 bytes
    let interface_hash = Hash::new_from_slice(interface_name.as_bytes());

    // tunnel_id = SHA256(public_key + interface_hash) — computed by both sides, not sent
    let mut tunnel_id_data = Vec::with_capacity(SYNTHESIS_PUBLIC_KEY_LEN + SYNTHESIS_INTERFACE_HASH_LEN);
    tunnel_id_data.extend_from_slice(&public_key);
    tunnel_id_data.extend_from_slice(interface_hash.as_slice());
    let tunnel_id = Hash::new_from_slice(&tunnel_id_data);

    // random_hash = truncated hash of 16 random bytes = 16 bytes
    let random_hash = AddressHash::new_from_rand(OsRng);

    // signed_data = public_key + interface_hash + random_hash = 112 bytes
    let mut signed_data = Vec::with_capacity(
        SYNTHESIS_PUBLIC_KEY_LEN + SYNTHESIS_INTERFACE_HASH_LEN + SYNTHESIS_RANDOM_HASH_LEN,
    );
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(interface_hash.as_slice());
    signed_data.extend_from_slice(random_hash.as_slice());

    // signature = Ed25519 sign(signed_data) = 64 bytes
    let signature = identity.sign(&signed_data);

    // data = signed_data + signature = 176 bytes
    let mut data = Vec::with_capacity(SYNTHESIS_PACKET_LEN);
    data.extend_from_slice(&signed_data);
    data.extend_from_slice(&signature.to_bytes());

    (tunnel_id, data)
}

/// Validate a tunnel synthesis packet.
///
/// Checks the 176-byte packet data, verifies the Ed25519 signature,
/// and returns the tunnel ID if valid.
///
/// Matches Python's Transport.tunnel_synthesize_handler() (Transport.py:2141-2162).
pub fn validate_synthesis_packet(data: &[u8]) -> Option<Hash> {
    if data.len() != SYNTHESIS_PACKET_LEN {
        log::debug!(
            "Tunnel synthesis packet has wrong length: {} (expected {})",
            data.len(),
            SYNTHESIS_PACKET_LEN
        );
        return None;
    }

    // Extract fields from the packet
    let public_key = &data[..SYNTHESIS_PUBLIC_KEY_LEN]; // bytes 0..64
    let _interface_hash = &data[SYNTHESIS_PUBLIC_KEY_LEN..SYNTHESIS_PUBLIC_KEY_LEN + SYNTHESIS_INTERFACE_HASH_LEN]; // bytes 64..96
    let _random_hash = &data[SYNTHESIS_PUBLIC_KEY_LEN + SYNTHESIS_INTERFACE_HASH_LEN
        ..SYNTHESIS_PUBLIC_KEY_LEN + SYNTHESIS_INTERFACE_HASH_LEN + SYNTHESIS_RANDOM_HASH_LEN]; // bytes 96..112
    let signature_bytes =
        &data[SYNTHESIS_PUBLIC_KEY_LEN + SYNTHESIS_INTERFACE_HASH_LEN + SYNTHESIS_RANDOM_HASH_LEN..]; // bytes 112..176

    // Compute tunnel_id = SHA256(public_key + interface_hash)
    let tunnel_id_data = &data[..SYNTHESIS_PUBLIC_KEY_LEN + SYNTHESIS_INTERFACE_HASH_LEN]; // bytes 0..96
    let tunnel_id = Hash::new_from_slice(tunnel_id_data);

    // signed_data = public_key + interface_hash + random_hash (bytes 0..112)
    let signed_data = &data[..SYNTHESIS_PUBLIC_KEY_LEN + SYNTHESIS_INTERFACE_HASH_LEN + SYNTHESIS_RANDOM_HASH_LEN];

    // Load remote identity from public key and verify signature
    let remote_identity = match Identity::from_bytes(public_key) {
        Ok(id) => id,
        Err(e) => {
            log::debug!("Failed to load remote identity from tunnel synthesis: {}", e);
            return None;
        }
    };

    let signature = match ed25519_dalek::Signature::from_slice(signature_bytes) {
        Ok(sig) => sig,
        Err(e) => {
            log::debug!("Invalid signature format in tunnel synthesis: {}", e);
            return None;
        }
    };

    match remote_identity.verify(signed_data, &signature) {
        Ok(()) => {
            log::debug!("Tunnel synthesis validated for tunnel {}", tunnel_id);
            Some(tunnel_id)
        }
        Err(_) => {
            log::debug!("Tunnel synthesis signature verification failed");
            None
        }
    }
}

// =============================================================================
// Serialization types for persistence
// =============================================================================

/// Serialised tunnel entry for MessagePack persistence.
/// Format matches Python: [tunnel_id, interface_hash, paths, expires]
#[derive(Serialize, Deserialize)]
struct SerialisedTunnel {
    tunnel_id: Vec<u8>,
    interface_hash: Option<Vec<u8>>,
    paths: Vec<SerialisedPathEntry>,
    expires: f64,
}

/// Serialised path entry within a tunnel.
/// Format matches Python: [dest_hash, timestamp, received_from, hops, expires, random_blobs, interface_hash, packet_hash]
#[derive(Serialize, Deserialize)]
struct SerialisedPathEntry {
    destination_hash: Vec<u8>,
    timestamp: f64,
    received_from: Vec<u8>,
    hops: u8,
    expires: f64,
    random_blobs: Vec<Vec<u8>>,
    interface_hash: Option<Vec<u8>>,
    packet_hash: Vec<u8>,
}

// =============================================================================
// Helpers
// =============================================================================

/// Get current Unix timestamp as f64.
fn now_unix_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(b: u8) -> AddressHash {
        AddressHash::new_from_slice(&[b; 32])
    }

    fn make_hash(b: u8) -> Hash {
        Hash::new([b; 32])
    }

    fn make_path_entry(hops: u8) -> TunnelPathEntry {
        let now = now_unix_f64();
        TunnelPathEntry {
            timestamp: now,
            received_from: make_addr(0xAA),
            hops,
            expires: now + TUNNEL_EXPIRY.as_secs_f64(),
            random_blobs: vec![[0u8; 10]],
            packet_hash: make_hash(0xBB),
        }
    }

    #[test]
    fn test_tunnel_expiry_is_seven_days() {
        assert_eq!(TUNNEL_EXPIRY.as_secs(), 60 * 60 * 24 * 7);
    }

    #[test]
    fn test_tunnel_path_entry_creation() {
        let entry = make_path_entry(3);
        assert_eq!(entry.hops, 3);
        assert_eq!(entry.random_blobs.len(), 1);
    }

    #[test]
    fn test_tunnel_manager_register() {
        let mut manager = TunnelManager::new(None);
        let tunnel_id = make_hash(1);
        let iface = make_addr(2);

        manager.register(tunnel_id, iface);

        let tunnel = manager.get(&tunnel_id).unwrap();
        assert_eq!(tunnel.interface_hash, Some(iface));
        assert!(tunnel.paths.is_empty());
    }

    #[test]
    fn test_handle_tunnel_new() {
        let mut manager = TunnelManager::new(None);
        let tunnel_id = make_hash(1);
        let iface = make_addr(2);

        let candidates = manager.handle_tunnel(tunnel_id, iface);
        assert!(candidates.is_empty());
        assert!(manager.get(&tunnel_id).is_some());
    }

    #[test]
    fn test_handle_tunnel_reappearing_with_paths() {
        let mut manager = TunnelManager::new(None);
        let tunnel_id = make_hash(1);
        let iface = make_addr(2);
        let dest = make_addr(3);

        // Create tunnel and add a valid path
        manager.handle_tunnel(tunnel_id, iface);
        let path_entry = make_path_entry(2);
        manager.record_path(&tunnel_id, dest, path_entry);

        // Simulate tunnel reappearing on a new interface
        let new_iface = make_addr(4);
        let candidates = manager.handle_tunnel(tunnel_id, new_iface);

        // Should return the stored path as a restoration candidate
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, dest);
        assert_eq!(candidates[0].1.hops, 2);

        // Interface should be updated
        let tunnel = manager.get(&tunnel_id).unwrap();
        assert_eq!(tunnel.interface_hash, Some(new_iface));
    }

    #[test]
    fn test_handle_tunnel_removes_expired_paths() {
        let mut manager = TunnelManager::new(None);
        let tunnel_id = make_hash(1);
        let iface = make_addr(2);

        manager.handle_tunnel(tunnel_id, iface);

        // Add a path that's already expired
        let expired_entry = TunnelPathEntry {
            timestamp: now_unix_f64() - TUNNEL_EXPIRY.as_secs_f64() - 1.0,
            received_from: make_addr(0xAA),
            hops: 2,
            expires: now_unix_f64() - 1.0, // Already expired
            random_blobs: vec![],
            packet_hash: make_hash(0xBB),
        };
        manager.record_path(&tunnel_id, make_addr(3), expired_entry);

        // Reappear — expired path should be removed, not returned
        let candidates = manager.handle_tunnel(tunnel_id, make_addr(4));
        assert!(candidates.is_empty());
        assert!(manager.get(&tunnel_id).unwrap().paths.is_empty());
    }

    #[test]
    fn test_void_interface() {
        let mut manager = TunnelManager::new(None);
        let tunnel_id = make_hash(1);
        let iface = make_addr(2);

        manager.register(tunnel_id, iface);
        assert_eq!(manager.get(&tunnel_id).unwrap().interface_hash, Some(iface));

        manager.void_interface(&tunnel_id);
        assert_eq!(manager.get(&tunnel_id).unwrap().interface_hash, None);

        // Paths should still be preserved
        let dest = make_addr(3);
        let entry = make_path_entry(1);
        manager.record_path(&tunnel_id, dest, entry);
        manager.void_interface(&tunnel_id);
        assert!(manager.get(&tunnel_id).unwrap().paths.contains_key(&dest));
    }

    #[test]
    fn test_cleanup_expired_tunnels() {
        let mut manager = TunnelManager::new(None);
        let tunnel_id = make_hash(1);

        // Create tunnel with past expiry
        let tunnel = TunnelInfo {
            id: tunnel_id,
            interface_hash: Some(make_addr(2)),
            paths: HashMap::new(),
            expires: now_unix_f64() - 1.0,
        };
        manager.tunnels.insert(tunnel_id, tunnel);

        manager.cleanup(&[]);
        assert!(manager.is_empty());
    }

    #[test]
    fn test_cleanup_expired_paths_within_tunnel() {
        let mut manager = TunnelManager::new(None);
        let tunnel_id = make_hash(1);
        let iface = make_addr(2);

        manager.register(tunnel_id, iface);

        // Add a path that's old enough to expire during cleanup
        let old_entry = TunnelPathEntry {
            timestamp: now_unix_f64() - TUNNEL_EXPIRY.as_secs_f64() - 1.0,
            received_from: make_addr(0xAA),
            hops: 2,
            expires: now_unix_f64() + 1000.0, // Not expired by expires field
            random_blobs: vec![],
            packet_hash: make_hash(0xBB),
        };
        manager.record_path(&tunnel_id, make_addr(3), old_entry);

        // Add a fresh path
        manager.record_path(&tunnel_id, make_addr(4), make_path_entry(1));

        manager.cleanup(&[iface]);

        let tunnel = manager.get(&tunnel_id).unwrap();
        // Old path should be removed, fresh path should remain
        assert_eq!(tunnel.paths.len(), 1);
        assert!(tunnel.paths.contains_key(&make_addr(4)));
    }

    #[test]
    fn test_cleanup_voids_missing_interface() {
        let mut manager = TunnelManager::new(None);
        let tunnel_id = make_hash(1);
        let iface = make_addr(2);

        manager.register(tunnel_id, iface);

        // Cleanup with empty active interfaces — should void the interface
        manager.cleanup(&[]);
        assert_eq!(manager.get(&tunnel_id).unwrap().interface_hash, None);
    }

    #[test]
    fn test_find_for_destination() {
        let mut manager = TunnelManager::new(None);
        let tunnel_id = make_hash(1);
        let iface = make_addr(2);
        let dest = make_addr(3);

        manager.register(tunnel_id, iface);
        manager.record_path(&tunnel_id, dest, make_path_entry(1));

        let found = manager.find_for_destination(&dest);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, tunnel_id);

        // Unknown destination should return None
        assert!(manager.find_for_destination(&make_addr(99)).is_none());
    }

    #[test]
    fn test_validate_synthesis_packet_wrong_length() {
        assert!(validate_synthesis_packet(&[0u8; 100]).is_none());
        assert!(validate_synthesis_packet(&[0u8; 177]).is_none());
    }

    #[test]
    fn test_build_and_validate_synthesis_roundtrip() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let interface_name = "TCPInterface[127.0.0.1:4242]";

        let (tunnel_id, data) = build_synthesis_data(&identity, interface_name);

        // Should be exactly 176 bytes
        assert_eq!(data.len(), SYNTHESIS_PACKET_LEN);

        // Validate should succeed and return the same tunnel_id
        let validated_id = validate_synthesis_packet(&data);
        assert!(validated_id.is_some());
        assert_eq!(validated_id.unwrap(), tunnel_id);
    }

    #[test]
    fn test_validate_synthesis_bad_signature() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let (_, mut data) = build_synthesis_data(&identity, "test");

        // Corrupt the signature (last 64 bytes)
        data[SYNTHESIS_PACKET_LEN - 1] ^= 0xFF;

        assert!(validate_synthesis_packet(&data).is_none());
    }

    #[test]
    fn test_persistence_roundtrip() {
        let tmp_dir = std::env::temp_dir().join(format!("tunnel_test_{}", std::process::id()));
        fs::create_dir_all(&tmp_dir).unwrap();

        let tunnel_id = make_hash(1);
        let dest = make_addr(3);

        // Create and populate a tunnel manager
        {
            let mut manager = TunnelManager::new(Some(tmp_dir.clone()));
            manager.register(tunnel_id, make_addr(2));
            manager.record_path(&tunnel_id, dest, make_path_entry(2));
            manager.save().unwrap();
        }

        // Load into a fresh manager
        {
            let mut manager = TunnelManager::new(Some(tmp_dir.clone()));
            manager.load().unwrap();

            assert_eq!(manager.len(), 1);
            let tunnel = manager.get(&tunnel_id).unwrap();
            // Interface should be None after loading
            assert!(tunnel.interface_hash.is_none());
            assert_eq!(tunnel.paths.len(), 1);
            let path = tunnel.paths.get(&dest).unwrap();
            assert_eq!(path.hops, 2);
        }

        // Cleanup
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_persistence_skips_empty_tunnels() {
        let tmp_dir = std::env::temp_dir().join(format!("tunnel_test_empty_{}", std::process::id()));
        fs::create_dir_all(&tmp_dir).unwrap();

        let tunnel_id = make_hash(1);

        // Save a tunnel with no paths
        {
            let mut manager = TunnelManager::new(Some(tmp_dir.clone()));
            manager.register(tunnel_id, make_addr(2));
            manager.save().unwrap();
        }

        // Load — should have no tunnels (empty tunnels are skipped)
        {
            let mut manager = TunnelManager::new(Some(tmp_dir.clone()));
            manager.load().unwrap();
            assert!(manager.is_empty());
        }

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
