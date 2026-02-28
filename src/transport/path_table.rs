use std::{collections::HashMap, time::{Duration, Instant}};

use serde::{Deserialize, Serialize};

use crate::{
    destination::NAME_HASH_LENGTH,
    hash::{AddressHash, Hash},
    identity::PUBLIC_KEY_LENGTH,
    iface::stats::InterfaceMode,
    packet::{DestinationType, Header, HeaderType, IfacFlag, Packet, PacketType, TransportType},
};

/// Max hops for pathfinding (matches Python's PATHFINDER_M = 128).
pub const PATHFINDER_M: u8 = 128;

/// Path state tracking for unresponsive path detection.
///
/// Mirrors Python's Transport.STATE_UNKNOWN/STATE_UNRESPONSIVE/STATE_RESPONSIVE.
/// Used to allow higher-hop announces to replace paths that have become unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PathState {
    #[default]
    Unknown = 0x00,
    Unresponsive = 0x01,
    Responsive = 0x02,
}

/// A 10-byte random blob extracted from announce packets.
///
/// Bytes [0..5] are random data, bytes [5..10] encode the emission timestamp
/// as a big-endian u40. Used to detect replayed announces and determine
/// announce freshness.
pub type RandomBlob = [u8; 10];

/// Maximum number of random blobs per destination to keep in memory.
pub const MAX_RANDOM_BLOBS: usize = 64;

/// Maximum number of random blobs per destination to persist to disk.
#[allow(dead_code)]
pub const PERSIST_RANDOM_BLOBS: usize = 32;

/// Offset into announce packet data where the random blob starts.
/// This is PUBLIC_KEY_LENGTH * 2 (64 bytes for encryption + signing keys) +
/// NAME_HASH_LENGTH (10 bytes for the name hash) = 74.
const RANDOM_BLOB_OFFSET: usize = PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH;

/// Length of the random blob in bytes.
const RANDOM_BLOB_LENGTH: usize = 10;

/// Extract the emission timestamp (u40) from bytes [5..10] of a random blob.
///
/// The timestamp is stored as big-endian in the last 5 bytes of the blob.
/// We pad it into a u64 by placing those 5 bytes at positions [3..8].
pub fn emission_timestamp_from_blob(blob: &RandomBlob) -> u64 {
    let mut buf = [0u8; 8];
    buf[3..8].copy_from_slice(&blob[5..10]);
    u64::from_be_bytes(buf)
}

/// Get the maximum emission timestamp across all random blobs.
pub fn timebase_from_blobs(blobs: &[RandomBlob]) -> u64 {
    blobs.iter().map(emission_timestamp_from_blob).max().unwrap_or(0)
}

/// Extract the 10-byte random blob from announce packet data at the standard offset.
///
/// Returns None if the packet data is too short.
pub fn extract_random_blob(packet_data: &[u8]) -> Option<RandomBlob> {
    if packet_data.len() < RANDOM_BLOB_OFFSET + RANDOM_BLOB_LENGTH {
        return None;
    }
    let mut blob = [0u8; RANDOM_BLOB_LENGTH];
    blob.copy_from_slice(&packet_data[RANDOM_BLOB_OFFSET..RANDOM_BLOB_OFFSET + RANDOM_BLOB_LENGTH]);
    Some(blob)
}

/// Default path expiration time (1 week, matching Python's PATHFINDER_E).
///
/// Python reference (Transport.py lines 70-72):
/// - PATHFINDER_E = 60*60*24*7 (1 week = 604800 seconds) - standard path expiration
/// - AP_PATH_TIME = 60*60*24 (1 day) - for Access Point paths
/// - ROAMING_PATH_TIME = 60*60*6 (6 hours) - for Roaming paths
pub const PATH_EXPIRY_TIME: Duration = Duration::from_secs(60 * 60 * 24 * 7);

/// Path expiry for Access Point mode interfaces (1 day)
pub const PATH_EXPIRY_ACCESS_POINT: Duration = Duration::from_secs(60 * 60 * 24);

/// Path expiry for Roaming mode interfaces (6 hours)
pub const PATH_EXPIRY_ROAMING: Duration = Duration::from_secs(60 * 60 * 6);

/// Get the path expiry duration for a given interface mode.
///
/// Returns the appropriate expiry based on Python reference:
/// - Full/Normal/others: 1 week (PATH_EXPIRY_TIME)
/// - AccessPoint: 1 day (PATH_EXPIRY_ACCESS_POINT)
/// - Roaming: 6 hours (PATH_EXPIRY_ROAMING)
pub fn path_expiry_for_mode(mode: InterfaceMode) -> Duration {
    match mode {
        InterfaceMode::AccessPoint => PATH_EXPIRY_ACCESS_POINT,
        InterfaceMode::Roaming => PATH_EXPIRY_ROAMING,
        _ => PATH_EXPIRY_TIME,
    }
}

/// Internal path entry stored in the path table
pub struct PathEntry {
    pub timestamp: Instant,
    pub received_from: AddressHash,
    pub hops: u8,
    pub iface: AddressHash,
    pub packet_hash: Hash,
    /// Expiry duration based on the interface mode that received the announce
    pub expiry_duration: Duration,
    /// Random blobs from announces for this destination, used for replay detection
    /// and emission timestamp comparison.
    pub random_blobs: Vec<RandomBlob>,
    /// Cached announce packet for path responses.
    ///
    /// The announce_table evicts entries after retransmission completes (~5-6s),
    /// but path responses need the announce packet for the lifetime of the path.
    /// Storing it here ensures path requests can be answered at any time.
    pub announce_packet: Packet,
}

/// Path information for external display/queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathInfo {
    /// Destination address hash (hex string)
    pub destination: String,
    /// Next hop address hash (hex string)
    pub next_hop: String,
    /// Interface hash through which path was learned (hex string)
    pub interface_hash: String,
    /// Number of hops to destination
    pub hops: u8,
    /// Unix timestamp when path was learned
    pub timestamp: f64,
    /// Unix timestamp when path expires (None if no expiration)
    pub expires: Option<f64>,
}

pub struct PathTable {
    map: HashMap<AddressHash, PathEntry>,
    /// Per-destination path state tracking for unresponsive detection
    path_states: HashMap<AddressHash, PathState>,
    /// Track when each entry was created for expiration
    #[allow(dead_code)]
    created_at: Instant,
}

impl PathTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            path_states: HashMap::new(),
            created_at: Instant::now(),
        }
    }

    /// Get the cached announce packet for a destination, if the path is still valid.
    ///
    /// Used for path responses — the announce packet is needed to construct the
    /// response even long after the announce_table has evicted its copy.
    pub fn get_announce_packet(&self, destination: &AddressHash) -> Option<&Packet> {
        self.map.get(destination).and_then(|entry| {
            if entry.timestamp.elapsed() > entry.expiry_duration {
                None
            } else {
                Some(&entry.announce_packet)
            }
        })
    }

    /// Check if a path to destination exists and is not expired.
    pub fn has_path(&self, destination: &AddressHash) -> bool {
        self.map
            .get(destination)
            .is_some_and(|entry| entry.timestamp.elapsed() <= entry.expiry_duration)
    }

    /// Get the number of hops to destination
    pub fn hops_to(&self, destination: &AddressHash) -> Option<u8> {
        self.map.get(destination).and_then(|entry| {
            if entry.timestamp.elapsed() > entry.expiry_duration {
                None
            } else {
                Some(entry.hops)
            }
        })
    }

    /// Get the number of hops to a destination, or PATHFINDER_M if unknown.
    pub fn hops_to_or_max(&self, destination: &AddressHash) -> u8 {
        self.hops_to(destination).unwrap_or(PATHFINDER_M)
    }

    /// Mark a destination's path state as Unknown.
    /// Returns true if the path exists (and state was set).
    pub fn mark_path_unknown_state(&mut self, dest: &AddressHash) -> bool {
        if self.map.contains_key(dest) {
            self.path_states.insert(*dest, PathState::Unknown);
            true
        } else {
            false
        }
    }

    /// Mark a destination's path state as Unresponsive.
    /// Returns true if the path exists (and state was set).
    pub fn mark_path_unresponsive(&mut self, dest: &AddressHash) -> bool {
        if self.map.contains_key(dest) {
            self.path_states.insert(*dest, PathState::Unresponsive);
            true
        } else {
            false
        }
    }

    /// Mark a destination's path state as Responsive.
    /// Returns true if the path exists (and state was set).
    pub fn mark_path_responsive(&mut self, dest: &AddressHash) -> bool {
        if self.map.contains_key(dest) {
            self.path_states.insert(*dest, PathState::Responsive);
            true
        } else {
            false
        }
    }

    /// Check if a destination's path is in Unresponsive state.
    pub fn path_is_unresponsive(&self, dest: &AddressHash) -> bool {
        self.path_states.get(dest).copied() == Some(PathState::Unresponsive)
    }

    /// Get all paths, optionally filtered by maximum hop count
    pub fn get_paths(&self, max_hops: Option<u8>) -> Vec<PathInfo> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        self.map
            .iter()
            .filter(|(_, entry)| {
                // Filter out expired paths (using stored expiry duration)
                if entry.timestamp.elapsed() > entry.expiry_duration {
                    return false;
                }
                // Filter by max hops if specified
                if let Some(max) = max_hops {
                    if entry.hops > max {
                        return false;
                    }
                }
                true
            })
            .map(|(dest, entry)| {
                // Calculate timestamps (using stored expiry duration)
                let entry_timestamp = now - entry.timestamp.elapsed().as_secs_f64();
                let expires_in = entry.expiry_duration.saturating_sub(entry.timestamp.elapsed());
                let expires_timestamp = now + expires_in.as_secs_f64();

                PathInfo {
                    destination: format!("{}", dest),
                    next_hop: format!("{}", entry.received_from),
                    interface_hash: format!("{}", entry.iface),
                    hops: entry.hops,
                    timestamp: entry_timestamp,
                    expires: Some(expires_timestamp),
                }
            })
            .collect()
    }

    /// Drop a specific path entry
    /// Returns true if path was found and removed
    pub fn drop_path(&mut self, destination: &AddressHash) -> bool {
        self.path_states.remove(destination);
        self.map.remove(destination).is_some()
    }

    /// Drop all paths that go through a specific transport instance
    /// Returns the number of paths dropped
    pub fn drop_via(&mut self, transport_hash: &AddressHash) -> usize {
        let before_count = self.map.len();
        self.map.retain(|_, entry| entry.received_from != *transport_hash);
        before_count - self.map.len()
    }

    /// Remove expired path entries
    /// Returns the number of entries removed
    pub fn cleanup_expired(&mut self) -> usize {
        let before_count = self.map.len();
        self.map.retain(|dest, entry| {
            let keep = entry.timestamp.elapsed() <= entry.expiry_duration;
            if !keep {
                self.path_states.remove(dest);
            }
            keep
        });
        before_count - self.map.len()
    }

    /// Get the number of entries in the path table
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if the path table is empty
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn next_hop_full(&self, destination: &AddressHash) -> Option<(AddressHash, AddressHash)> {
        self.map.get(destination).and_then(|entry| {
            if entry.timestamp.elapsed() > entry.expiry_duration {
                None
            } else {
                Some((entry.received_from, entry.iface))
            }
        })
    }

    pub fn next_hop_iface(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.map.get(destination).and_then(|entry| {
            if entry.timestamp.elapsed() > entry.expiry_duration {
                None
            } else {
                Some(entry.iface)
            }
        })
    }

    pub fn next_hop(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.map.get(destination).and_then(|entry| {
            if entry.timestamp.elapsed() > entry.expiry_duration {
                None
            } else {
                Some(entry.received_from)
            }
        })
    }

    /// Handle an announce packet and update the path table.
    ///
    /// Implements the Python multi-factor path update decision tree:
    /// 1. Extract random blob and compute emission timestamp
    /// 2. If no existing path → accept
    /// 3. If hops <= existing hops → accept if blob is new AND emitted > timebase
    /// 4. If hops > existing hops:
    ///    a. If path expired → accept if blob is new
    ///    b. If emitted > existing max emission → accept if blob is new
    ///    c. If emitted == existing max emission → accept if path is unresponsive
    ///    d. Otherwise → reject
    ///
    /// Returns true if the path was updated, false if rejected.
    pub fn handle_announce(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
        iface_mode: InterfaceMode,
    ) -> bool {
        let hops = announce.header.hops + 1;
        let random_blob = extract_random_blob(announce.data.as_slice());
        let announce_emitted = random_blob
            .as_ref()
            .map(emission_timestamp_from_blob)
            .unwrap_or(0);

        let should_add;

        if let Some(existing) = self.map.get(&announce.destination) {
            let existing_blobs = &existing.random_blobs;

            if hops <= existing.hops {
                // Equal or fewer hops: accept only if blob is new and emitted > timebase
                let path_timebase = timebase_from_blobs(existing_blobs);
                if random_blob.is_some()
                    && !existing_blobs.contains(random_blob.as_ref().unwrap())
                    && announce_emitted > path_timebase
                {
                    self.mark_path_unknown_state(&announce.destination);
                    should_add = true;
                } else {
                    should_add = false;
                }
            } else {
                // More hops than existing: only accept under specific conditions
                let path_expired = existing.timestamp.elapsed() > existing.expiry_duration;

                // Compute max emission from existing blobs, with early exit optimization
                let mut path_announce_emitted: u64 = 0;
                for blob in existing_blobs {
                    path_announce_emitted = path_announce_emitted.max(emission_timestamp_from_blob(blob));
                    if path_announce_emitted >= announce_emitted {
                        break;
                    }
                }

                let blob_is_new = random_blob.is_some()
                    && !existing_blobs.contains(random_blob.as_ref().unwrap());

                if path_expired {
                    // Expired path: accept if blob is new
                    if blob_is_new {
                        log::debug!(
                            "Replacing path for {} with new announce due to expired path",
                            announce.destination
                        );
                        self.mark_path_unknown_state(&announce.destination);
                        should_add = true;
                    } else {
                        should_add = false;
                    }
                } else if announce_emitted > path_announce_emitted {
                    // More recently emitted: accept if blob is new
                    if blob_is_new {
                        log::debug!(
                            "Replacing path for {} with new announce, since it was more recently emitted",
                            announce.destination
                        );
                        self.mark_path_unknown_state(&announce.destination);
                        should_add = true;
                    } else {
                        should_add = false;
                    }
                } else if announce_emitted == path_announce_emitted {
                    // Same emission time: accept only if current path is unresponsive
                    if self.path_is_unresponsive(&announce.destination) {
                        log::debug!(
                            "Replacing path for {} with new announce, since previously tried path was unresponsive",
                            announce.destination
                        );
                        // Note: Python does NOT call mark_path_unknown_state here
                        should_add = true;
                    } else {
                        should_add = false;
                    }
                } else {
                    should_add = false;
                }
            }
        } else {
            // No existing path — always accept
            should_add = true;
        }

        if !should_add {
            return false;
        }

        // Collect the existing random_blobs before inserting the new entry
        let mut random_blobs = self.map.get(&announce.destination)
            .map(|e| e.random_blobs.clone())
            .unwrap_or_default();

        // Append new blob if not duplicate, truncate to MAX_RANDOM_BLOBS from end
        if let Some(blob) = random_blob {
            if !random_blobs.contains(&blob) {
                random_blobs.push(blob);
                if random_blobs.len() > MAX_RANDOM_BLOBS {
                    let start = random_blobs.len() - MAX_RANDOM_BLOBS;
                    random_blobs = random_blobs[start..].to_vec();
                }
            }
        }

        let received_from = transport_id.unwrap_or(announce.destination);
        let expiry_duration = path_expiry_for_mode(iface_mode);
        let new_entry = PathEntry {
            timestamp: Instant::now(),
            received_from,
            hops,
            iface,
            packet_hash: announce.hash(),
            expiry_duration,
            random_blobs,
            announce_packet: *announce,
        };

        self.map.insert(announce.destination, new_entry);

        log::info!(
            "{} is now reachable over {} hops through {} (expiry: {:?})",
            announce.destination,
            hops,
            received_from,
            expiry_duration,
        );

        true
    }

    pub fn handle_inbound_packet(
        &self,
        original_packet: &Packet,
        lookup: Option<AddressHash>,
    ) -> (Packet, Option<AddressHash>) {
        let lookup = lookup.unwrap_or(original_packet.destination);

        let entry = match self.map.get(&lookup) {
            Some(entry) if entry.timestamp.elapsed() <= entry.expiry_duration => entry,
            _ => return (*original_packet, None),
        };

        // When hops == 1, the next hop IS the destination, so we strip the transport
        // header and use HEADER_1 format. This matches Python's behavior where
        // remaining_hops == 1 triggers stripping transport headers.
        if entry.hops == 1 {
            (
                Packet {
                    header: Header {
                        ifac_flag: IfacFlag::Authenticated,
                        header_type: HeaderType::Type1,
                        context_flag: original_packet.header.context_flag,
                        transport_type: original_packet.header.transport_type,
                        destination_type: original_packet.header.destination_type,
                        packet_type: original_packet.header.packet_type,
                        hops: original_packet.header.hops + 1,
                    },
                    ifac: None,
                    destination: original_packet.destination,
                    transport: None, // No transport header for last hop
                    context: original_packet.context,
                    data: original_packet.data,
                    ratchet_id: None,
                },
                Some(entry.iface),
            )
        } else {
            (
                Packet {
                    header: Header {
                        ifac_flag: IfacFlag::Authenticated,
                        header_type: HeaderType::Type2,
                        context_flag: original_packet.header.context_flag,
                        // Type2 packets must use Transport transport type for Python compatibility
                        // Python expects bit 4 = 1 (transport_type=TRANSPORT) for routed packets
                        transport_type: TransportType::Transport,
                        destination_type: original_packet.header.destination_type,
                        packet_type: original_packet.header.packet_type,
                        hops: original_packet.header.hops + 1,
                    },
                    ifac: None,
                    destination: original_packet.destination,
                    transport: Some(entry.received_from),
                    context: original_packet.context,
                    data: original_packet.data,
                    ratchet_id: None,
                },
                Some(entry.iface),
            )
        }
    }

    pub fn refresh(&mut self, destination: &AddressHash) {
        if let Some(entry) = self.map.get_mut(destination) {
            entry.timestamp = Instant::now();
        }
    }

    pub fn handle_packet(&self, original_packet: &Packet) -> (Packet, Option<AddressHash>) {
        if original_packet.header.header_type == HeaderType::Type2 {
            return (*original_packet, None);
        }

        if original_packet.header.packet_type == PacketType::Announce {
            return (*original_packet, None);
        }

        if original_packet.header.destination_type == DestinationType::Plain
            || original_packet.header.destination_type == DestinationType::Group
        {
            return (*original_packet, None);
        }

        let entry = match self.map.get(&original_packet.destination) {
            Some(entry) if entry.timestamp.elapsed() <= entry.expiry_duration => entry,
            _ => return (*original_packet, None),
        };

        // When hops == 1, the next hop IS the destination, so we keep HEADER_1 format
        // without transport header. This matches Python's behavior.
        if entry.hops == 1 {
            // Keep the original packet format (HEADER_1) since destination is direct
            log::debug!(
                "path_table: routing {} hops=1 direct, iface={}",
                original_packet.destination,
                entry.iface,
            );
            (*original_packet, Some(entry.iface))
        } else {
            log::debug!(
                "path_table: routing {} via transport {} (hops={}), iface={}",
                original_packet.destination,
                entry.received_from,
                entry.hops,
                entry.iface,
            );
            (
                Packet {
                    header: Header {
                        // Preserve original ifac_flag - Python expects Open for Type2 packets
                        ifac_flag: original_packet.header.ifac_flag,
                        header_type: HeaderType::Type2,
                        context_flag: original_packet.header.context_flag,
                        // Type2 packets must use Transport transport type for Python compatibility
                        // Python expects bit 4 = 1 (transport_type=TRANSPORT) for routed packets
                        transport_type: TransportType::Transport,
                        destination_type: original_packet.header.destination_type,
                        packet_type: original_packet.header.packet_type,
                        hops: original_packet.header.hops,
                    },
                    ifac: original_packet.ifac,
                    destination: original_packet.destination,
                    transport: Some(entry.received_from),
                    context: original_packet.context,
                    data: original_packet.data,
                    ratchet_id: None,
                },
                Some(entry.iface),
            )
        }
    }
}

impl Default for PathTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PacketContext, PacketDataBuffer};

    /// Helper to create a zero AddressHash for testing
    fn zero_address_hash() -> AddressHash {
        AddressHash::new_from_slice(&[0u8; 16])
    }

    /// Helper to create a dummy announce packet for PathEntry construction in tests.
    fn dummy_announce_packet() -> Packet {
        Packet {
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
            destination: zero_address_hash(),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new(),
            ratchet_id: None,
        }
    }

    #[test]
    fn test_has_path() {
        let mut table = PathTable::new();
        let dest = zero_address_hash();

        assert!(!table.has_path(&dest));

        // Add a path entry manually
        table.map.insert(dest, PathEntry {
            timestamp: Instant::now(),
            received_from: zero_address_hash(),
            hops: 1,
            iface: zero_address_hash(),
            packet_hash: Hash::new_empty(),
            expiry_duration: PATH_EXPIRY_TIME,
            random_blobs: Vec::new(),
            announce_packet: dummy_announce_packet(),
        });

        assert!(table.has_path(&dest));
    }

    #[test]
    fn test_drop_path() {
        let mut table = PathTable::new();
        let dest = zero_address_hash();

        table.map.insert(dest, PathEntry {
            timestamp: Instant::now(),
            received_from: zero_address_hash(),
            hops: 1,
            iface: zero_address_hash(),
            packet_hash: Hash::new_empty(),
            expiry_duration: PATH_EXPIRY_TIME,
            random_blobs: Vec::new(),
            announce_packet: dummy_announce_packet(),
        });

        assert!(table.drop_path(&dest));
        assert!(!table.has_path(&dest));
        assert!(!table.drop_path(&dest)); // Second drop returns false
    }

    #[test]
    fn test_get_paths_with_max_hops() {
        let mut table = PathTable::new();

        // Add entries with different hop counts
        for i in 1..=5 {
            let mut dest = [0u8; 16];
            dest[0] = i;
            let dest = AddressHash::new_from_slice(&dest);

            table.map.insert(dest, PathEntry {
                timestamp: Instant::now(),
                received_from: zero_address_hash(),
                hops: i,
                iface: zero_address_hash(),
                packet_hash: Hash::new_empty(),
                expiry_duration: PATH_EXPIRY_TIME,
                random_blobs: Vec::new(),
                announce_packet: dummy_announce_packet(),
            });
        }

        // Get all paths
        let all_paths = table.get_paths(None);
        assert_eq!(all_paths.len(), 5);

        // Get paths with max 3 hops
        let filtered_paths = table.get_paths(Some(3));
        assert_eq!(filtered_paths.len(), 3);
    }

    #[test]
    fn test_path_expiry_for_mode() {
        // Test that path_expiry_for_mode returns correct durations for each mode
        assert_eq!(path_expiry_for_mode(InterfaceMode::Full), PATH_EXPIRY_TIME);
        assert_eq!(path_expiry_for_mode(InterfaceMode::AccessPoint), PATH_EXPIRY_ACCESS_POINT);
        assert_eq!(path_expiry_for_mode(InterfaceMode::Roaming), PATH_EXPIRY_ROAMING);
        assert_eq!(path_expiry_for_mode(InterfaceMode::PointToPoint), PATH_EXPIRY_TIME);
        assert_eq!(path_expiry_for_mode(InterfaceMode::Boundary), PATH_EXPIRY_TIME);
        assert_eq!(path_expiry_for_mode(InterfaceMode::Gateway), PATH_EXPIRY_TIME);
    }

    #[test]
    fn test_path_expiry_durations() {
        // Verify the duration values match Python implementation
        assert_eq!(PATH_EXPIRY_TIME.as_secs(), 60 * 60 * 24 * 7); // 1 week
        assert_eq!(PATH_EXPIRY_ACCESS_POINT.as_secs(), 60 * 60 * 24); // 1 day
        assert_eq!(PATH_EXPIRY_ROAMING.as_secs(), 60 * 60 * 6); // 6 hours
    }

    // =========================================================================
    // RandomBlob and emission timestamp tests
    // =========================================================================

    #[test]
    fn test_emission_timestamp_from_blob() {
        // Bytes [5..10] = [0x00, 0x00, 0x01, 0x00, 0x00] = 65536
        let mut blob: RandomBlob = [0u8; 10];
        blob[7] = 0x01; // position [7] maps to big-endian byte
        let ts = emission_timestamp_from_blob(&blob);
        assert_eq!(ts, 65536);

        // All zeros → 0
        let zero_blob: RandomBlob = [0u8; 10];
        assert_eq!(emission_timestamp_from_blob(&zero_blob), 0);

        // All 0xFF in bytes [5..10] → max u40 = 2^40 - 1
        let mut max_blob: RandomBlob = [0u8; 10];
        max_blob[5..10].fill(0xFF);
        assert_eq!(emission_timestamp_from_blob(&max_blob), (1u64 << 40) - 1);

        // Known value: bytes [5..10] = [0, 0, 0, 0, 42] → 42
        let mut blob42: RandomBlob = [0u8; 10];
        blob42[9] = 42;
        assert_eq!(emission_timestamp_from_blob(&blob42), 42);
    }

    #[test]
    fn test_timebase_from_blobs() {
        // Empty blobs → 0
        assert_eq!(timebase_from_blobs(&[]), 0);

        // Single blob
        let mut b1: RandomBlob = [0u8; 10];
        b1[9] = 10;
        assert_eq!(timebase_from_blobs(&[b1]), 10);

        // Multiple blobs — returns max
        let mut b2: RandomBlob = [0u8; 10];
        b2[9] = 20;
        let mut b3: RandomBlob = [0u8; 10];
        b3[9] = 5;
        assert_eq!(timebase_from_blobs(&[b1, b2, b3]), 20);
    }

    #[test]
    fn test_extract_random_blob() {
        // Packet data too short
        let short_data = [0u8; 80]; // needs >= 84 (74 + 10)
        assert!(extract_random_blob(&short_data).is_none());

        // Exact minimum length (74 + 10 = 84)
        let mut data = [0u8; 84];
        data[74..84].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let blob = extract_random_blob(&data).unwrap();
        assert_eq!(blob, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        // Longer packet data also works
        let mut long_data = [0u8; 200];
        long_data[74..84].copy_from_slice(&[0xAA; 10]);
        let blob = extract_random_blob(&long_data).unwrap();
        assert_eq!(blob, [0xAA; 10]);
    }

    // =========================================================================
    // PathState tests
    // =========================================================================

    #[test]
    fn test_path_state_default() {
        assert_eq!(PathState::default(), PathState::Unknown);
    }

    #[test]
    fn test_path_state_transitions() {
        let mut table = PathTable::new();
        let dest = zero_address_hash();

        // No path exists — state changes should return false
        assert!(!table.mark_path_unresponsive(&dest));
        assert!(!table.mark_path_responsive(&dest));
        assert!(!table.mark_path_unknown_state(&dest));
        assert!(!table.path_is_unresponsive(&dest));

        // Add a path
        table.map.insert(dest, PathEntry {
            timestamp: Instant::now(),
            received_from: zero_address_hash(),
            hops: 2,
            iface: zero_address_hash(),
            packet_hash: Hash::new_empty(),
            expiry_duration: PATH_EXPIRY_TIME,
            random_blobs: Vec::new(),
            announce_packet: dummy_announce_packet(),
        });

        // Default state is not unresponsive
        assert!(!table.path_is_unresponsive(&dest));

        // Mark unresponsive
        assert!(table.mark_path_unresponsive(&dest));
        assert!(table.path_is_unresponsive(&dest));

        // Mark responsive
        assert!(table.mark_path_responsive(&dest));
        assert!(!table.path_is_unresponsive(&dest));

        // Mark unknown
        assert!(table.mark_path_unknown_state(&dest));
        assert!(!table.path_is_unresponsive(&dest));
    }

    #[test]
    fn test_path_state_cleanup_on_drop() {
        let mut table = PathTable::new();
        let dest = zero_address_hash();

        table.map.insert(dest, PathEntry {
            timestamp: Instant::now(),
            received_from: zero_address_hash(),
            hops: 1,
            iface: zero_address_hash(),
            packet_hash: Hash::new_empty(),
            expiry_duration: PATH_EXPIRY_TIME,
            random_blobs: Vec::new(),
            announce_packet: dummy_announce_packet(),
        });

        table.mark_path_unresponsive(&dest);
        assert!(table.path_is_unresponsive(&dest));

        // Drop the path — state should be cleaned up
        table.drop_path(&dest);
        assert!(!table.path_is_unresponsive(&dest));
    }

    // =========================================================================
    // hops_to_or_max tests
    // =========================================================================

    #[test]
    fn test_hops_to_or_max() {
        let mut table = PathTable::new();
        let dest = zero_address_hash();

        // Unknown destination → PATHFINDER_M (128)
        assert_eq!(table.hops_to_or_max(&dest), PATHFINDER_M);
        assert_eq!(table.hops_to_or_max(&dest), 128);

        // Known destination → actual hops
        table.map.insert(dest, PathEntry {
            timestamp: Instant::now(),
            received_from: zero_address_hash(),
            hops: 3,
            iface: zero_address_hash(),
            packet_hash: Hash::new_empty(),
            expiry_duration: PATH_EXPIRY_TIME,
            random_blobs: Vec::new(),
            announce_packet: dummy_announce_packet(),
        });

        assert_eq!(table.hops_to_or_max(&dest), 3);
    }

    // =========================================================================
    // Multi-factor handle_announce tests
    // =========================================================================

    /// Create a test announce packet with specific hops and random blob data.
    fn make_announce_packet(dest: AddressHash, hops: u8, blob_bytes: &RandomBlob) -> Packet {
        use crate::packet::{PacketDataBuffer, PacketContext};

        // Build packet data: 64 bytes public keys + 10 bytes name hash + 10 bytes random blob
        let mut data = PacketDataBuffer::new();
        // 64 bytes of key data (PUBLIC_KEY_LENGTH * 2)
        data.chain_safe_write(&[0u8; 64]);
        // 10 bytes name hash
        data.chain_safe_write(&[0u8; NAME_HASH_LENGTH]);
        // 10 bytes random blob
        data.chain_safe_write(blob_bytes);

        Packet {
            header: Header {
                hops, // handle_announce will add 1
                ..Default::default()
            },
            destination: dest,
            data,
            context: PacketContext::None,
            ..Default::default()
        }
    }

    /// Helper to make a random blob with a specific emission timestamp
    fn blob_with_timestamp(ts: u64) -> RandomBlob {
        let mut blob = [0u8; 10];
        // Encode timestamp into bytes [5..10] as big-endian u40
        let ts_bytes = ts.to_be_bytes(); // 8 bytes
        // u40 occupies the last 5 bytes of the u64 big-endian representation
        blob[5..10].copy_from_slice(&ts_bytes[3..8]);
        blob
    }

    #[test]
    fn test_handle_announce_new_destination_accepted() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);
        let blob = blob_with_timestamp(100);
        let packet = make_announce_packet(dest, 2, &blob);

        let result = table.handle_announce(&packet, None, zero_address_hash(), InterfaceMode::Full);
        assert!(result, "New destination should always be accepted");
        assert!(table.has_path(&dest));
        assert_eq!(table.hops_to(&dest), Some(3)); // hops + 1

        // Random blob should be stored
        let entry = table.map.get(&dest).unwrap();
        assert_eq!(entry.random_blobs.len(), 1);
        assert_eq!(entry.random_blobs[0], blob);
    }

    #[test]
    fn test_handle_announce_fewer_hops_new_blob_accepted() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);

        // First announce: 3 hops (packet hops=2), timestamp=100
        let blob1 = blob_with_timestamp(100);
        let p1 = make_announce_packet(dest, 2, &blob1);
        assert!(table.handle_announce(&p1, None, zero_address_hash(), InterfaceMode::Full));

        // Second announce: 2 hops (packet hops=1), newer timestamp, new blob → accepted
        let blob2 = blob_with_timestamp(200);
        let p2 = make_announce_packet(dest, 1, &blob2);
        assert!(table.handle_announce(&p2, None, zero_address_hash(), InterfaceMode::Full));
        assert_eq!(table.hops_to(&dest), Some(2));
    }

    #[test]
    fn test_handle_announce_equal_hops_new_blob_newer_accepted() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);

        let blob1 = blob_with_timestamp(100);
        let p1 = make_announce_packet(dest, 2, &blob1);
        assert!(table.handle_announce(&p1, None, zero_address_hash(), InterfaceMode::Full));

        // Same hop count, new blob, newer timestamp → accepted
        let blob2 = blob_with_timestamp(200);
        let p2 = make_announce_packet(dest, 2, &blob2);
        assert!(table.handle_announce(&p2, None, zero_address_hash(), InterfaceMode::Full));

        // Should now have 2 random blobs
        let entry = table.map.get(&dest).unwrap();
        assert_eq!(entry.random_blobs.len(), 2);
    }

    #[test]
    fn test_handle_announce_duplicate_blob_rejected() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);

        let blob = blob_with_timestamp(100);
        let p1 = make_announce_packet(dest, 2, &blob);
        assert!(table.handle_announce(&p1, None, zero_address_hash(), InterfaceMode::Full));

        // Same blob, same hops → rejected (replay protection)
        let p2 = make_announce_packet(dest, 2, &blob);
        assert!(!table.handle_announce(&p2, None, zero_address_hash(), InterfaceMode::Full));
    }

    #[test]
    fn test_handle_announce_equal_hops_older_timestamp_rejected() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);

        let blob1 = blob_with_timestamp(200);
        let p1 = make_announce_packet(dest, 2, &blob1);
        assert!(table.handle_announce(&p1, None, zero_address_hash(), InterfaceMode::Full));

        // Same hops, new blob but OLDER timestamp → rejected
        let blob2 = blob_with_timestamp(100);
        let p2 = make_announce_packet(dest, 2, &blob2);
        assert!(!table.handle_announce(&p2, None, zero_address_hash(), InterfaceMode::Full));
    }

    #[test]
    fn test_handle_announce_more_hops_newer_emission_accepted() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);

        let blob1 = blob_with_timestamp(100);
        let p1 = make_announce_packet(dest, 1, &blob1); // 2 hops
        assert!(table.handle_announce(&p1, None, zero_address_hash(), InterfaceMode::Full));

        // More hops but newer emission → accepted
        let blob2 = blob_with_timestamp(200);
        let p2 = make_announce_packet(dest, 3, &blob2); // 4 hops
        assert!(table.handle_announce(&p2, None, zero_address_hash(), InterfaceMode::Full));
        assert_eq!(table.hops_to(&dest), Some(4));
    }

    #[test]
    fn test_handle_announce_more_hops_same_emission_rejected() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);

        let blob1 = blob_with_timestamp(100);
        let p1 = make_announce_packet(dest, 1, &blob1);
        assert!(table.handle_announce(&p1, None, zero_address_hash(), InterfaceMode::Full));

        // More hops, same emission time, path responsive → rejected
        let blob2 = blob_with_timestamp(100);
        // Different blob bytes but same timestamp
        blob2[0]; // Just referencing; create a genuinely different blob
        let mut blob2_diff: RandomBlob = [0x42; 10];
        // Set timestamp to 100
        let ts_bytes = 100u64.to_be_bytes();
        blob2_diff[5..10].copy_from_slice(&ts_bytes[3..8]);

        let p2 = make_announce_packet(dest, 3, &blob2_diff);
        assert!(!table.handle_announce(&p2, None, zero_address_hash(), InterfaceMode::Full));
    }

    #[test]
    fn test_handle_announce_more_hops_unresponsive_path_accepted() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);

        let blob1 = blob_with_timestamp(100);
        let p1 = make_announce_packet(dest, 1, &blob1);
        assert!(table.handle_announce(&p1, None, zero_address_hash(), InterfaceMode::Full));

        // Mark path as unresponsive
        table.mark_path_unresponsive(&dest);

        // More hops, same emission, but path is unresponsive → accepted
        let mut blob2: RandomBlob = [0x42; 10];
        let ts_bytes = 100u64.to_be_bytes();
        blob2[5..10].copy_from_slice(&ts_bytes[3..8]);
        let p2 = make_announce_packet(dest, 3, &blob2);
        assert!(table.handle_announce(&p2, None, zero_address_hash(), InterfaceMode::Full));
    }

    #[test]
    fn test_handle_announce_expired_path_new_blob_accepted() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);

        // Insert an expired path manually
        let blob1 = blob_with_timestamp(100);
        table.map.insert(dest, PathEntry {
            timestamp: Instant::now() - Duration::from_secs(60 * 60 * 24 * 8), // 8 days ago
            received_from: zero_address_hash(),
            hops: 2,
            iface: zero_address_hash(),
            packet_hash: Hash::new_empty(),
            expiry_duration: PATH_EXPIRY_TIME, // 7 days
            random_blobs: vec![blob1],
            announce_packet: dummy_announce_packet(),
        });

        // More hops but new blob on expired path → accepted
        let blob2 = blob_with_timestamp(50); // Even older timestamp is fine for expired path
        let p2 = make_announce_packet(dest, 4, &blob2);
        assert!(table.handle_announce(&p2, None, zero_address_hash(), InterfaceMode::Full));
    }

    #[test]
    fn test_handle_announce_max_random_blobs_truncation() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);

        // Fill up with MAX_RANDOM_BLOBS entries by inserting directly
        let mut blobs = Vec::new();
        for i in 0..MAX_RANDOM_BLOBS {
            blobs.push(blob_with_timestamp(i as u64));
        }
        table.map.insert(dest, PathEntry {
            timestamp: Instant::now(),
            received_from: zero_address_hash(),
            hops: 5,
            iface: zero_address_hash(),
            packet_hash: Hash::new_empty(),
            expiry_duration: PATH_EXPIRY_TIME,
            random_blobs: blobs,
            announce_packet: dummy_announce_packet(),
        });

        // Add one more via announce (fewer hops, newer timestamp)
        let new_blob = blob_with_timestamp((MAX_RANDOM_BLOBS + 1) as u64);
        let packet = make_announce_packet(dest, 0, &new_blob); // 1 hop
        assert!(table.handle_announce(&packet, None, zero_address_hash(), InterfaceMode::Full));

        // Should still be MAX_RANDOM_BLOBS (oldest was evicted)
        let entry = table.map.get(&dest).unwrap();
        assert_eq!(entry.random_blobs.len(), MAX_RANDOM_BLOBS);
        // The newest blob should be the last one
        assert_eq!(*entry.random_blobs.last().unwrap(), new_blob);
        // The oldest (timestamp=0) should have been evicted
        assert!(!entry.random_blobs.contains(&blob_with_timestamp(0)));
    }

    #[test]
    fn test_handle_announce_returns_bool() {
        let mut table = PathTable::new();
        let dest = AddressHash::new_from_slice(&[1u8; 16]);
        let blob = blob_with_timestamp(100);
        let packet = make_announce_packet(dest, 2, &blob);

        // First call accepts
        assert!(table.handle_announce(&packet, None, zero_address_hash(), InterfaceMode::Full));

        // Duplicate blob same hops rejects
        assert!(!table.handle_announce(&packet, None, zero_address_hash(), InterfaceMode::Full));
    }
}
