use std::{collections::HashMap, time::{Duration, Instant}};

use serde::{Deserialize, Serialize};

use crate::{
    hash::{AddressHash, Hash},
    iface::stats::InterfaceMode,
    packet::{DestinationType, Header, HeaderType, IfacFlag, Packet, PacketType, TransportType},
};

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
    /// Track when each entry was created for expiration
    #[allow(dead_code)]
    created_at: Instant,
}

impl PathTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            created_at: Instant::now(),
        }
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
        self.map.retain(|_, entry| entry.timestamp.elapsed() <= entry.expiry_duration);
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
    /// The `iface_mode` parameter determines the path expiry duration:
    /// - AccessPoint: 1 day
    /// - Roaming: 6 hours
    /// - Full/others: 1 week
    pub fn handle_announce(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
        iface_mode: InterfaceMode,
    ) {
        let hops = announce.header.hops + 1;

        if let Some(existing_entry) = self.map.get(&announce.destination) {
            if hops >= existing_entry.hops {
                return;
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
        };

        self.map.insert(announce.destination, new_entry);

        log::info!(
            "{} is now reachable over {} hops through {} (expiry: {:?})",
            announce.destination,
            hops,
            received_from,
            expiry_duration,
        );
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

    /// Helper to create a zero AddressHash for testing
    fn zero_address_hash() -> AddressHash {
        AddressHash::new_from_slice(&[0u8; 16])
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
}
