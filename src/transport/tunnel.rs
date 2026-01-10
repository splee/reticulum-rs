//! Tunnel support for transport layer.
//!
//! Tunnels allow packets to be forwarded to remote transport instances,
//! enabling routing through intermediary nodes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::hash::{AddressHash, Hash};

/// Default tunnel expiry time
pub const TUNNEL_EXPIRY: Duration = Duration::from_secs(3600); // 1 hour

/// Tunnel states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TunnelState {
    /// Tunnel is being established
    Establishing = 0,
    /// Tunnel is active
    Active = 1,
    /// Tunnel is stale and needs refresh
    Stale = 2,
    /// Tunnel has expired
    Expired = 3,
}

impl Default for TunnelState {
    fn default() -> Self {
        TunnelState::Establishing
    }
}

/// Information about a tunnel to another transport instance
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    /// Tunnel ID (hash)
    pub id: Hash,
    /// Interface hash for this tunnel
    pub interface_hash: AddressHash,
    /// Remote transport identity hash
    pub remote_transport: AddressHash,
    /// Timestamp when tunnel was established
    pub established_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Current tunnel state
    pub state: TunnelState,
    /// Tunnel paths (destination hashes reachable through this tunnel)
    pub paths: Vec<AddressHash>,
    /// Whether this is an incoming or outgoing tunnel
    pub incoming: bool,
}

impl TunnelInfo {
    /// Create a new outgoing tunnel
    pub fn new_outgoing(id: Hash, interface_hash: AddressHash, remote_transport: AddressHash) -> Self {
        let now = Instant::now();
        Self {
            id,
            interface_hash,
            remote_transport,
            established_at: now,
            last_activity: now,
            state: TunnelState::Establishing,
            paths: Vec::new(),
            incoming: false,
        }
    }

    /// Create a new incoming tunnel
    pub fn new_incoming(id: Hash, interface_hash: AddressHash, remote_transport: AddressHash) -> Self {
        let now = Instant::now();
        Self {
            id,
            interface_hash,
            remote_transport,
            established_at: now,
            last_activity: now,
            state: TunnelState::Establishing,
            paths: Vec::new(),
            incoming: true,
        }
    }

    /// Mark tunnel as active
    pub fn set_active(&mut self) {
        self.state = TunnelState::Active;
        self.last_activity = Instant::now();
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        if self.state == TunnelState::Stale {
            self.state = TunnelState::Active;
        }
    }

    /// Check if tunnel has expired
    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > TUNNEL_EXPIRY
    }

    /// Get tunnel age
    pub fn age(&self) -> Duration {
        self.established_at.elapsed()
    }

    /// Add a path to this tunnel
    pub fn add_path(&mut self, destination: AddressHash) {
        if !self.paths.contains(&destination) {
            self.paths.push(destination);
        }
    }

    /// Remove a path from this tunnel
    pub fn remove_path(&mut self, destination: &AddressHash) {
        self.paths.retain(|p| p.as_slice() != destination.as_slice());
    }

    /// Check if a destination is reachable through this tunnel
    pub fn has_path(&self, destination: &AddressHash) -> bool {
        self.paths.iter().any(|p| p.as_slice() == destination.as_slice())
    }
}

/// Tunnel manager for transport layer
#[derive(Debug, Default)]
pub struct TunnelManager {
    /// Map of tunnel ID -> tunnel info
    tunnels: HashMap<Hash, TunnelInfo>,
    /// Map of destination hash -> tunnel ID (for quick lookup)
    destination_to_tunnel: HashMap<AddressHash, Hash>,
}

impl TunnelManager {
    /// Create a new tunnel manager
    pub fn new() -> Self {
        Self {
            tunnels: HashMap::new(),
            destination_to_tunnel: HashMap::new(),
        }
    }

    /// Register a new tunnel
    pub fn register(&mut self, tunnel: TunnelInfo) {
        let tunnel_id = tunnel.id.clone();

        // Update destination mappings
        for path in &tunnel.paths {
            self.destination_to_tunnel.insert(path.clone(), tunnel_id.clone());
        }

        self.tunnels.insert(tunnel_id, tunnel);
    }

    /// Get a tunnel by ID
    pub fn get(&self, tunnel_id: &Hash) -> Option<&TunnelInfo> {
        self.tunnels.get(tunnel_id)
    }

    /// Get a mutable reference to a tunnel
    pub fn get_mut(&mut self, tunnel_id: &Hash) -> Option<&mut TunnelInfo> {
        self.tunnels.get_mut(tunnel_id)
    }

    /// Find tunnel for a destination
    pub fn find_for_destination(&self, destination: &AddressHash) -> Option<&TunnelInfo> {
        self.destination_to_tunnel
            .get(destination)
            .and_then(|id| self.tunnels.get(id))
    }

    /// Remove a tunnel
    pub fn remove(&mut self, tunnel_id: &Hash) -> Option<TunnelInfo> {
        if let Some(tunnel) = self.tunnels.remove(tunnel_id) {
            // Clean up destination mappings
            for path in &tunnel.paths {
                self.destination_to_tunnel.remove(path);
            }
            Some(tunnel)
        } else {
            None
        }
    }

    /// Add a path to a tunnel
    pub fn add_path(&mut self, tunnel_id: &Hash, destination: AddressHash) {
        if let Some(tunnel) = self.tunnels.get_mut(tunnel_id) {
            tunnel.add_path(destination.clone());
            self.destination_to_tunnel.insert(destination, tunnel_id.clone());
        }
    }

    /// Remove a path from a tunnel
    pub fn remove_path(&mut self, tunnel_id: &Hash, destination: &AddressHash) {
        if let Some(tunnel) = self.tunnels.get_mut(tunnel_id) {
            tunnel.remove_path(destination);
            self.destination_to_tunnel.remove(destination);
        }
    }

    /// Clean up expired tunnels
    pub fn cleanup(&mut self) {
        let expired: Vec<Hash> = self
            .tunnels
            .iter()
            .filter(|(_, t)| t.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            self.remove(&id);
        }
    }

    /// Get all tunnel IDs
    pub fn tunnel_ids(&self) -> Vec<Hash> {
        self.tunnels.keys().cloned().collect()
    }

    /// Get number of tunnels
    pub fn len(&self) -> usize {
        self.tunnels.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.tunnels.is_empty()
    }

    /// Iterate over all tunnels
    pub fn iter(&self) -> impl Iterator<Item = (&Hash, &TunnelInfo)> {
        self.tunnels.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_creation() {
        let id = Hash::new([1u8; 32]);
        let iface = AddressHash::new_from_slice(&[2u8; 32]);
        let remote = AddressHash::new_from_slice(&[3u8; 32]);

        let tunnel = TunnelInfo::new_outgoing(id, iface, remote);
        assert_eq!(tunnel.state, TunnelState::Establishing);
        assert!(!tunnel.incoming);
    }

    #[test]
    fn test_tunnel_manager() {
        let mut manager = TunnelManager::new();

        let id = Hash::new([1u8; 32]);
        let iface = AddressHash::new_from_slice(&[2u8; 32]);
        let remote = AddressHash::new_from_slice(&[3u8; 32]);

        let mut tunnel = TunnelInfo::new_outgoing(id.clone(), iface, remote);
        let dest = AddressHash::new_from_slice(&[4u8; 32]);
        tunnel.add_path(dest.clone());

        manager.register(tunnel);

        assert!(manager.get(&id).is_some());
        assert!(manager.find_for_destination(&dest).is_some());
    }

    #[test]
    fn test_tunnel_paths() {
        let id = Hash::new([1u8; 32]);
        let iface = AddressHash::new_from_slice(&[2u8; 32]);
        let remote = AddressHash::new_from_slice(&[3u8; 32]);

        let mut tunnel = TunnelInfo::new_outgoing(id, iface, remote);
        let dest = AddressHash::new_from_slice(&[4u8; 32]);

        tunnel.add_path(dest.clone());
        assert!(tunnel.has_path(&dest));

        tunnel.remove_path(&dest);
        assert!(!tunnel.has_path(&dest));
    }
}
