//! RPC protocol types for daemon communication.
//!
//! Defines the request and response types that can be exchanged between
//! CLI utilities and the daemon process.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// RPC request types that clients can send to the daemon.
///
/// These match the operations supported by the Python implementation's
/// RPC interface in `RNS/Reticulum.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcRequest {
    /// Get the routing path table.
    /// Optionally filter by maximum hop count.
    GetPathTable {
        /// Maximum number of hops to include (None = all)
        max_hops: Option<u32>,
    },

    /// Get statistics for all interfaces.
    GetInterfaceStats,

    /// Get the current rate table (bitrates).
    GetRateTable,

    /// Get the next hop for a destination.
    GetNextHop {
        /// Destination hash (16 bytes)
        destination_hash: Vec<u8>,
    },

    /// Get the first hop timeout for a destination.
    GetFirstHopTimeout {
        /// Destination hash (16 bytes)
        destination_hash: Vec<u8>,
    },

    /// Get the number of active links.
    GetLinkCount,

    /// Get the list of blackholed identities.
    GetBlackholeIdentities,

    /// Check if the daemon is connected to shared instance.
    GetIsConnectedToSharedInstance,

    /// Drop a routing path for a destination.
    DropPath {
        /// Destination hash (16 bytes)
        destination_hash: Vec<u8>,
    },

    /// Drop all paths that route via a specific destination.
    DropAllVia {
        /// Via destination hash (16 bytes)
        destination_hash: Vec<u8>,
    },

    /// Drop all pending announce queues.
    DropAnnounceQueues,

    /// Blackhole an identity (block announcements/packets).
    BlackholeIdentity {
        /// Identity hash to blackhole (16 bytes)
        identity_hash: Vec<u8>,
        /// Unix timestamp when blackhole expires (0 = permanent)
        until: f64,
        /// Reason for blackholing
        reason: String,
    },

    /// Remove an identity from the blackhole list.
    UnblackholeIdentity {
        /// Identity hash to remove (16 bytes)
        identity_hash: Vec<u8>,
    },

    /// Ping the daemon to check if it's alive.
    Ping,

    /// Get discovered interfaces (from network announcements).
    GetDiscoveredInterfaces,
}

/// RPC response from the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResponse {
    /// Successful response with data.
    Success(RpcResult),
    /// Error response with message.
    Error(String),
}

/// Successful RPC result types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResult {
    /// No data returned (for mutation operations).
    Ok,

    /// Pong response to ping.
    Pong,

    /// Boolean result.
    Bool(bool),

    /// Integer result (e.g., link count).
    Count(u64),

    /// Float result (e.g., timeout value).
    Float(f64),

    /// Path table result.
    PathTable(Vec<PathEntry>),

    /// Interface statistics result.
    InterfaceStats(Vec<InterfaceStats>),

    /// Rate table result.
    RateTable(HashMap<String, u64>),

    /// Next hop result.
    NextHop(Option<NextHopInfo>),

    /// Blackholed identities list.
    BlackholeList(Vec<BlackholeEntry>),

    /// Discovered interfaces list.
    DiscoveredInterfaces(Vec<DiscoveredInterfaceEntry>),
}

/// Entry in the routing path table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathEntry {
    /// Destination hash (hex encoded for display)
    pub destination_hash: String,
    /// Number of hops to destination
    pub hops: u32,
    /// Unix timestamp when path expires
    pub expires: f64,
    /// Interface name for next hop
    pub interface: String,
    /// Next hop address (hex encoded)
    pub via: Option<String>,
}

/// Statistics for a single interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStats {
    /// Interface name
    pub name: String,
    /// Interface type (e.g., "TCPClientInterface")
    pub interface_type: String,
    /// Whether interface is online/connected
    pub online: bool,
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Interface bitrate (if known)
    pub bitrate: Option<u64>,
    /// Interface address/endpoint
    pub address: String,
}

/// Information about the next hop for a destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextHopInfo {
    /// Next hop interface name
    pub interface: String,
    /// Next hop address (hex encoded)
    pub via: Option<String>,
    /// Number of hops
    pub hops: u32,
}

/// Entry in the blackhole list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackholeEntry {
    /// Identity hash (hex encoded)
    pub identity_hash: String,
    /// Unix timestamp when blackhole expires (0 = permanent)
    pub until: f64,
    /// Reason for blackholing
    pub reason: String,
}

/// Discovered interface entry from network announcements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredInterfaceEntry {
    /// Interface name
    pub name: String,
    /// Interface type (e.g., "RNodeInterface")
    #[serde(rename = "type")]
    pub interface_type: String,
    /// Status string ("available", "unknown", "stale")
    pub status: String,
    /// Whether interface supports transport
    pub transport: bool,
    /// Number of hops to interface
    pub hops: u8,
    /// Unix timestamp when first discovered
    pub discovered: f64,
    /// Unix timestamp when last heard
    pub last_heard: f64,
    /// Stamp value (proof-of-work difficulty achieved)
    pub value: u32,
    /// Transport identity hash (hex encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_id: Option<String>,
    /// Network identity hash (hex encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    /// Latitude coordinate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    /// Longitude coordinate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    /// Height/altitude in meters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<f32>,
    /// Radio frequency in Hz
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency: Option<u64>,
    /// Radio bandwidth in Hz
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<u64>,
    /// LoRa spreading factor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sf: Option<u8>,
    /// LoRa coding rate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cr: Option<u8>,
    /// Modulation type (e.g., "LoRa")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modulation: Option<String>,
    /// Network address/hostname to reach this interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachable_on: Option<String>,
    /// Network port
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// IFAC network name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_netname: Option<String>,
    /// IFAC network key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_netkey: Option<String>,
    /// Generated config entry for adding this interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_entry: Option<String>,
}

impl RpcRequest {
    /// Returns a human-readable name for this request type.
    pub fn name(&self) -> &'static str {
        match self {
            RpcRequest::GetPathTable { .. } => "GetPathTable",
            RpcRequest::GetInterfaceStats => "GetInterfaceStats",
            RpcRequest::GetRateTable => "GetRateTable",
            RpcRequest::GetNextHop { .. } => "GetNextHop",
            RpcRequest::GetFirstHopTimeout { .. } => "GetFirstHopTimeout",
            RpcRequest::GetLinkCount => "GetLinkCount",
            RpcRequest::GetBlackholeIdentities => "GetBlackholeIdentities",
            RpcRequest::GetIsConnectedToSharedInstance => "GetIsConnectedToSharedInstance",
            RpcRequest::DropPath { .. } => "DropPath",
            RpcRequest::DropAllVia { .. } => "DropAllVia",
            RpcRequest::DropAnnounceQueues => "DropAnnounceQueues",
            RpcRequest::BlackholeIdentity { .. } => "BlackholeIdentity",
            RpcRequest::UnblackholeIdentity { .. } => "UnblackholeIdentity",
            RpcRequest::Ping => "Ping",
            RpcRequest::GetDiscoveredInterfaces => "GetDiscoveredInterfaces",
        }
    }
}

impl RpcResponse {
    /// Create a success response with the given result.
    pub fn success(result: RpcResult) -> Self {
        RpcResponse::Success(result)
    }

    /// Create an error response with the given message.
    pub fn error(message: impl Into<String>) -> Self {
        RpcResponse::Error(message.into())
    }

    /// Check if this is a successful response.
    pub fn is_success(&self) -> bool {
        matches!(self, RpcResponse::Success(_))
    }

    /// Get the result if this is a success response.
    pub fn result(&self) -> Option<&RpcResult> {
        match self {
            RpcResponse::Success(result) => Some(result),
            RpcResponse::Error(_) => None,
        }
    }

    /// Get the error message if this is an error response.
    pub fn error_message(&self) -> Option<&str> {
        match self {
            RpcResponse::Success(_) => None,
            RpcResponse::Error(msg) => Some(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = RpcRequest::GetPathTable { max_hops: Some(5) };
        let encoded = rmp_serde::to_vec(&request).unwrap();
        let decoded: RpcRequest = rmp_serde::from_slice(&encoded).unwrap();

        match decoded {
            RpcRequest::GetPathTable { max_hops } => {
                assert_eq!(max_hops, Some(5));
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn test_response_serialization() {
        let response = RpcResponse::success(RpcResult::Count(42));
        let encoded = rmp_serde::to_vec(&response).unwrap();
        let decoded: RpcResponse = rmp_serde::from_slice(&encoded).unwrap();

        assert!(decoded.is_success());
        match decoded.result() {
            Some(RpcResult::Count(n)) => assert_eq!(*n, 42),
            _ => panic!("Wrong result type"),
        }
    }

    #[test]
    fn test_error_response() {
        let response = RpcResponse::error("Something went wrong");
        assert!(!response.is_success());
        assert_eq!(response.error_message(), Some("Something went wrong"));
    }
}
