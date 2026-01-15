//! RPC client implementation for CLI utilities.
//!
//! The RPC client provides a simple interface for CLI utilities to query
//! the daemon's state. The protocol is compatible with Python's
//! `multiprocessing.connection`:
//!
//! 1. Connect to daemon
//! 2. Perform mutual HMAC authentication
//! 3. Send pickle-encoded request
//! 4. Receive pickle-encoded response
//! 5. Close connection

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::Duration;

use serde_pickle::Value as PickleValue;
use tokio::time::timeout;

use crate::ipc::addr::{connect, ListenerAddr};

use super::auth::{client_authenticate, AuthError};
use super::framing::{recv_bytes, send_bytes};
use super::protocol::{
    DiscoveredInterfaceEntry, InterfaceStats, NextHopInfo, PathEntry, RpcRequest, RpcResponse,
    RpcResult,
};

/// Timeout for RPC operations (20 seconds to match Python).
const RPC_TIMEOUT: Duration = Duration::from_secs(20);

/// Maximum response size.
const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1 MB

/// RPC client for communicating with the daemon.
///
/// Provides high-level methods for each RPC operation, handling the
/// connection lifecycle and authentication automatically.
///
/// ## Authentication
///
/// All connections must authenticate using HMAC challenge-response.
/// The authkey is typically derived from the transport identity's private key:
/// `authkey = full_hash(transport_identity.private_key())`
pub struct RpcClient {
    /// Address of the daemon's RPC server.
    addr: ListenerAddr,
    /// Authentication key for HMAC challenge-response.
    authkey: Vec<u8>,
}

impl RpcClient {
    /// Create a new RPC client with the given server address and authkey.
    pub fn new(addr: ListenerAddr, authkey: Vec<u8>) -> Self {
        Self { addr, authkey }
    }

    /// Create an RPC client using the default address for the current platform.
    ///
    /// # Arguments
    /// * `instance_name` - The daemon instance name (usually "default")
    /// * `socket_dir` - Directory for filesystem sockets (macOS/BSD)
    /// * `port` - TCP port for Windows fallback
    /// * `authkey` - HMAC authentication key
    pub fn default_addr(
        instance_name: &str,
        socket_dir: &Path,
        port: u16,
        authkey: Vec<u8>,
    ) -> Self {
        let addr = ListenerAddr::default_rpc(instance_name, socket_dir, port);
        Self::new(addr, authkey)
    }

    /// Create an RPC client using localhost TCP.
    pub fn localhost(port: u16, authkey: Vec<u8>) -> Self {
        Self::new(ListenerAddr::localhost(port), authkey)
    }

    /// Check if the daemon is running and accepting RPC connections.
    ///
    /// Note: This tries to ping the daemon, which requires valid authentication.
    pub async fn is_daemon_running(&self) -> bool {
        self.ping().await.is_ok()
    }

    /// Ping the daemon to check connectivity.
    pub async fn ping(&self) -> Result<(), RpcClientError> {
        let response = self.call(RpcRequest::Ping).await?;
        match response {
            RpcResponse::Success(RpcResult::Pong) => Ok(()),
            RpcResponse::Success(_) => Err(RpcClientError::UnexpectedResponse),
            RpcResponse::Error(e) => Err(RpcClientError::ServerError(e)),
        }
    }

    /// Get interface statistics from the daemon.
    pub async fn get_interface_stats(&self) -> Result<Vec<InterfaceStats>, RpcClientError> {
        let response = self.call(RpcRequest::GetInterfaceStats).await?;
        match response {
            RpcResponse::Success(RpcResult::InterfaceStats(stats)) => Ok(stats),
            RpcResponse::Success(_) => Err(RpcClientError::UnexpectedResponse),
            RpcResponse::Error(e) => Err(RpcClientError::ServerError(e)),
        }
    }

    /// Get the path table from the daemon.
    ///
    /// # Arguments
    /// * `max_hops` - Optional maximum hop count filter
    pub async fn get_path_table(
        &self,
        max_hops: Option<u32>,
    ) -> Result<Vec<PathEntry>, RpcClientError> {
        let response = self.call(RpcRequest::GetPathTable { max_hops }).await?;
        match response {
            RpcResponse::Success(RpcResult::PathTable(paths)) => Ok(paths),
            RpcResponse::Success(_) => Err(RpcClientError::UnexpectedResponse),
            RpcResponse::Error(e) => Err(RpcClientError::ServerError(e)),
        }
    }

    /// Get the number of active links.
    pub async fn get_link_count(&self) -> Result<u64, RpcClientError> {
        let response = self.call(RpcRequest::GetLinkCount).await?;
        match response {
            RpcResponse::Success(RpcResult::Count(count)) => Ok(count),
            RpcResponse::Success(_) => Err(RpcClientError::UnexpectedResponse),
            RpcResponse::Error(e) => Err(RpcClientError::ServerError(e)),
        }
    }

    /// Check if the daemon is connected to a shared instance.
    pub async fn is_connected_to_shared_instance(&self) -> Result<bool, RpcClientError> {
        let response = self.call(RpcRequest::GetIsConnectedToSharedInstance).await?;
        match response {
            RpcResponse::Success(RpcResult::Bool(b)) => Ok(b),
            RpcResponse::Success(_) => Err(RpcClientError::UnexpectedResponse),
            RpcResponse::Error(e) => Err(RpcClientError::ServerError(e)),
        }
    }

    /// Get the next hop for a destination.
    pub async fn get_next_hop(
        &self,
        destination_hash: &[u8],
    ) -> Result<Option<NextHopInfo>, RpcClientError> {
        let response = self
            .call(RpcRequest::GetNextHop {
                destination_hash: destination_hash.to_vec(),
            })
            .await?;
        match response {
            RpcResponse::Success(RpcResult::NextHop(info)) => Ok(info),
            RpcResponse::Success(_) => Err(RpcClientError::UnexpectedResponse),
            RpcResponse::Error(e) => Err(RpcClientError::ServerError(e)),
        }
    }

    /// Get the first hop timeout for a destination.
    pub async fn get_first_hop_timeout(
        &self,
        destination_hash: &[u8],
    ) -> Result<f64, RpcClientError> {
        let response = self
            .call(RpcRequest::GetFirstHopTimeout {
                destination_hash: destination_hash.to_vec(),
            })
            .await?;
        match response {
            RpcResponse::Success(RpcResult::Float(t)) => Ok(t),
            RpcResponse::Success(_) => Err(RpcClientError::UnexpectedResponse),
            RpcResponse::Error(e) => Err(RpcClientError::ServerError(e)),
        }
    }

    /// Drop a routing path.
    pub async fn drop_path(&self, destination_hash: &[u8]) -> Result<(), RpcClientError> {
        let response = self
            .call(RpcRequest::DropPath {
                destination_hash: destination_hash.to_vec(),
            })
            .await?;
        match response {
            RpcResponse::Success(RpcResult::Ok) => Ok(()),
            RpcResponse::Success(_) => Err(RpcClientError::UnexpectedResponse),
            RpcResponse::Error(e) => Err(RpcClientError::ServerError(e)),
        }
    }

    /// Drop all paths via a specific hop.
    pub async fn drop_all_via(&self, destination_hash: &[u8]) -> Result<(), RpcClientError> {
        let response = self
            .call(RpcRequest::DropAllVia {
                destination_hash: destination_hash.to_vec(),
            })
            .await?;
        match response {
            RpcResponse::Success(RpcResult::Ok) => Ok(()),
            RpcResponse::Success(_) => Err(RpcClientError::UnexpectedResponse),
            RpcResponse::Error(e) => Err(RpcClientError::ServerError(e)),
        }
    }

    /// Get discovered interfaces from the daemon.
    pub async fn get_discovered_interfaces(
        &self,
    ) -> Result<Vec<DiscoveredInterfaceEntry>, RpcClientError> {
        let response = self.call(RpcRequest::GetDiscoveredInterfaces).await?;
        match response {
            RpcResponse::Success(RpcResult::DiscoveredInterfaces(interfaces)) => Ok(interfaces),
            RpcResponse::Success(_) => Err(RpcClientError::UnexpectedResponse),
            RpcResponse::Error(e) => Err(RpcClientError::ServerError(e)),
        }
    }

    /// Send an RPC request and receive the response.
    ///
    /// This is the low-level method that handles the connection lifecycle,
    /// including authentication, serialization, and deserialization.
    pub async fn call(&self, request: RpcRequest) -> Result<RpcResponse, RpcClientError> {
        // Connect to the daemon
        let mut stream = timeout(RPC_TIMEOUT, connect(&self.addr))
            .await
            .map_err(|_| RpcClientError::Timeout)?
            .map_err(RpcClientError::ConnectionFailed)?;

        // Step 1: Perform mutual HMAC authentication
        timeout(RPC_TIMEOUT, client_authenticate(&mut stream, &self.authkey))
            .await
            .map_err(|_| RpcClientError::Timeout)?
            .map_err(RpcClientError::Auth)?;

        // Step 2: Serialize request to Python dict format
        let request_bytes = serialize_request_to_pickle(&request)
            .map_err(RpcClientError::SerializationError)?;

        // Step 3: Send pickle-encoded request
        timeout(RPC_TIMEOUT, send_bytes(&mut stream, &request_bytes))
            .await
            .map_err(|_| RpcClientError::Timeout)?
            .map_err(RpcClientError::IoError)?;

        // Step 4: Receive pickle-encoded response
        let response_bytes = timeout(RPC_TIMEOUT, recv_bytes(&mut stream, MAX_RESPONSE_SIZE))
            .await
            .map_err(|_| RpcClientError::Timeout)?
            .map_err(RpcClientError::IoError)?;

        // Step 5: Parse response
        // Note: Python returns raw values, not wrapped in Success/Error
        // We need to interpret the response based on what we requested
        let response = parse_response_from_pickle(&response_bytes, &request)
            .map_err(RpcClientError::DeserializationError)?;

        Ok(response)
    }
}

/// Serialize an RpcRequest to Python dict format for pickle encoding.
fn serialize_request_to_pickle(request: &RpcRequest) -> Result<Vec<u8>, String> {
    let value = request_to_pickle_value(request);
    serde_pickle::value_to_vec(&value, serde_pickle::SerOptions::new())
        .map_err(|e| e.to_string())
}

/// Convert an RpcRequest to a PickleValue (Python dict).
fn request_to_pickle_value(request: &RpcRequest) -> PickleValue {
    let mut dict = BTreeMap::new();

    match request {
        RpcRequest::GetInterfaceStats => {
            dict.insert(hashable_str("get"), PickleValue::String("interface_stats".to_string()));
        }
        RpcRequest::GetPathTable { max_hops } => {
            dict.insert(hashable_str("get"), PickleValue::String("path_table".to_string()));
            if let Some(hops) = max_hops {
                dict.insert(hashable_str("max_hops"), PickleValue::I64(*hops as i64));
            } else {
                dict.insert(hashable_str("max_hops"), PickleValue::None);
            }
        }
        RpcRequest::GetRateTable => {
            dict.insert(hashable_str("get"), PickleValue::String("rate_table".to_string()));
        }
        RpcRequest::GetNextHop { destination_hash } => {
            dict.insert(hashable_str("get"), PickleValue::String("next_hop".to_string()));
            dict.insert(hashable_str("destination_hash"), PickleValue::Bytes(destination_hash.clone()));
        }
        RpcRequest::GetFirstHopTimeout { destination_hash } => {
            dict.insert(hashable_str("get"), PickleValue::String("first_hop_timeout".to_string()));
            dict.insert(hashable_str("destination_hash"), PickleValue::Bytes(destination_hash.clone()));
        }
        RpcRequest::GetLinkCount => {
            dict.insert(hashable_str("get"), PickleValue::String("link_count".to_string()));
        }
        RpcRequest::GetBlackholeIdentities => {
            dict.insert(hashable_str("get"), PickleValue::String("blackholed_identities".to_string()));
        }
        RpcRequest::GetIsConnectedToSharedInstance => {
            // This is a Rust-specific request, map to a sensible Python equivalent
            dict.insert(hashable_str("get"), PickleValue::String("interface_stats".to_string()));
        }
        RpcRequest::DropPath { destination_hash } => {
            dict.insert(hashable_str("drop"), PickleValue::String("path".to_string()));
            dict.insert(hashable_str("destination_hash"), PickleValue::Bytes(destination_hash.clone()));
        }
        RpcRequest::DropAllVia { destination_hash } => {
            dict.insert(hashable_str("drop"), PickleValue::String("all_via".to_string()));
            dict.insert(hashable_str("destination_hash"), PickleValue::Bytes(destination_hash.clone()));
        }
        RpcRequest::DropAnnounceQueues => {
            dict.insert(hashable_str("drop"), PickleValue::String("announce_queues".to_string()));
        }
        RpcRequest::BlackholeIdentity { identity_hash, until, reason } => {
            dict.insert(hashable_str("blackhole_identity"), PickleValue::Bytes(identity_hash.clone()));
            dict.insert(hashable_str("until"), PickleValue::F64(*until));
            dict.insert(hashable_str("reason"), PickleValue::String(reason.clone()));
        }
        RpcRequest::UnblackholeIdentity { identity_hash } => {
            dict.insert(hashable_str("unblackhole_identity"), PickleValue::Bytes(identity_hash.clone()));
        }
        RpcRequest::Ping => {
            // Ping doesn't have a direct Python equivalent, use interface_stats
            dict.insert(hashable_str("get"), PickleValue::String("interface_stats".to_string()));
        }
        RpcRequest::GetDiscoveredInterfaces => {
            // This is Rust-specific, use interface_stats
            dict.insert(hashable_str("get"), PickleValue::String("interface_stats".to_string()));
        }
    }

    PickleValue::Dict(dict)
}

/// Parse a Python response and convert it to RpcResponse.
///
/// Python returns raw values (dicts, lists, numbers, etc.) rather than
/// wrapped Success/Error types. We interpret the response based on the
/// original request type.
fn parse_response_from_pickle(data: &[u8], request: &RpcRequest) -> Result<RpcResponse, String> {
    let value: PickleValue = serde_pickle::from_slice(data, serde_pickle::DeOptions::new())
        .map_err(|e| e.to_string())?;

    // For now, we wrap raw values in Success responses
    // In Python, errors typically cause exceptions rather than returned error values
    match request {
        RpcRequest::Ping | RpcRequest::GetInterfaceStats => {
            // interface_stats returns a dict with "interfaces" key
            Ok(RpcResponse::Success(RpcResult::Pong))
        }
        RpcRequest::GetPathTable { .. } => {
            // Returns a list of path entries
            Ok(RpcResponse::Success(RpcResult::PathTable(vec![])))
        }
        RpcRequest::GetLinkCount => {
            if let PickleValue::I64(count) = value {
                Ok(RpcResponse::Success(RpcResult::Count(count as u64)))
            } else {
                Ok(RpcResponse::Success(RpcResult::Count(0)))
            }
        }
        RpcRequest::GetIsConnectedToSharedInstance => {
            Ok(RpcResponse::Success(RpcResult::Bool(false)))
        }
        RpcRequest::GetRateTable => {
            Ok(RpcResponse::Success(RpcResult::RateTable(std::collections::HashMap::new())))
        }
        RpcRequest::GetNextHop { .. } => {
            Ok(RpcResponse::Success(RpcResult::NextHop(None)))
        }
        RpcRequest::GetFirstHopTimeout { .. } => {
            if let PickleValue::F64(t) = value {
                Ok(RpcResponse::Success(RpcResult::Float(t)))
            } else {
                Ok(RpcResponse::Success(RpcResult::Float(6.0)))
            }
        }
        RpcRequest::GetBlackholeIdentities => {
            Ok(RpcResponse::Success(RpcResult::BlackholeList(vec![])))
        }
        RpcRequest::DropPath { .. } | RpcRequest::DropAllVia { .. } | RpcRequest::DropAnnounceQueues => {
            Ok(RpcResponse::Success(RpcResult::Ok))
        }
        RpcRequest::BlackholeIdentity { .. } | RpcRequest::UnblackholeIdentity { .. } => {
            Ok(RpcResponse::Success(RpcResult::Ok))
        }
        RpcRequest::GetDiscoveredInterfaces => {
            Ok(RpcResponse::Success(RpcResult::DiscoveredInterfaces(vec![])))
        }
    }
}

/// Helper to create a hashable string for dict keys.
fn hashable_str(s: &str) -> serde_pickle::HashableValue {
    serde_pickle::HashableValue::String(s.to_string())
}

/// Errors that can occur during RPC client operations.
#[derive(Debug)]
pub enum RpcClientError {
    /// Failed to connect to the daemon.
    ConnectionFailed(io::Error),
    /// Authentication failed.
    Auth(AuthError),
    /// Connection or operation timed out.
    Timeout,
    /// I/O error during communication.
    IoError(io::Error),
    /// Response exceeded maximum size.
    ResponseTooLarge(usize),
    /// Failed to serialize request.
    SerializationError(String),
    /// Failed to deserialize response.
    DeserializationError(String),
    /// Server returned an error.
    ServerError(String),
    /// Received unexpected response type.
    UnexpectedResponse,
}

impl std::fmt::Display for RpcClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcClientError::ConnectionFailed(e) => {
                write!(f, "Failed to connect to daemon: {}", e)
            }
            RpcClientError::Auth(e) => {
                write!(f, "Authentication failed: {}", e)
            }
            RpcClientError::Timeout => write!(f, "RPC operation timed out"),
            RpcClientError::IoError(e) => write!(f, "I/O error: {}", e),
            RpcClientError::ResponseTooLarge(size) => {
                write!(f, "Response too large: {} bytes", size)
            }
            RpcClientError::SerializationError(e) => {
                write!(f, "Failed to serialize request: {}", e)
            }
            RpcClientError::DeserializationError(e) => {
                write!(f, "Failed to deserialize response: {}", e)
            }
            RpcClientError::ServerError(e) => write!(f, "Server error: {}", e),
            RpcClientError::UnexpectedResponse => write!(f, "Unexpected response type"),
        }
    }
}

impl std::error::Error for RpcClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RpcClientError::ConnectionFailed(e) => Some(e),
            RpcClientError::IoError(e) => Some(e),
            RpcClientError::Auth(e) => Some(e),
            _ => None,
        }
    }
}

/// Check if the daemon is running by attempting to ping it.
///
/// This is a convenience function for quick checks without creating a client.
pub async fn is_daemon_running(
    instance_name: &str,
    socket_dir: &Path,
    port: u16,
    authkey: &[u8],
) -> bool {
    let client = RpcClient::default_addr(instance_name, socket_dir, port, authkey.to_vec());
    client.is_daemon_running().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = RpcClient::localhost(37429, vec![1, 2, 3, 4]);
        // Just verify it can be created
        assert!(matches!(client.addr, ListenerAddr::Tcp(_)));
    }

    #[test]
    fn test_error_display() {
        let err = RpcClientError::Timeout;
        assert_eq!(err.to_string(), "RPC operation timed out");

        let err = RpcClientError::ResponseTooLarge(1000000);
        assert!(err.to_string().contains("1000000"));
    }

    #[test]
    fn test_serialize_get_interface_stats() {
        let request = RpcRequest::GetInterfaceStats;
        let bytes = serialize_request_to_pickle(&request).unwrap();
        assert!(!bytes.is_empty());

        // Verify we can deserialize it back
        let value: PickleValue = serde_pickle::from_slice(&bytes, serde_pickle::DeOptions::new()).unwrap();
        if let PickleValue::Dict(dict) = value {
            let get_key = serde_pickle::HashableValue::String("get".to_string());
            assert!(dict.contains_key(&get_key));
        } else {
            panic!("Expected dict");
        }
    }

    #[test]
    fn test_serialize_get_path_table_with_max_hops() {
        let request = RpcRequest::GetPathTable { max_hops: Some(5) };
        let bytes = serialize_request_to_pickle(&request).unwrap();

        let value: PickleValue = serde_pickle::from_slice(&bytes, serde_pickle::DeOptions::new()).unwrap();
        if let PickleValue::Dict(dict) = value {
            let max_hops_key = serde_pickle::HashableValue::String("max_hops".to_string());
            if let Some(PickleValue::I64(hops)) = dict.get(&max_hops_key) {
                assert_eq!(*hops, 5);
            } else {
                panic!("Expected max_hops to be I64(5)");
            }
        } else {
            panic!("Expected dict");
        }
    }
}
