//! RPC client implementation for CLI utilities.
//!
//! The RPC client provides a simple interface for CLI utilities to query
//! the daemon's state. Each method establishes a connection, sends a request,
//! receives a response, and closes the connection.

use std::io;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::ipc::addr::{connect, ListenerAddr};

use super::protocol::{
    DiscoveredInterfaceEntry, InterfaceStats, NextHopInfo, PathEntry, RpcRequest, RpcResponse,
    RpcResult,
};

/// Timeout for RPC operations.
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum response size.
const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1 MB

/// RPC client for communicating with the daemon.
///
/// Provides high-level methods for each RPC operation, handling the
/// connection lifecycle automatically.
pub struct RpcClient {
    /// Address of the daemon's RPC server.
    addr: ListenerAddr,
}

impl RpcClient {
    /// Create a new RPC client with the given server address.
    pub fn new(addr: ListenerAddr) -> Self {
        Self { addr }
    }

    /// Create an RPC client using the default address for the current platform.
    ///
    /// # Arguments
    /// * `instance_name` - The daemon instance name (usually "default")
    /// * `socket_dir` - Directory for filesystem sockets (macOS/BSD)
    /// * `port` - TCP port for Windows fallback
    pub fn default_addr(instance_name: &str, socket_dir: &Path, port: u16) -> Self {
        let addr = ListenerAddr::default_rpc(instance_name, socket_dir, port);
        Self::new(addr)
    }

    /// Create an RPC client using localhost TCP.
    pub fn localhost(port: u16) -> Self {
        Self::new(ListenerAddr::localhost(port))
    }

    /// Check if the daemon is running and accepting RPC connections.
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
    /// This is the low-level method that handles the connection lifecycle.
    pub async fn call(&self, request: RpcRequest) -> Result<RpcResponse, RpcClientError> {
        // Connect to the daemon
        let stream = timeout(RPC_TIMEOUT, connect(&self.addr))
            .await
            .map_err(|_| RpcClientError::Timeout)?
            .map_err(RpcClientError::ConnectionFailed)?;

        let (mut reader, mut writer) = tokio::io::split(stream);

        // Serialize request
        let request_bytes =
            rmp_serde::to_vec(&request).map_err(|e| RpcClientError::SerializationError(e.to_string()))?;

        // Send request length and body
        let len_bytes = (request_bytes.len() as u32).to_be_bytes();

        timeout(RPC_TIMEOUT, async {
            writer.write_all(&len_bytes).await?;
            writer.write_all(&request_bytes).await?;
            writer.flush().await?;
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(|_| RpcClientError::Timeout)?
        .map_err(RpcClientError::IoError)?;

        // Read response length
        let mut len_bytes = [0u8; 4];
        timeout(RPC_TIMEOUT, reader.read_exact(&mut len_bytes))
            .await
            .map_err(|_| RpcClientError::Timeout)?
            .map_err(RpcClientError::IoError)?;

        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > MAX_RESPONSE_SIZE {
            return Err(RpcClientError::ResponseTooLarge(len));
        }

        // Read response body
        let mut response_bytes = vec![0u8; len];
        timeout(RPC_TIMEOUT, reader.read_exact(&mut response_bytes))
            .await
            .map_err(|_| RpcClientError::Timeout)?
            .map_err(RpcClientError::IoError)?;

        // Deserialize response
        let response: RpcResponse = rmp_serde::from_slice(&response_bytes)
            .map_err(|e| RpcClientError::DeserializationError(e.to_string()))?;

        Ok(response)
    }
}

/// Errors that can occur during RPC client operations.
#[derive(Debug)]
pub enum RpcClientError {
    /// Failed to connect to the daemon.
    ConnectionFailed(io::Error),
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
            _ => None,
        }
    }
}

/// Check if the daemon is running by attempting to ping it.
///
/// This is a convenience function for quick checks without creating a client.
pub async fn is_daemon_running(instance_name: &str, socket_dir: &Path, port: u16) -> bool {
    let client = RpcClient::default_addr(instance_name, socket_dir, port);
    client.is_daemon_running().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = RpcClient::localhost(37429);
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
}
