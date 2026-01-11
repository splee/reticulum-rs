//! RPC server implementation for daemon mode.
//!
//! The RPC server listens for connections from CLI utilities and handles
//! queries about daemon state. Each connection follows a simple pattern:
//! connect → receive request → send response → close.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::ipc::addr::{IpcListener, ListenerAddr};
use crate::transport::Transport;

use super::protocol::{
    InterfaceStats, PathEntry, RpcRequest, RpcResponse, RpcResult,
};

/// Maximum size of an RPC message (16 KB should be plenty).
const MAX_MESSAGE_SIZE: usize = 16 * 1024;

/// RPC server that handles management queries from CLI utilities.
///
/// The server listens on a Unix socket (or TCP on Windows) and processes
/// RPC requests from local clients like rnstatus, rnpath, etc.
pub struct RpcServer {
    /// Address to listen on.
    addr: ListenerAddr,
    /// Reference to the transport for querying state.
    transport: Arc<Transport>,
    /// Cancellation token for shutdown.
    cancel: CancellationToken,
}

impl RpcServer {
    /// Create a new RPC server.
    ///
    /// # Arguments
    /// * `addr` - The address to listen on
    /// * `transport` - Reference to the daemon's transport
    /// * `cancel` - Cancellation token for graceful shutdown
    pub fn new(
        addr: ListenerAddr,
        transport: Arc<Transport>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            addr,
            transport,
            cancel,
        }
    }

    /// Start the RPC server and handle connections until cancelled.
    pub async fn run(self) {
        loop {
            if self.cancel.is_cancelled() {
                break;
            }

            let listener = match IpcListener::bind(&self.addr).await {
                Ok(l) => l,
                Err(e) => {
                    log::warn!("rpc_server: couldn't bind to {}: {}", self.addr.display(), e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            log::info!("rpc_server: listening on {}", self.addr.display());

            loop {
                if self.cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = self.cancel.cancelled() => {
                        break;
                    }

                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                log::debug!("rpc_server: connection from <{}>", peer_addr);

                                let transport = self.transport.clone();

                                // Handle each connection in a separate task
                                tokio::spawn(async move {
                                    if let Err(e) = handle_rpc_connection(stream, transport).await {
                                        log::debug!("rpc_server: client <{}> error: {}", peer_addr, e);
                                    }
                                });
                            }
                            Err(e) => {
                                log::warn!("rpc_server: accept error: {}", e);
                            }
                        }
                    }
                }
            }
        }

        log::info!("rpc_server: shutting down");
    }
}

/// Handle a single RPC connection.
///
/// Reads one request, processes it, sends the response, then closes.
async fn handle_rpc_connection(
    stream: crate::ipc::addr::IpcStream,
    transport: Arc<Transport>,
) -> Result<(), RpcError> {
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Read request length (4-byte big-endian)
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(RpcError::MessageTooLarge(len));
    }

    // Read request body
    let mut request_bytes = vec![0u8; len];
    reader.read_exact(&mut request_bytes).await?;

    // Deserialize request
    let request: RpcRequest = rmp_serde::from_slice(&request_bytes)
        .map_err(|e| RpcError::DeserializationError(e.to_string()))?;

    log::debug!("rpc_server: received request: {}", request.name());

    // Process request
    let response = process_request(request, &transport).await;

    // Serialize response
    let response_bytes = rmp_serde::to_vec(&response)
        .map_err(|e| RpcError::SerializationError(e.to_string()))?;

    // Send response length and body
    let len_bytes = (response_bytes.len() as u32).to_be_bytes();
    writer.write_all(&len_bytes).await?;
    writer.write_all(&response_bytes).await?;
    writer.flush().await?;

    Ok(())
}

/// Process an RPC request and return the response.
async fn process_request(request: RpcRequest, transport: &Transport) -> RpcResponse {
    match request {
        RpcRequest::Ping => RpcResponse::success(RpcResult::Pong),

        RpcRequest::GetInterfaceStats => {
            // For now, return empty stats - the interface manager doesn't track
            // detailed statistics yet. This will be expanded when stats are added.
            let stats = get_interface_stats(transport).await;
            RpcResponse::success(RpcResult::InterfaceStats(stats))
        }

        RpcRequest::GetPathTable { max_hops } => {
            let paths = get_path_table(transport, max_hops).await;
            RpcResponse::success(RpcResult::PathTable(paths))
        }

        RpcRequest::GetLinkCount => {
            let count = get_link_count(transport).await;
            RpcResponse::success(RpcResult::Count(count))
        }

        RpcRequest::GetIsConnectedToSharedInstance => {
            // The daemon itself is never connected to a shared instance
            RpcResponse::success(RpcResult::Bool(false))
        }

        RpcRequest::GetRateTable => {
            // Rate table not yet implemented
            RpcResponse::success(RpcResult::RateTable(std::collections::HashMap::new()))
        }

        RpcRequest::GetNextHop { destination_hash } => {
            let next_hop = get_next_hop(transport, &destination_hash).await;
            RpcResponse::success(RpcResult::NextHop(next_hop))
        }

        RpcRequest::GetFirstHopTimeout { destination_hash } => {
            let timeout = get_first_hop_timeout(transport, &destination_hash).await;
            RpcResponse::success(RpcResult::Float(timeout))
        }

        RpcRequest::GetBlackholeIdentities => {
            // Blackhole list not yet implemented
            RpcResponse::success(RpcResult::BlackholeList(vec![]))
        }

        RpcRequest::DropPath { destination_hash } => {
            match drop_path(transport, &destination_hash).await {
                Ok(_) => RpcResponse::success(RpcResult::Ok),
                Err(e) => RpcResponse::error(e),
            }
        }

        RpcRequest::DropAllVia { destination_hash } => {
            match drop_all_via(transport, &destination_hash).await {
                Ok(_) => RpcResponse::success(RpcResult::Ok),
                Err(e) => RpcResponse::error(e),
            }
        }

        RpcRequest::DropAnnounceQueues => {
            // Not yet implemented
            RpcResponse::success(RpcResult::Ok)
        }

        RpcRequest::BlackholeIdentity { .. } => {
            // Not yet implemented
            RpcResponse::success(RpcResult::Ok)
        }

        RpcRequest::UnblackholeIdentity { .. } => {
            // Not yet implemented
            RpcResponse::success(RpcResult::Ok)
        }
    }
}

/// Get interface statistics from the transport.
async fn get_interface_stats(_transport: &Transport) -> Vec<InterfaceStats> {
    // The current InterfaceManager doesn't track detailed statistics.
    // This is a placeholder that will be expanded when stats tracking is added.
    //
    // For now, we return basic info about connected interfaces.
    vec![]
}

/// Get the path table from the transport.
async fn get_path_table(_transport: &Transport, _max_hops: Option<u32>) -> Vec<PathEntry> {
    // Access to path table requires exposing it through Transport.
    // This is a placeholder that will be expanded.
    vec![]
}

/// Get the number of active links.
async fn get_link_count(_transport: &Transport) -> u64 {
    // Access to link count requires exposing it through Transport.
    // This is a placeholder.
    0
}

/// Get the next hop for a destination.
async fn get_next_hop(
    _transport: &Transport,
    _destination_hash: &[u8],
) -> Option<super::protocol::NextHopInfo> {
    // Access to routing info requires exposing it through Transport.
    None
}

/// Get the first hop timeout for a destination.
async fn get_first_hop_timeout(_transport: &Transport, _destination_hash: &[u8]) -> f64 {
    // Default timeout value
    6.0
}

/// Drop a routing path.
async fn drop_path(_transport: &Transport, _destination_hash: &[u8]) -> Result<(), String> {
    // Not yet implemented
    Ok(())
}

/// Drop all paths via a specific hop.
async fn drop_all_via(_transport: &Transport, _destination_hash: &[u8]) -> Result<(), String> {
    // Not yet implemented
    Ok(())
}

/// Errors that can occur during RPC handling.
#[derive(Debug)]
enum RpcError {
    /// I/O error during communication.
    Io(std::io::Error),
    /// Message exceeded maximum size.
    MessageTooLarge(usize),
    /// Failed to deserialize request.
    DeserializationError(String),
    /// Failed to serialize response.
    SerializationError(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Io(e) => write!(f, "I/O error: {}", e),
            RpcError::MessageTooLarge(size) => {
                write!(f, "Message too large: {} bytes (max {})", size, MAX_MESSAGE_SIZE)
            }
            RpcError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            RpcError::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl From<std::io::Error> for RpcError {
    fn from(e: std::io::Error) -> Self {
        RpcError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_error_display() {
        let err = RpcError::MessageTooLarge(100000);
        assert!(err.to_string().contains("100000"));
    }
}
