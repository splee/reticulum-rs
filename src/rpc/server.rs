//! RPC server implementation for daemon mode.
//!
//! The RPC server listens for connections from CLI utilities and handles
//! queries about daemon state. The protocol is compatible with Python's
//! `multiprocessing.connection`:
//!
//! 1. Accept connection
//! 2. Perform mutual HMAC authentication
//! 3. Receive pickle-encoded request
//! 4. Process request and send pickle-encoded response
//! 5. Close connection

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::ipc::addr::{IpcListener, IpcStream, ListenerAddr};
use crate::transport::Transport;

use super::auth::{server_authenticate, AuthError};
use super::framing::{recv_bytes, send_bytes};
use super::pickle_protocol::{parse_request, serialize_response, PickleProtocolError};
use super::protocol::{
    DiscoveredInterfaceEntry, InterfaceStats, PathEntry, RpcRequest, RpcResponse, RpcResult,
};

use crate::config::ReticulumConfig;
use crate::discovery::InterfaceDiscoveryStorage;

/// Maximum size of an RPC message (1 MB should be plenty).
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// RPC server that handles management queries from CLI utilities.
///
/// The server listens on a Unix socket (or TCP on Windows) and processes
/// RPC requests from local clients like rnstatus, rnpath, etc.
///
/// ## Authentication
///
/// All connections must authenticate using HMAC challenge-response.
/// The authkey is typically derived from the transport identity's private key:
/// `authkey = full_hash(transport_identity.private_key())`
pub struct RpcServer {
    /// Address to listen on.
    addr: ListenerAddr,
    /// Reference to the transport for querying state.
    transport: Arc<Transport>,
    /// Cancellation token for shutdown.
    cancel: CancellationToken,
    /// Authentication key for HMAC challenge-response.
    authkey: Vec<u8>,
}

impl RpcServer {
    /// Create a new RPC server.
    ///
    /// # Arguments
    /// * `addr` - The address to listen on
    /// * `transport` - Reference to the daemon's transport
    /// * `cancel` - Cancellation token for graceful shutdown
    /// * `authkey` - HMAC authentication key
    pub fn new(
        addr: ListenerAddr,
        transport: Arc<Transport>,
        cancel: CancellationToken,
        authkey: Vec<u8>,
    ) -> Self {
        Self {
            addr,
            transport,
            cancel,
            authkey,
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
                                let authkey = self.authkey.clone();

                                // Handle each connection in a separate task
                                tokio::spawn(async move {
                                    if let Err(e) = handle_rpc_connection(stream, transport, &authkey).await {
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
/// Performs authentication, reads one request, processes it, sends the response, then closes.
async fn handle_rpc_connection(
    mut stream: IpcStream,
    transport: Arc<Transport>,
    authkey: &[u8],
) -> Result<(), RpcError> {
    // Step 1: Perform mutual HMAC authentication
    server_authenticate(&mut stream, authkey)
        .await
        .map_err(RpcError::Auth)?;

    log::debug!("rpc_server: client authenticated");

    // Step 2: Receive pickle-encoded request
    let request_bytes = recv_bytes(&mut stream, MAX_MESSAGE_SIZE).await?;

    // Step 3: Parse pickle request into RpcRequest
    let request = parse_request(&request_bytes).map_err(RpcError::Protocol)?;

    log::debug!("rpc_server: received request: {}", request.name());

    // Step 4: Process request
    let response = process_request(request, &transport).await;

    // Step 5: Serialize response to pickle format
    let response_bytes = serialize_response(&response).map_err(RpcError::Protocol)?;

    // Step 6: Send pickle-encoded response
    send_bytes(&mut stream, &response_bytes).await?;

    log::debug!("rpc_server: response sent");

    Ok(())
}

/// Process an RPC request and return the response.
async fn process_request(request: RpcRequest, transport: &Transport) -> RpcResponse {
    match request {
        RpcRequest::Ping => RpcResponse::success(RpcResult::Pong),

        RpcRequest::GetInterfaceStats => {
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

        RpcRequest::GetDiscoveredInterfaces => {
            let interfaces = get_discovered_interfaces().await;
            RpcResponse::success(RpcResult::DiscoveredInterfaces(interfaces))
        }
    }
}

/// Get interface statistics from the transport.
async fn get_interface_stats(transport: &Transport) -> Vec<InterfaceStats> {
    transport
        .get_interface_stats()
        .await
        .into_iter()
        .map(|s| InterfaceStats {
            name: s.name,
            interface_type: s.interface_type,
            online: s.online,
            rx_packets: 0, // TODO: Add packet counting if needed
            tx_packets: 0,
            rx_bytes: s.rx_bytes,
            tx_bytes: s.tx_bytes,
            bitrate: s.bitrate,
            address: s.endpoint_address,
        })
        .collect()
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

/// Get discovered interfaces from storage.
async fn get_discovered_interfaces() -> Vec<DiscoveredInterfaceEntry> {
    // Load configuration to get storage path
    let config = match ReticulumConfig::load(None) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Failed to load config for discovery: {}", e);
            return vec![];
        }
    };

    let storage = match InterfaceDiscoveryStorage::new(&config.paths.storage_path) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Failed to create discovery storage: {}", e);
            return vec![];
        }
    };

    // Load and convert all discovered interfaces (no source filtering)
    match storage.list_discovered(None) {
        Ok(interfaces) => interfaces
            .into_iter()
            .map(|info| {
                let status_str = info
                    .status
                    .map(|s| s.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                DiscoveredInterfaceEntry {
                    name: info.name,
                    interface_type: info.interface_type,
                    status: status_str,
                    transport: info.transport,
                    hops: info.hops,
                    discovered: info.discovered,
                    last_heard: info.last_heard,
                    value: info.value,
                    transport_id: if info.transport_id.is_empty() {
                        None
                    } else {
                        Some(info.transport_id)
                    },
                    network_id: if info.network_id.is_empty() {
                        None
                    } else {
                        Some(info.network_id)
                    },
                    latitude: info.latitude,
                    longitude: info.longitude,
                    height: info.height,
                    frequency: info.frequency,
                    bandwidth: info.bandwidth,
                    sf: info.sf,
                    cr: info.cr,
                    modulation: info.modulation,
                    reachable_on: info.reachable_on,
                    port: info.port,
                    ifac_netname: info.ifac_netname,
                    ifac_netkey: info.ifac_netkey,
                    config_entry: info.config_entry,
                }
            })
            .collect(),
        Err(e) => {
            log::warn!("Failed to load discovered interfaces: {}", e);
            vec![]
        }
    }
}

/// Errors that can occur during RPC handling.
#[derive(Debug)]
pub enum RpcError {
    /// I/O error during communication.
    Io(std::io::Error),
    /// Authentication error.
    Auth(AuthError),
    /// Protocol error (pickle parsing/serialization).
    Protocol(PickleProtocolError),
    /// Message exceeded maximum size.
    MessageTooLarge(usize),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Io(e) => write!(f, "I/O error: {}", e),
            RpcError::Auth(e) => write!(f, "Authentication error: {}", e),
            RpcError::Protocol(e) => write!(f, "Protocol error: {}", e),
            RpcError::MessageTooLarge(size) => {
                write!(
                    f,
                    "Message too large: {} bytes (max {})",
                    size, MAX_MESSAGE_SIZE
                )
            }
        }
    }
}

impl std::error::Error for RpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RpcError::Io(e) => Some(e),
            RpcError::Auth(e) => Some(e),
            RpcError::Protocol(e) => Some(e),
            _ => None,
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
