//! Remote Management Client
//!
//! Provides a reusable client for connecting to remote Reticulum transport
//! instances and sending management requests. Used by rnstatus, rnpath, and
//! other CLI utilities that need remote management capabilities.
//!
//! # Protocol
//!
//! Remote management uses two destination types:
//! - `rnstransport.remote.management` - Authenticated management (ALLOW_LIST)
//! - `rnstransport.info.blackhole` - Public blackhole info (ALLOW_ALL)

use std::fs;
use std::io::Read as IoRead;
use std::path::PathBuf;
use std::time::Duration;

use rand_core::OsRng;
use sha2::{Sha256, Digest as Sha2Digest};

use crate::config::ReticulumConfig;
use crate::error::RnsError;
use crate::destination::{DestinationName, SingleOutputDestination};
use crate::destination::link::{LinkEvent, LinkStatus};
use crate::destination::request::RequestRouter;
use crate::hash::{AddressHash, Hash};
use crate::identity::PrivateIdentity;
use crate::iface::tcp_client::TcpClient;
use crate::ipc::addr::{IpcListener, ListenerAddr};
use crate::ipc::{LocalClientInterface, LocalServerInterface};
use crate::transport::{Transport, TransportConfig};

/// Aspect name for remote management destination (authenticated).
pub const REMOTE_MANAGEMENT_ASPECT: &str = "rnstransport.remote.management";

/// Aspect name for blackhole info destination (public).
pub const BLACKHOLE_INFO_ASPECT: &str = "rnstransport.info.blackhole";

/// Error type for remote client operations.
#[derive(Debug)]
pub enum RemoteError {
    /// Invalid transport hash format
    InvalidHash(String),
    /// Failed to load identity file
    IdentityError(String),
    /// Path to remote destination not found
    PathNotFound,
    /// Could not recall remote identity
    NoIdentity,
    /// Link establishment timed out
    LinkTimeout,
    /// Failed to create identify packet
    IdentifyError(String),
    /// Request timed out waiting for response
    ResponseTimeout,
    /// Failed to parse response
    ParseError(String),
    /// Generic error
    Other(String),
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteError::InvalidHash(e) => write!(f, "Invalid hash: {}", e),
            RemoteError::IdentityError(e) => write!(f, "Identity error: {}", e),
            RemoteError::PathNotFound => write!(f, "Path to remote destination not found"),
            RemoteError::NoIdentity => write!(f, "Could not recall remote identity"),
            RemoteError::LinkTimeout => write!(f, "Link establishment timed out"),
            RemoteError::IdentifyError(e) => write!(f, "Identify error: {}", e),
            RemoteError::ResponseTimeout => write!(f, "Response timed out"),
            RemoteError::ParseError(e) => write!(f, "Parse error: {}", e),
            RemoteError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for RemoteError {}

/// Configuration for remote client operations.
#[derive(Clone)]
pub struct RemoteClientConfig {
    /// Timeout for remote operations
    pub timeout: Duration,
    /// Optional identity for authenticated management
    pub identity: Option<PrivateIdentity>,
}

impl std::fmt::Debug for RemoteClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteClientConfig")
            .field("timeout", &self.timeout)
            .field("identity", &self.identity.as_ref().map(|_| "<identity>"))
            .finish()
    }
}

impl Default for RemoteClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            identity: None,
        }
    }
}

/// Parse a transport identity hash from hex string.
///
/// Accepts formats like:
/// - `abcdef0123456789abcdef0123456789` (32 hex chars)
/// - `<abcdef0123456789abcdef0123456789>` (with angle brackets)
/// - `/abcdef0123456789abcdef0123456789/` (with slashes)
pub fn parse_transport_hash(hash_str: &str) -> Result<[u8; 16], RemoteError> {
    let clean = hash_str
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim_start_matches('/')
        .trim_end_matches('/');

    if clean.len() != 32 {
        return Err(RemoteError::InvalidHash(format!(
            "Expected 32 hex characters, got {}",
            clean.len()
        )));
    }

    let bytes = hex::decode(clean)
        .map_err(|_| RemoteError::InvalidHash("Invalid hexadecimal string".to_string()))?;

    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Load a private identity from a file.
///
/// Uses binary format (64 bytes) which is compatible with Python.
pub fn load_identity(path: &PathBuf) -> Result<PrivateIdentity, RemoteError> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|mut f| f.read_to_end(&mut bytes))
        .map_err(|e| RemoteError::IdentityError(format!("Could not read identity file: {}", e)))?;

    // Binary format: 64 bytes (Python-compatible)
    if bytes.len() != 64 {
        return Err(RemoteError::IdentityError(format!(
            "Invalid identity file: expected 64 bytes, got {} bytes",
            bytes.len()
        )));
    }

    PrivateIdentity::new_from_bytes(&bytes)
        .map_err(|e| RemoteError::IdentityError(format!("Invalid identity format: {:?}", e)))
}

/// Compute a destination hash from an aspect name and transport identity hash.
///
/// The destination hash is computed as:
/// `truncated(sha256(name_hash || identity_hash))`
///
/// This matches Python's `Destination.hash_from_name_and_identity()`.
pub fn compute_destination_hash(aspect: &str, transport_identity_hash: &[u8; 16]) -> Result<AddressHash, RnsError> {
    // Parse aspect into app_name and aspects
    // e.g., "rnstransport.remote.management" -> ("rnstransport", "remote.management")
    let parts: Vec<&str> = aspect.splitn(2, '.').collect();
    let (app_name, aspects) = if parts.len() == 2 {
        (parts[0], parts[1])
    } else {
        (aspect, "")
    };

    let name = DestinationName::new(app_name, aspects)?;
    let name_hash = name.as_name_hash_slice();

    // Destination hash = truncated(sha256(name_hash || identity_hash))
    let mut hasher = Sha256::new();
    hasher.update(name_hash);
    hasher.update(transport_identity_hash);
    let result = hasher.finalize();

    Ok(AddressHash::new_from_hash(&Hash::new(result.into())))
}

/// Wait for a path to be established.
pub async fn wait_for_path(
    transport: &Transport,
    dest_hash: &AddressHash,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;

    while tokio::time::Instant::now() < deadline {
        if transport.has_path(dest_hash).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    false
}

/// Create a client transport suitable for remote management queries.
///
/// This transport:
/// 1. Tries to become the shared instance (start LocalServerInterface)
/// 2. If that fails (daemon already running), connects as client via LocalClientInterface
/// 3. Loads network interfaces from config for outbound connectivity
pub async fn create_client_transport(config: &ReticulumConfig, name: &str) -> Transport {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport_config = TransportConfig::new(name, &identity, false);
    let transport = Transport::new(transport_config);

    let socket_dir = config.paths.config_dir.join("sockets");
    if let Err(e) = std::fs::create_dir_all(&socket_dir) {
        log::warn!("Failed to create socket directory: {}", e);
    }

    let local_addr = ListenerAddr::default_transport(
        "default",
        &socket_dir,
        config.shared_instance_port,
    );

    // Try to become the shared instance (start LocalServerInterface)
    // This will fail if another daemon is already running on this socket
    let became_shared_instance = try_become_shared_instance(
        &transport,
        local_addr.clone(),
        config,
    ).await;

    if became_shared_instance {
        log::info!("Started as shared instance, serving other clients");
        return transport;
    }

    // Daemon exists, connect as client via LocalClientInterface
    log::info!("Connecting to existing daemon via LocalClientInterface");

    transport
        .iface_manager()
        .lock()
        .await
        .spawn(
            LocalClientInterface::new(local_addr.clone()),
            LocalClientInterface::spawn,
        );

    // Give LocalClientInterface time to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    transport
}

/// Try to start as a shared instance by binding LocalServerInterface.
/// Returns true if successful (we became the shared instance).
/// Returns false if binding fails (another daemon is running).
async fn try_become_shared_instance(
    transport: &Transport,
    local_addr: ListenerAddr,
    config: &ReticulumConfig,
) -> bool {
    // Try to bind to the socket - this will fail if daemon is already running
    match IpcListener::bind(&local_addr).await {
        Ok(_listener) => {
            // We successfully bound - we are the shared instance
            // Drop the listener so LocalServerInterface can bind it
            drop(_listener);

            // Start LocalServerInterface to serve other clients
            transport
                .iface_manager()
                .lock()
                .await
                .spawn(
                    LocalServerInterface::new(local_addr, transport.iface_manager()),
                    LocalServerInterface::spawn,
                );

            // Load network interfaces from config
            spawn_network_interfaces(transport, config).await;

            // Give interfaces time to connect
            tokio::time::sleep(Duration::from_millis(500)).await;

            true
        }
        Err(e) => {
            log::debug!("Could not bind LocalServerInterface: {} - daemon likely running", e);
            false
        }
    }
}

/// Spawn network interfaces from configuration.
async fn spawn_network_interfaces(transport: &Transport, config: &ReticulumConfig) {
    for iface_config in config.interface_configs() {
        if !iface_config.enabled {
            continue;
        }

        match iface_config.interface_type.as_str() {
            "TCPClientInterface" | "tcp_client" => {
                if let Some(ref target) = iface_config.target_host {
                    let port = iface_config.target_port.unwrap_or(4242);
                    let addr = format!("{}:{}", target, port);
                    log::info!("Starting TCPClientInterface: {}", addr);
                    transport
                        .iface_manager()
                        .lock()
                        .await
                        .spawn(TcpClient::new(&addr), TcpClient::spawn);
                }
            }
            "TCPServerInterface" | "tcp_server" => {
                // Skip server interfaces for client utilities
                log::debug!("Skipping TCPServerInterface for client transport");
            }
            _ => {
                log::debug!("Skipping unsupported interface type: {}", iface_config.interface_type);
            }
        }
    }
}

/// Remote management client for connecting to transport instances.
pub struct RemoteClient {
    transport: Transport,
    config: RemoteClientConfig,
}

impl RemoteClient {
    /// Create a new remote client.
    pub fn new(transport: Transport, config: RemoteClientConfig) -> Self {
        Self { transport, config }
    }

    /// Get a reference to the underlying transport.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Connect to a remote management destination and establish a link.
    ///
    /// Returns the established link on success.
    pub async fn connect(
        &self,
        aspect: &str,
        transport_identity_hash: &[u8; 16],
    ) -> Result<crate::transport::Link, RemoteError> {
        let dest_hash = compute_destination_hash(aspect, transport_identity_hash)
            .map_err(|e| RemoteError::Other(e.to_string()))?;

        // Request path to the management destination
        self.transport.request_path(&dest_hash, None).await;

        let path_found = wait_for_path(&self.transport, &dest_hash, self.config.timeout).await;
        if !path_found {
            return Err(RemoteError::PathNotFound);
        }

        // Wait for announce to get identity
        tokio::time::sleep(Duration::from_millis(500)).await;

        let remote_identity = self.transport.recall_identity(&dest_hash).await
            .ok_or(RemoteError::NoIdentity)?;

        // Parse aspect into app_name and aspects for destination descriptor
        let parts: Vec<&str> = aspect.splitn(2, '.').collect();
        let (app_name, aspects) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            (aspect, "")
        };

        let dest_name = DestinationName::new(app_name, aspects)
            .map_err(|e| RemoteError::Other(e.to_string()))?;
        let dest_desc = SingleOutputDestination::new(remote_identity, dest_name);

        // Establish link
        let link = self.transport.link(dest_desc.desc).await;

        // Wait for link activation
        let mut out_link_events = self.transport.out_link_events();
        let deadline = tokio::time::Instant::now() + self.config.timeout;

        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(RemoteError::LinkTimeout);
            }

            let status = link.status().await;
            if status == LinkStatus::Active {
                break;
            }

            tokio::select! {
                Ok(_event) = out_link_events.recv() => {
                    // Link events are handled internally
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }

        // Identify with management identity if we have one
        if let Some(ref mgmt_id) = self.config.identity {
            link.identify(mgmt_id).await
                .map_err(|e| RemoteError::IdentifyError(format!("{:?}", e)))?;

            // Give server time to process identity
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        Ok(link)
    }

    /// Send a request on an established link and wait for response.
    pub async fn request(
        &self,
        link: &crate::transport::Link,
        path: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, RemoteError> {
        let request_data = build_request(path, data);

        link.send_request(&request_data).await
            .map_err(|e| RemoteError::Other(format!("Failed to send request packet: {:?}", e)))?;

        // Wait for response
        let mut out_link_events = self.transport.out_link_events();
        let deadline = tokio::time::Instant::now() + self.config.timeout;

        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(RemoteError::ResponseTimeout);
            }

            tokio::select! {
                Ok(event) = out_link_events.recv() => {
                    if let LinkEvent::Response(payload) = &event.event {
                        return Ok(payload.as_slice().to_vec());
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    }
}

/// Build a request packet data for a given path and payload.
///
/// Request format: [timestamp, path_hash, data]
///
/// `data` must be pre-serialized msgpack bytes. They are spliced directly
/// into the array so the receiver sees the native msgpack type (Array, Map,
/// Integer, etc.) rather than a Binary wrapper. This matches Python's
/// `umsgpack.packb([timestamp, path_hash, data])` behaviour.
pub fn build_request(path: &str, data: &[u8]) -> Vec<u8> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    let path_hash = RequestRouter::path_hash(path);

    // Pack manually so we can splice pre-serialized data bytes directly,
    // avoiding double-encoding them inside a Binary envelope.
    let mut packed = Vec::new();
    rmp::encode::write_array_len(&mut packed, 3).unwrap();
    rmp::encode::write_f64(&mut packed, timestamp).unwrap();
    rmp::encode::write_bin(&mut packed, &path_hash).unwrap();
    packed.extend_from_slice(data);
    packed
}

/// Parse a response packet to extract the response data.
///
/// Response format: [request_id, response_data]
pub fn parse_response(data: &[u8]) -> Result<Vec<u8>, RemoteError> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(data))
        .map_err(|e| RemoteError::ParseError(format!("Failed to decode response: {}", e)))?;

    let arr = value.as_array()
        .ok_or_else(|| RemoteError::ParseError("Response is not an array".to_string()))?;

    if arr.len() < 2 {
        return Err(RemoteError::ParseError("Response too short".to_string()));
    }

    // Second element is the actual response data
    let response_data = &arr[1];

    // Response data may be binary encoded or direct value
    if let Some(bytes) = response_data.as_slice() {
        Ok(bytes.to_vec())
    } else {
        // Re-encode as msgpack
        let mut packed = Vec::new();
        rmpv::encode::write_value(&mut packed, response_data)
            .map_err(|e| RemoteError::ParseError(format!("Failed to re-encode response: {}", e)))?;
        Ok(packed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_request_embeds_data_natively() {
        // Pre-serialize an Array value, simulating what callers pass as data.
        let inner = rmpv::Value::Array(vec![
            rmpv::Value::Integer(1.into()),
            rmpv::Value::String("test".into()),
        ]);
        let mut pre_serialized = Vec::new();
        rmpv::encode::write_value(&mut pre_serialized, &inner).unwrap();

        let packed = build_request("test.path", &pre_serialized);

        // Decode and verify the third element is a native Array, not Binary.
        let decoded = rmpv::decode::read_value(&mut &packed[..]).unwrap();
        let arr = decoded.as_array().expect("should be an array");
        assert_eq!(arr.len(), 3);
        assert!(arr[0].is_f64(), "element 0 should be timestamp");
        assert!(arr[1].is_bin(), "element 1 should be path_hash");
        assert!(
            arr[2].is_array(),
            "element 2 should be native Array, got: {:?}",
            arr[2]
        );
        let data_arr = arr[2].as_array().unwrap();
        assert_eq!(data_arr[0].as_i64(), Some(1));
        assert_eq!(data_arr[1].as_str(), Some("test"));
    }

    #[test]
    fn test_build_request_embeds_integer_natively() {
        let inner = rmpv::Value::Integer(42.into());
        let mut pre_serialized = Vec::new();
        rmpv::encode::write_value(&mut pre_serialized, &inner).unwrap();

        let packed = build_request("some.path", &pre_serialized);

        let decoded = rmpv::decode::read_value(&mut &packed[..]).unwrap();
        let arr = decoded.as_array().unwrap();
        assert!(
            arr[2].is_i64() || arr[2].is_u64(),
            "element 2 should be native Integer, got: {:?}",
            arr[2]
        );
        assert_eq!(arr[2].as_i64(), Some(42));
    }

    #[test]
    fn test_build_request_path_hash_is_16_bytes() {
        let inner = rmpv::Value::Nil;
        let mut pre_serialized = Vec::new();
        rmpv::encode::write_value(&mut pre_serialized, &inner).unwrap();

        let packed = build_request("test.path", &pre_serialized);

        let decoded = rmpv::decode::read_value(&mut &packed[..]).unwrap();
        let arr = decoded.as_array().unwrap();
        let path_hash = arr[1].as_slice().unwrap();
        assert_eq!(path_hash.len(), 16, "path_hash should be truncated to 16 bytes");
    }
}
