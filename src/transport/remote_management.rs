//! Remote Management Service for Transport
//!
//! This module implements the remote management destination that allows
//! authorized clients to query transport status over links. This provides
//! feature parity with Python's `RNS.Transport.remote_management`.
//!
//! # Usage
//!
//! The remote management service is started by calling `Transport::start_remote_management()`.
//! Clients can then establish a link to the management destination and send status requests.
//!
//! # Wire Protocol
//!
//! The management destination uses the aspect `rnstransport.remote.management`.
//!
//! Request format (msgpack on "/status" path):
//! ```text
//! [include_link_stats: bool]
//! ```
//!
//! Request format (msgpack on "/path" path):
//! ```text
//! ["table", destination_hash_or_nil, max_hops_or_nil]  -- for path table
//! ["rates"]  -- for rate table
//! ```
//!
//! Response format (msgpack):
//! ```text
//! [interface_stats: array, link_count: u64 (if include_link_stats)]
//! ```

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::transport::path_table::PathInfo;
use crate::transport::announce_limits::RateInfo;

use crate::destination::link::{LinkEvent, LinkEventData, LinkId};
use crate::destination::request::{
    AllowPolicy, RequestHandler, RequestRouter, pack_response, parse_request,
};
use crate::destination::{DestinationName, SingleInputDestination};
use crate::identity::PrivateIdentity;

/// The aspect name for the remote management destination.
/// This matches Python's `RNS.Transport.APP_NAME + ".remote.management"`.
pub const REMOTE_MANAGEMENT_ASPECT: &str = "rnstransport.remote.management";

/// Context data for processing remote management requests.
///
/// This provides access to transport data that handlers need.
#[derive(Default)]
pub struct RemoteManagementContext {
    /// Path table data (for /path requests with "table" command)
    pub path_table: Option<Vec<PathInfo>>,
    /// Rate table data (for /path requests with "rates" command)
    pub rate_table: Option<Vec<RateInfo>>,
    /// Interface stats (for /status requests)
    pub interface_stats: Vec<RemoteInterfaceStats>,
    /// Link count (for /status requests)
    pub link_count: Option<u64>,
}

/// Configuration for remote management service.
#[derive(Clone)]
pub struct RemoteManagementConfig {
    /// Whether remote management is enabled
    pub enabled: bool,
    /// Access control policy for management requests
    pub allow_policy: AllowPolicy,
}

impl Default for RemoteManagementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_policy: AllowPolicy::AllowNone,
        }
    }
}

impl RemoteManagementConfig {
    /// Create a new config that allows all identified peers.
    pub fn allow_all() -> Self {
        Self {
            enabled: true,
            allow_policy: AllowPolicy::AllowAll,
        }
    }

    /// Create a new config with a specific allow list.
    pub fn allow_list(identities: Vec<[u8; 16]>) -> Self {
        Self {
            enabled: true,
            allow_policy: AllowPolicy::AllowList(identities),
        }
    }
}

/// Remote management service context.
///
/// This holds the state needed to process management requests.
pub struct RemoteManagementService {
    /// The management destination
    pub destination: Arc<Mutex<SingleInputDestination>>,
    /// Request router for handling management requests
    router: RequestRouter,
}

impl RemoteManagementService {
    /// Create a new remote management service.
    ///
    /// # Arguments
    /// * `identity` - The transport's identity (used for the management destination)
    /// * `config` - Configuration for access control
    pub fn new(identity: &PrivateIdentity, config: RemoteManagementConfig) -> Self {
        let destination = SingleInputDestination::new(
            identity.clone(),
            DestinationName::new("rnstransport", "remote.management")
                .expect("valid destination name"),
        );

        let mut router = RequestRouter::new();

        // Register the /status handler
        let status_handler = RequestHandler::new_sync(
            "/status",
            handle_status_request,
            config.allow_policy.clone(),
        );
        router.register(status_handler);

        // Register the /path handler (for path table queries)
        let path_handler = RequestHandler::new_sync(
            "/path",
            handle_path_request,
            config.allow_policy,
        );
        router.register(path_handler);

        Self {
            destination: Arc::new(Mutex::new(destination)),
            router,
        }
    }

    /// Get the destination hash for this management service.
    pub async fn destination_hash(&self) -> crate::hash::AddressHash {
        self.destination.lock().await.desc.address_hash
    }

    /// Process an incoming request on a link.
    ///
    /// # Arguments
    /// * `request_data` - The raw request data (msgpack encoded)
    /// * `link_id` - The link the request came from
    /// * `remote_identity` - The remote peer's identity hash (if identified)
    /// * `context` - Context data from transport (path table, rate table, etc.)
    ///
    /// # Returns
    /// The response data to send back, or None if no response.
    pub async fn process_request(
        &self,
        request_data: &[u8],
        link_id: &[u8],
        remote_identity: Option<&[u8; 16]>,
        context: &RemoteManagementContext,
        request_id: &[u8; 16],
    ) -> Option<Vec<u8>> {
        // Parse the request to get timestamp, path_hash, and data
        let (requested_at, path_hash, data) = match parse_request(request_data) {
            Ok(parsed) => parsed,
            Err(e) => {
                log::warn!("remote_management: failed to parse request: {}", e);
                return None;
            }
        };

        // Check if this is a /path request - we handle it specially with context
        let path_hash_for_path = RequestRouter::path_hash("/path");
        let path_hash_for_status = RequestRouter::path_hash("/status");

        let response_data = if path_hash == path_hash_for_path {
            // Handle /path request with context data
            if let Some(handler) = self.router.get_by_path("/path") {
                if !handler.is_allowed(remote_identity) {
                    log::warn!("remote_management: /path request denied for {:?}", remote_identity);
                    return None;
                }
            }
            handle_path_request_with_context(&data, context)
        } else if path_hash == path_hash_for_status {
            // Handle /status request with context data
            if let Some(handler) = self.router.get_by_path("/status") {
                if !handler.is_allowed(remote_identity) {
                    log::warn!("remote_management: /status request denied for {:?}", remote_identity);
                    return None;
                }
            }
            handle_status_request_with_context(&data, context)
        } else {
            // Route to the appropriate handler (for other paths)
            match self.router.handle_request(
                &path_hash,
                &data,
                request_id,
                link_id,
                remote_identity,
                requested_at,
            ).await {
                Ok(response) => response,
                Err(e) => {
                    log::warn!("remote_management: request error: {}", e);
                    return None;
                }
            }
        };

        // Pack the response with the request_id
        if let Some(response_data) = response_data {
            match pack_response(request_id, &response_data) {
                Ok(packed) => Some(packed),
                Err(e) => {
                    log::warn!("remote_management: failed to pack response: {}", e);
                    None
                }
            }
        } else {
            log::trace!("remote_management: handler returned no response");
            None
        }
    }

    /// Check if a remote identity is allowed to access management.
    pub fn is_allowed(&self, remote_identity: Option<&[u8; 16]>) -> bool {
        // Check against the /status handler's policy
        if let Some(handler) = self.router.get_by_path("/status") {
            handler.is_allowed(remote_identity)
        } else {
            false
        }
    }
}

/// Handle a /status request (legacy handler, used by router for access control).
fn handle_status_request(
    _path: &str,
    _data: &[u8],
    _request_id: &[u8; 16],
    _link_id: &[u8],
    _remote_identity: Option<&[u8; 16]>,
    _requested_at: f64,
) -> Option<Vec<u8>> {
    // This handler is only used for access control checks.
    // Actual processing is done in handle_status_request_with_context.
    None
}

/// Handle a /path request (legacy handler, used by router for access control).
fn handle_path_request(
    _path: &str,
    _data: &[u8],
    _request_id: &[u8; 16],
    _link_id: &[u8],
    _remote_identity: Option<&[u8; 16]>,
    _requested_at: f64,
) -> Option<Vec<u8>> {
    // This handler is only used for access control checks.
    // Actual processing is done in handle_path_request_with_context.
    None
}

/// Handle a /status request with context data.
fn handle_status_request_with_context(
    data: &[u8],
    context: &RemoteManagementContext,
) -> Option<Vec<u8>> {
    // Parse request data: [include_link_stats: bool]
    let include_link_stats = parse_status_request_data(data);

    // Get link count if requested and available
    let link_count = if include_link_stats {
        context.link_count
    } else {
        None
    };

    // Pack response as msgpack
    let response = pack_status_response(&context.interface_stats, link_count);

    Some(response)
}

/// Handle a /path request with context data.
///
/// Request format: ["table"|"rates", destination_hash?, max_hops?]
fn handle_path_request_with_context(
    data: &[u8],
    context: &RemoteManagementContext,
) -> Option<Vec<u8>> {
    // Parse request data
    let (command, destination_hash, max_hops) = match parse_path_request_data(data) {
        Some(parsed) => parsed,
        None => {
            log::warn!("remote_management: failed to parse /path request data");
            return None;
        }
    };

    log::debug!(
        "remote_management: /path request command={}, dest_hash={:?}, max_hops={:?}",
        command, destination_hash.as_ref(), max_hops
    );

    match command.as_str() {
        "table" => {
            // Return path table, optionally filtered
            let table = context.path_table.as_ref().map(|t| {
                t.iter()
                    .filter(|entry| {
                        // Filter by destination hash if specified
                        if let Some(ref filter_hash) = destination_hash {
                            if entry.destination != *filter_hash {
                                return false;
                            }
                        }
                        // Filter by max hops if specified
                        if let Some(max) = max_hops {
                            if entry.hops > max {
                                return false;
                            }
                        }
                        true
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            }).unwrap_or_default();

            let response = pack_path_table_response(&table);
            Some(response)
        }
        "rates" => {
            // Return rate table, optionally filtered
            let table = context.rate_table.as_ref().map(|t| {
                t.iter()
                    .filter(|entry| {
                        // Filter by destination hash if specified
                        if let Some(ref filter_hash) = destination_hash {
                            if entry.destination != *filter_hash {
                                return false;
                            }
                        }
                        true
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            }).unwrap_or_default();

            let response = pack_rate_table_response(&table);
            Some(response)
        }
        _ => {
            log::warn!("remote_management: unknown /path command: {}", command);
            None
        }
    }
}

/// Parse /path request data.
///
/// Returns (command, destination_hash, max_hops) if successful.
fn parse_path_request_data(data: &[u8]) -> Option<(String, Option<String>, Option<u8>)> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(data)).ok()?;

    let arr = value.as_array()?;
    if arr.is_empty() {
        return None;
    }

    let command = arr[0].as_str()?.to_string();

    let destination_hash = if arr.len() > 1 {
        arr[1].as_str().map(|s| s.to_string())
            .or_else(|| arr[1].as_slice().map(hex::encode))
    } else {
        None
    };

    let max_hops = if arr.len() > 2 {
        arr[2].as_u64().map(|n| n as u8)
    } else {
        None
    };

    Some((command, destination_hash, max_hops))
}

/// Pack path table response as msgpack.
///
/// Response format: array of path entries, each entry is a map with:
/// - "hash": destination hash (hex string)
/// - "timestamp": float
/// - "via": next hop hash (hex string)
/// - "hops": u8
/// - "expires": float (or nil)
/// - "interface": interface hash (hex string)
fn pack_path_table_response(table: &[PathInfo]) -> Vec<u8> {
    let entries: Vec<rmpv::Value> = table
        .iter()
        .map(|entry| {
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::String("hash".into()),
                    rmpv::Value::String(entry.destination.clone().into()),
                ),
                (
                    rmpv::Value::String("timestamp".into()),
                    rmpv::Value::F64(entry.timestamp),
                ),
                (
                    rmpv::Value::String("via".into()),
                    rmpv::Value::String(entry.next_hop.clone().into()),
                ),
                (
                    rmpv::Value::String("hops".into()),
                    rmpv::Value::Integer(entry.hops.into()),
                ),
                (
                    rmpv::Value::String("expires".into()),
                    entry.expires.map(rmpv::Value::F64).unwrap_or(rmpv::Value::Nil),
                ),
                (
                    rmpv::Value::String("interface".into()),
                    rmpv::Value::String(entry.interface_hash.clone().into()),
                ),
            ])
        })
        .collect();

    let response = rmpv::Value::Array(entries);

    let mut packed = Vec::new();
    if rmpv::encode::write_value(&mut packed, &response).is_err() {
        log::warn!("remote_management: failed to pack path table response");
    }
    packed
}

/// Pack rate table response as msgpack.
fn pack_rate_table_response(table: &[RateInfo]) -> Vec<u8> {
    let entries: Vec<rmpv::Value> = table
        .iter()
        .map(|entry| {
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::String("hash".into()),
                    rmpv::Value::String(entry.destination.clone().into()),
                ),
                (
                    rmpv::Value::String("last".into()),
                    entry.last_announce.map(rmpv::Value::F64).unwrap_or(rmpv::Value::Nil),
                ),
                (
                    rmpv::Value::String("rate_violations".into()),
                    rmpv::Value::Integer(entry.violations.into()),
                ),
                (
                    rmpv::Value::String("blocked_until".into()),
                    entry.blocked_until.map(rmpv::Value::F64).unwrap_or(rmpv::Value::Nil),
                ),
                (
                    rmpv::Value::String("timestamps".into()),
                    rmpv::Value::Array(
                        entry.timestamps.iter().map(|t| rmpv::Value::F64(*t)).collect()
                    ),
                ),
            ])
        })
        .collect();

    let response = rmpv::Value::Array(entries);

    let mut packed = Vec::new();
    if rmpv::encode::write_value(&mut packed, &response).is_err() {
        log::warn!("remote_management: failed to pack rate table response");
    }
    packed
}

/// Parse the status request data.
fn parse_status_request_data(data: &[u8]) -> bool {
    // Expected format: [include_link_stats: bool]
    if let Ok(value) = rmpv::decode::read_value(&mut std::io::Cursor::new(data)) {
        if let rmpv::Value::Array(arr) = value {
            if !arr.is_empty() {
                return arr[0].as_bool().unwrap_or(false);
            }
        } else if let Some(b) = value.as_bool() {
            return b;
        }
    }
    false
}

/// Interface statistics for remote status response.
#[derive(Debug, Clone)]
pub struct RemoteInterfaceStats {
    pub name: String,
    pub interface_type: String,
    pub online: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub bitrate: Option<u64>,
}

/// Pack the status response as msgpack.
fn pack_status_response(
    interfaces: &[RemoteInterfaceStats],
    link_count: Option<u64>,
) -> Vec<u8> {
    // Build interface stats array
    let iface_stats: Vec<rmpv::Value> = interfaces
        .iter()
        .map(|iface| {
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::String("name".into()),
                    rmpv::Value::String(iface.name.clone().into()),
                ),
                (
                    rmpv::Value::String("type".into()),
                    rmpv::Value::String(iface.interface_type.clone().into()),
                ),
                (
                    rmpv::Value::String("online".into()),
                    rmpv::Value::Boolean(iface.online),
                ),
                (
                    rmpv::Value::String("rxb".into()),
                    rmpv::Value::Integer(iface.rx_bytes.into()),
                ),
                (
                    rmpv::Value::String("txb".into()),
                    rmpv::Value::Integer(iface.tx_bytes.into()),
                ),
            ])
        })
        .collect();

    // Build response array
    let mut response_arr = vec![rmpv::Value::Array(iface_stats)];

    if let Some(count) = link_count {
        response_arr.push(rmpv::Value::Integer(count.into()));
    }

    let response = rmpv::Value::Array(response_arr);

    let mut packed = Vec::new();
    if rmpv::encode::write_value(&mut packed, &response).is_err() {
        log::warn!("remote_management: failed to pack status response");
    }
    packed
}

/// Helper to process link events for the management service.
///
/// This handles the event loop for processing management requests on links.
pub async fn process_link_event(
    service: &RemoteManagementService,
    event: &LinkEventData,
    context: &RemoteManagementContext,
    send_response: impl FnOnce(LinkId, Vec<u8>) + Send,
) {
    match &event.event {
        LinkEvent::Identified(identity) => {
            let identity_hash = {
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&identity.address_hash.as_slice()[..16]);
                hash
            };

            if service.is_allowed(Some(&identity_hash)) {
                log::debug!(
                    "remote_management: identity {} allowed for management",
                    identity.address_hash
                );
            } else {
                log::warn!(
                    "remote_management: identity {} not allowed",
                    identity.address_hash
                );
            }
        }
        LinkEvent::Request(payload, request_id) => {
            // Process the request
            // Note: We need the remote identity from the link, which would
            // need to be passed through the event or looked up.
            if let Some(response) = service.process_request(
                payload.as_slice(),
                event.id.as_slice(),
                None, // Would need to get this from the link
                context,
                request_id,
            ).await {
                send_response(event.id, response);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_management_config_default() {
        let config = RemoteManagementConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.allow_policy, AllowPolicy::AllowNone);
    }

    #[test]
    fn test_remote_management_config_allow_all() {
        let config = RemoteManagementConfig::allow_all();
        assert!(config.enabled);
        assert_eq!(config.allow_policy, AllowPolicy::AllowAll);
    }

    #[test]
    fn test_parse_status_request_data() {
        // Test with array format
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &rmpv::Value::Array(vec![rmpv::Value::Boolean(true)])).unwrap();
        assert!(parse_status_request_data(&data));

        // Test with simple bool
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &rmpv::Value::Boolean(false)).unwrap();
        assert!(!parse_status_request_data(&data));

        // Test with empty
        assert!(!parse_status_request_data(&[]));
    }

    #[test]
    fn test_pack_status_response() {
        let interfaces = vec![RemoteInterfaceStats {
            name: "test".to_string(),
            interface_type: "TCPClient".to_string(),
            online: true,
            rx_bytes: 100,
            tx_bytes: 200,
            bitrate: None,
        }];

        let response = pack_status_response(&interfaces, Some(5));
        assert!(!response.is_empty());

        // Verify it can be unpacked
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&response)).unwrap();
        assert!(value.is_array());
    }
}
