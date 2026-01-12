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
//! Response format (msgpack):
//! ```text
//! [interface_stats: array, link_count: u64 (if include_link_stats)]
//! ```

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::destination::link::{LinkEvent, LinkEventData, LinkId};
use crate::destination::request::{
    AllowPolicy, RequestHandler, RequestRouter, compute_request_id, pack_response, parse_request,
};
use crate::destination::{DestinationName, SingleInputDestination};
use crate::identity::PrivateIdentity;

/// The aspect name for the remote management destination.
/// This matches Python's `RNS.Transport.APP_NAME + ".remote.management"`.
pub const REMOTE_MANAGEMENT_ASPECT: &str = "rnstransport.remote.management";

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
            DestinationName::new("rnstransport", "remote.management"),
        );

        let mut router = RequestRouter::new();

        // Register the /status handler
        let status_handler = RequestHandler::new(
            "/status",
            handle_status_request,
            config.allow_policy.clone(),
        );
        router.register(status_handler);

        // Register the /path handler (for path table queries)
        let path_handler = RequestHandler::new(
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
    ///
    /// # Returns
    /// The response data to send back, or None if no response.
    pub fn process_request(
        &self,
        request_data: &[u8],
        link_id: &[u8],
        remote_identity: Option<&[u8; 16]>,
    ) -> Option<Vec<u8>> {
        // Parse the request to get timestamp, path_hash, and data
        let (requested_at, path_hash, data) = match parse_request(request_data) {
            Ok(parsed) => parsed,
            Err(e) => {
                log::warn!("remote_management: failed to parse request: {}", e);
                return None;
            }
        };

        // Compute request ID from the packed request
        let request_id = compute_request_id(request_data);

        // Route to the appropriate handler
        match self.router.handle_request(
            &path_hash,
            &data,
            &request_id,
            link_id,
            remote_identity,
            requested_at,
        ) {
            Ok(Some(response_data)) => {
                // Pack the response with the request_id
                match pack_response(&request_id, &response_data) {
                    Ok(packed) => Some(packed),
                    Err(e) => {
                        log::warn!("remote_management: failed to pack response: {}", e);
                        None
                    }
                }
            }
            Ok(None) => {
                log::trace!("remote_management: handler returned no response");
                None
            }
            Err(e) => {
                log::warn!("remote_management: request error: {}", e);
                None
            }
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

/// Handle a /status request.
///
/// This gathers interface statistics and returns them to the caller.
fn handle_status_request(
    _path: &str,
    data: &[u8],
    _request_id: &[u8; 16],
    _link_id: &[u8],
    _remote_identity: Option<&[u8; 16]>,
    _requested_at: f64,
) -> Option<Vec<u8>> {
    // Parse request data: [include_link_stats: bool]
    let include_link_stats = parse_status_request_data(data);

    // Gather interface statistics
    // For now, return a placeholder response since we don't have direct access
    // to the transport's interface manager from this context.
    // In practice, this would be populated by the transport when it handles the request.
    let interface_stats = gather_interface_stats();
    let link_count = if include_link_stats { Some(0u64) } else { None };

    // Pack response as msgpack
    let response = pack_status_response(&interface_stats, link_count);

    Some(response)
}

/// Handle a /path request.
///
/// This queries the path table for a specific destination.
fn handle_path_request(
    _path: &str,
    _data: &[u8],
    _request_id: &[u8; 16],
    _link_id: &[u8],
    _remote_identity: Option<&[u8; 16]>,
    _requested_at: f64,
) -> Option<Vec<u8>> {
    // Placeholder for path request handling
    // This would look up path information for a specific destination
    log::debug!("remote_management: /path request (not yet implemented)");

    // Return empty response for now
    let mut response = Vec::new();
    rmpv::encode::write_value(&mut response, &rmpv::Value::Nil).ok()?;
    Some(response)
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

/// Gather interface statistics (placeholder).
fn gather_interface_stats() -> Vec<RemoteInterfaceStats> {
    // This is a placeholder. In practice, the Transport would inject
    // actual interface statistics when processing the request.
    vec![]
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
        LinkEvent::Request(payload) => {
            // Process the request
            // Note: We need the remote identity from the link, which would
            // need to be passed through the event or looked up.
            if let Some(response) = service.process_request(
                payload.as_slice(),
                event.id.as_slice(),
                None, // Would need to get this from the link
            ) {
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
