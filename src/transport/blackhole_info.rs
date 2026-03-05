//! Blackhole Info Service
//!
//! Public destination for querying blackholed identities.
//! Aspect: "rnstransport.info.blackhole"
//! Policy: ALLOW_ALL (no authentication required)
//!
//! # Wire Protocol
//!
//! The blackhole info destination uses the aspect `rnstransport.info.blackhole`.
//!
//! Request format (msgpack on "/list" path):
//! ```text
//! nil or empty array  -- request all blackholed identities
//! ```
//!
//! Response format (msgpack):
//! ```text
//! {
//!   identity_hash_bytes: {
//!     "source": source_identity_hash_bytes,
//!     "until": f64 or nil,
//!     "reason": string or nil
//!   },
//!   ...
//! }
//! ```

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::destination::request::{
    AllowPolicy, RequestHandler, RequestRouter, pack_response, parse_request,
};
use crate::destination::{DestinationName, SingleInputDestination};
use crate::hash::AddressHash;
use crate::identity::PrivateIdentity;

/// The aspect name for the blackhole info destination.
/// This matches Python's `RNS.Transport.APP_NAME + ".info.blackhole"`.
pub const BLACKHOLE_INFO_ASPECT: &str = "rnstransport.info.blackhole";

/// Entry in the blackhole list for serialization.
#[derive(Debug, Clone)]
pub struct BlackholeInfoEntry {
    /// Identity hash that is blackholed
    pub identity_hash: AddressHash,
    /// Source transport identity that applied this blackhole
    pub source: AddressHash,
    /// Unix timestamp when blackhole expires (None = permanent)
    pub until: Option<f64>,
    /// Reason for blackholing
    pub reason: Option<String>,
}

/// Context data for processing blackhole info requests.
#[derive(Default)]
pub struct BlackholeInfoContext {
    /// List of blackholed identities with their metadata
    pub entries: Vec<BlackholeInfoEntry>,
}

/// Blackhole info service.
///
/// Provides a public destination for querying blackholed identities.
pub struct BlackholeInfoService {
    /// The blackhole info destination
    pub destination: Arc<Mutex<SingleInputDestination>>,
    /// Request router for handling requests
    router: RequestRouter,
}

impl BlackholeInfoService {
    /// Create a new blackhole info service.
    ///
    /// # Arguments
    /// * `identity` - The transport's identity (used for the destination)
    pub fn new(identity: &PrivateIdentity) -> Self {
        let destination = SingleInputDestination::new(
            identity.clone(),
            DestinationName::new("rnstransport", "info.blackhole")
                .expect("valid destination name"),
        );

        let mut router = RequestRouter::new();

        // Register the /list handler with ALLOW_ALL policy (public)
        let list_handler = RequestHandler::new(
            "/list",
            handle_list_request,
            AllowPolicy::AllowAll,
        );
        router.register(list_handler);

        Self {
            destination: Arc::new(Mutex::new(destination)),
            router,
        }
    }

    /// Get the destination hash for this blackhole info service.
    pub async fn destination_hash(&self) -> crate::hash::AddressHash {
        self.destination.lock().await.desc.address_hash
    }

    /// Process an incoming request on a link.
    ///
    /// # Arguments
    /// * `request_data` - The raw request data (msgpack encoded)
    /// * `link_id` - The link the request came from
    /// * `remote_identity` - The remote peer's identity hash (if identified)
    /// * `context` - Context data with blackhole entries
    ///
    /// # Returns
    /// The response data to send back, or None if no response.
    pub fn process_request(
        &self,
        request_data: &[u8],
        link_id: &[u8],
        remote_identity: Option<&[u8; 16]>,
        context: &BlackholeInfoContext,
        request_id: &[u8; 16],
    ) -> Option<Vec<u8>> {
        // Parse the request to get timestamp, path_hash, and data
        let (requested_at, path_hash, data) = match parse_request(request_data) {
            Ok(parsed) => parsed,
            Err(e) => {
                log::warn!("blackhole_info: failed to parse request: {}", e);
                return None;
            }
        };

        // Check if this is a /list request
        let path_hash_for_list = RequestRouter::path_hash("/list");

        let response_data = if path_hash == path_hash_for_list {
            // Handle /list request with context data
            // Access control check (AllowAll always passes, but we do it for consistency)
            if let Some(handler) = self.router.get_by_path("/list") {
                if !handler.is_allowed(remote_identity) {
                    log::warn!("blackhole_info: /list request denied for {:?}", remote_identity);
                    return None;
                }
            }
            handle_list_request_with_context(&data, context)
        } else {
            // Route to the appropriate handler (for other paths, if any)
            match self.router.handle_request(
                &path_hash,
                &data,
                request_id,
                link_id,
                remote_identity,
                requested_at,
            ) {
                Ok(response) => response,
                Err(e) => {
                    log::warn!("blackhole_info: request error: {}", e);
                    return None;
                }
            }
        };

        // Pack the response with the request_id
        if let Some(response_data) = response_data {
            match pack_response(request_id, &response_data) {
                Ok(packed) => Some(packed),
                Err(e) => {
                    log::warn!("blackhole_info: failed to pack response: {}", e);
                    None
                }
            }
        } else {
            log::trace!("blackhole_info: handler returned no response");
            None
        }
    }
}

/// Handle a /list request (legacy handler for router registration).
fn handle_list_request(
    _path: &str,
    _data: &[u8],
    _request_id: &[u8; 16],
    _link_id: &[u8],
    _remote_identity: Option<&[u8; 16]>,
    _requested_at: f64,
) -> Option<Vec<u8>> {
    // This handler is only used for access control checks.
    // Actual processing is done in handle_list_request_with_context.
    None
}

/// Handle a /list request with context data.
///
/// Response format matches Python's Transport.blackholed_identities dict:
/// {
///   identity_hash_bytes: {
///     "source": source_hash_bytes,
///     "until": f64 or nil,
///     "reason": string or nil
///   },
///   ...
/// }
fn handle_list_request_with_context(
    _data: &[u8],
    context: &BlackholeInfoContext,
) -> Option<Vec<u8>> {
    log::debug!("blackhole_info: /list request, {} entries", context.entries.len());

    let response = pack_blackhole_list(&context.entries);
    Some(response)
}

/// Pack the blackhole list as msgpack.
///
/// Python format is a dict keyed by identity_hash bytes:
/// {
///   b'identity_hash': {"source": b'source_hash', "until": f64|None, "reason": str|None},
///   ...
/// }
fn pack_blackhole_list(entries: &[BlackholeInfoEntry]) -> Vec<u8> {
    let mut map_entries: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();

    for entry in entries {
        // Key is the identity hash as binary
        let key = rmpv::Value::Binary(entry.identity_hash.as_slice().to_vec());

        // Value is a map with source, until, reason
        let value = rmpv::Value::Map(vec![
            (
                rmpv::Value::String("source".into()),
                rmpv::Value::Binary(entry.source.as_slice().to_vec()),
            ),
            (
                rmpv::Value::String("until".into()),
                entry.until.map(rmpv::Value::F64).unwrap_or(rmpv::Value::Nil),
            ),
            (
                rmpv::Value::String("reason".into()),
                entry.reason.as_ref()
                    .map(|r| rmpv::Value::String(r.clone().into()))
                    .unwrap_or(rmpv::Value::Nil),
            ),
        ]);

        map_entries.push((key, value));
    }

    let response = rmpv::Value::Map(map_entries);

    let mut packed = Vec::new();
    if rmpv::encode::write_value(&mut packed, &response).is_err() {
        log::warn!("blackhole_info: failed to pack blackhole list response");
    }
    packed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_blackhole_list_empty() {
        let entries: Vec<BlackholeInfoEntry> = vec![];
        let packed = pack_blackhole_list(&entries);

        // Should decode as empty map
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&packed)).unwrap();
        assert!(value.is_map());
        assert_eq!(value.as_map().unwrap().len(), 0);
    }

    #[test]
    fn test_pack_blackhole_list_with_entries() {
        let entries = vec![
            BlackholeInfoEntry {
                identity_hash: AddressHash::new_from_slice(&[0x01u8; 32]),
                source: AddressHash::new_from_slice(&[0x02u8; 32]),
                until: Some(1700000000.0),
                reason: Some("Test reason".to_string()),
            },
            BlackholeInfoEntry {
                identity_hash: AddressHash::new_from_slice(&[0x03u8; 32]),
                source: AddressHash::new_from_slice(&[0x04u8; 32]),
                until: None,
                reason: None,
            },
        ];
        let packed = pack_blackhole_list(&entries);

        // Should decode as map with 2 entries
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&packed)).unwrap();
        assert!(value.is_map());
        assert_eq!(value.as_map().unwrap().len(), 2);
    }
}
