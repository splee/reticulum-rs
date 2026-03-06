//! Request/Response handler infrastructure for destinations.
//!
//! This module provides path-based request routing with ACL-based access control,
//! matching Python's `Destination.register_request_handler()` functionality.
//!
//! # Overview
//!
//! Request handlers are registered for specific paths (e.g., "/status", "/path").
//! When a request arrives over a Link, it's routed to the appropriate handler
//! based on the path hash. Access control policies determine who can invoke handlers.
//!
//! # Wire Protocol
//!
//! Request format (msgpack):
//! ```text
//! [timestamp: f64, path_hash: bytes[16], data: any]
//! ```
//!
//! Response format (msgpack):
//! ```text
//! [request_id: bytes[16], response_data: any]
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use sha2::{Sha256, Digest};

/// A shared, interior-mutable allow list that can be modified at runtime.
///
/// Callers hold a clone of this handle and can add/remove identity hashes
/// without re-registering the request handler. This mirrors Python's behavior
/// where `allowed_list` is a mutable list passed by reference.
pub type SharedAllowList = Arc<RwLock<Vec<[u8; 16]>>>;

/// Access control policy for request handlers.
#[derive(Debug, Clone)]
#[derive(Default)]
pub enum AllowPolicy {
    /// No requests allowed (handler disabled).
    #[default]
    AllowNone,
    /// All identified peers can make requests.
    AllowAll,
    /// Only peers in the allowed list can make requests.
    /// The list contains truncated identity hashes (16 bytes each).
    /// Uses `Arc<RwLock<...>>` so the list can be mutated at runtime
    /// by callers who hold a clone of the `SharedAllowList`.
    AllowList(SharedAllowList),
}

impl PartialEq for AllowPolicy {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (AllowPolicy::AllowNone, AllowPolicy::AllowNone) => true,
            (AllowPolicy::AllowAll, AllowPolicy::AllowAll) => true,
            (AllowPolicy::AllowList(a), AllowPolicy::AllowList(b)) => {
                let a = a.read().expect("AllowList lock poisoned");
                let b = b.read().expect("AllowList lock poisoned");
                *a == *b
            }
            _ => false,
        }
    }
}

impl Eq for AllowPolicy {}

impl AllowPolicy {
    /// Create a new AllowList policy, returning the policy and a shared handle
    /// that callers can use to mutate the list at runtime.
    pub fn new_allow_list(identities: Vec<[u8; 16]>) -> (Self, SharedAllowList) {
        let list = Arc::new(RwLock::new(identities));
        (AllowPolicy::AllowList(Arc::clone(&list)), list)
    }

    /// Check if a remote identity is allowed by this policy.
    ///
    /// # Arguments
    /// * `remote_identity_hash` - The truncated hash of the remote identity (16 bytes)
    ///
    /// # Returns
    /// `true` if the identity is allowed, `false` otherwise.
    pub fn is_allowed(&self, remote_identity_hash: Option<&[u8; 16]>) -> bool {
        match self {
            AllowPolicy::AllowNone => false,
            AllowPolicy::AllowAll => remote_identity_hash.is_some(),
            AllowPolicy::AllowList(allowed) => {
                if let Some(hash) = remote_identity_hash {
                    let list = allowed.read().expect("AllowList lock poisoned");
                    list.iter().any(|h| h == hash)
                } else {
                    false
                }
            }
        }
    }
}

/// Async handler function type for request processing.
///
/// Arguments (owned for async safety — the future must be `'static`):
/// - `path`: The request path string
/// - `data`: Request data (deserialized from msgpack)
/// - `request_id`: Unique identifier for this request
/// - `link_id`: Identifier of the link the request came from
/// - `remote_identity`: Hash of the remote identity (if identified)
/// - `requested_at`: Timestamp when the request was made
///
/// Returns: Optional response data to send back (None = no response)
pub type RequestHandlerFn = Arc<
    dyn Fn(
            String,                  // path
            Vec<u8>,                 // data
            [u8; 16],                // request_id
            Vec<u8>,                 // link_id
            Option<[u8; 16]>,        // remote_identity
            f64,                     // requested_at
        ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>
        + Send
        + Sync,
>;

/// Wrap a synchronous handler function as an async `RequestHandlerFn`.
///
/// This lets existing sync handlers work with the async handler infrastructure
/// without requiring the caller to deal with futures directly.
pub fn sync_handler<F>(f: F) -> RequestHandlerFn
where
    F: Fn(&str, &[u8], &[u8; 16], &[u8], Option<&[u8; 16]>, f64) -> Option<Vec<u8>>
        + Send
        + Sync
        + 'static,
{
    Arc::new(move |path, data, request_id, link_id, remote_identity, requested_at| {
        let result = f(
            &path,
            &data,
            &request_id,
            &link_id,
            remote_identity.as_ref(),
            requested_at,
        );
        Box::pin(async move { result })
    })
}

/// Configuration for a registered request handler.
#[derive(Clone)]
pub struct RequestHandler {
    /// The original path string.
    pub path: String,
    /// The handler function.
    pub handler: RequestHandlerFn,
    /// Access control policy.
    pub allow: AllowPolicy,
    /// Whether to auto-compress responses.
    pub auto_compress: bool,
}

impl RequestHandler {
    /// Create a new request handler with an async closure.
    ///
    /// The closure receives owned parameters and returns a boxed future.
    /// For sync handlers, use `new_sync()` instead.
    pub fn new<F, Fut>(path: impl Into<String>, handler: F, allow: AllowPolicy) -> Self
    where
        F: Fn(String, Vec<u8>, [u8; 16], Vec<u8>, Option<[u8; 16]>, f64) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: Future<Output = Option<Vec<u8>>> + Send + 'static,
    {
        Self {
            path: path.into(),
            handler: Arc::new(move |path, data, request_id, link_id, remote_identity, requested_at| {
                Box::pin(handler(path, data, request_id, link_id, remote_identity, requested_at))
            }),
            allow,
            auto_compress: true,
        }
    }

    /// Create a new request handler with a synchronous closure.
    ///
    /// Convenience wrapper that adapts a sync handler (with borrowed params)
    /// to the async `RequestHandlerFn` type.
    pub fn new_sync<F>(path: impl Into<String>, handler: F, allow: AllowPolicy) -> Self
    where
        F: Fn(&str, &[u8], &[u8; 16], &[u8], Option<&[u8; 16]>, f64) -> Option<Vec<u8>>
            + Send
            + Sync
            + 'static,
    {
        Self {
            path: path.into(),
            handler: sync_handler(handler),
            allow,
            auto_compress: true,
        }
    }

    /// Set auto-compression behavior.
    pub fn with_auto_compress(mut self, auto_compress: bool) -> Self {
        self.auto_compress = auto_compress;
        self
    }

    /// Check if a remote identity is allowed to use this handler.
    pub fn is_allowed(&self, remote_identity: Option<&[u8; 16]>) -> bool {
        self.allow.is_allowed(remote_identity)
    }

    /// Invoke the handler asynchronously.
    pub async fn invoke(
        &self,
        data: &[u8],
        request_id: &[u8; 16],
        link_id: &[u8],
        remote_identity: Option<&[u8; 16]>,
        requested_at: f64,
    ) -> Option<Vec<u8>> {
        (self.handler)(
            self.path.clone(),
            data.to_vec(),
            *request_id,
            link_id.to_vec(),
            remote_identity.copied(),
            requested_at,
        ).await
    }
}

/// Router for path-based request handlers.
///
/// Handlers are stored by their path hash (truncated SHA256 of the path string).
#[derive(Default)]
pub struct RequestRouter {
    /// Handlers indexed by path hash.
    handlers: HashMap<[u8; 16], RequestHandler>,
}

impl RequestRouter {
    /// Create a new empty router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute the path hash for a given path string.
    ///
    /// This matches Python's `RNS.Identity.truncated_hash(path.encode("utf-8"))`.
    pub fn path_hash(path: &str) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(path.as_bytes());
        let result = hasher.finalize();

        let mut hash = [0u8; 16];
        hash.copy_from_slice(&result[..16]);
        hash
    }

    /// Register a request handler for a path.
    ///
    /// # Arguments
    /// * `handler` - The handler configuration
    ///
    /// # Returns
    /// The previous handler for this path, if any.
    pub fn register(&mut self, handler: RequestHandler) -> Option<RequestHandler> {
        let path_hash = Self::path_hash(&handler.path);
        self.handlers.insert(path_hash, handler)
    }

    /// Deregister a request handler.
    ///
    /// # Arguments
    /// * `path` - The path to deregister
    ///
    /// # Returns
    /// The removed handler, if any.
    pub fn deregister(&mut self, path: &str) -> Option<RequestHandler> {
        let path_hash = Self::path_hash(path);
        self.handlers.remove(&path_hash)
    }

    /// Get a handler by path hash.
    pub fn get(&self, path_hash: &[u8; 16]) -> Option<&RequestHandler> {
        self.handlers.get(path_hash)
    }

    /// Get a handler by path string.
    pub fn get_by_path(&self, path: &str) -> Option<&RequestHandler> {
        let path_hash = Self::path_hash(path);
        self.handlers.get(&path_hash)
    }

    /// Check if a handler exists for a path.
    pub fn has_handler(&self, path: &str) -> bool {
        let path_hash = Self::path_hash(path);
        self.handlers.contains_key(&path_hash)
    }

    /// Get the number of registered handlers.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Check if the router has no handlers.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Handle an incoming request.
    ///
    /// # Arguments
    /// * `path_hash` - The path hash from the request
    /// * `data` - The request data
    /// * `request_id` - Unique request identifier
    /// * `link_id` - The link the request came from
    /// * `remote_identity` - The remote identity hash (if identified)
    /// * `requested_at` - Request timestamp
    ///
    /// # Returns
    /// - `Ok(Some(response))` - Handler was found and returned a response
    /// - `Ok(None)` - Handler was found but returned no response
    /// - `Err(RequestError)` - Handler not found or access denied
    pub async fn handle_request(
        &self,
        path_hash: &[u8; 16],
        data: &[u8],
        request_id: &[u8; 16],
        link_id: &[u8],
        remote_identity: Option<&[u8; 16]>,
        requested_at: f64,
    ) -> Result<Option<Vec<u8>>, RequestError> {
        let handler = self.handlers.get(path_hash).ok_or(RequestError::HandlerNotFound)?;

        if !handler.is_allowed(remote_identity) {
            return Err(RequestError::AccessDenied);
        }

        Ok(handler.invoke(data, request_id, link_id, remote_identity, requested_at).await)
    }
}

/// Errors that can occur during request handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// No handler registered for the path.
    HandlerNotFound,
    /// Remote identity not allowed to access this handler.
    AccessDenied,
    /// Request data is malformed.
    MalformedRequest,
    /// Response serialization failed.
    SerializationError,
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::HandlerNotFound => write!(f, "No handler found for path"),
            RequestError::AccessDenied => write!(f, "Access denied"),
            RequestError::MalformedRequest => write!(f, "Malformed request"),
            RequestError::SerializationError => write!(f, "Serialization error"),
        }
    }
}

impl std::error::Error for RequestError {}

/// Parse an incoming request packet.
///
/// Request format: `[timestamp: f64, path_hash: bytes[16], data: any]`
///
/// # Arguments
/// * `packed_request` - The msgpack-encoded request data
///
/// # Returns
/// Tuple of (requested_at, path_hash, request_data) or error
pub fn parse_request(packed_request: &[u8]) -> Result<(f64, [u8; 16], Vec<u8>), RequestError> {
    // Use rmpv's decoder since rmpv::Value doesn't implement serde::Deserialize
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(packed_request))
        .map_err(|_| RequestError::MalformedRequest)?;

    let unpacked = match value {
        rmpv::Value::Array(arr) => arr,
        _ => return Err(RequestError::MalformedRequest),
    };

    if unpacked.len() < 3 {
        return Err(RequestError::MalformedRequest);
    }

    let requested_at = unpacked[0]
        .as_f64()
        .ok_or(RequestError::MalformedRequest)?;

    let path_hash_bytes = unpacked[1]
        .as_slice()
        .ok_or(RequestError::MalformedRequest)?;

    if path_hash_bytes.len() != 16 {
        return Err(RequestError::MalformedRequest);
    }

    let mut path_hash = [0u8; 16];
    path_hash.copy_from_slice(path_hash_bytes);

    // Serialize the data field back to msgpack for the handler
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &unpacked[2])
        .map_err(|_| RequestError::MalformedRequest)?;

    Ok((requested_at, path_hash, data))
}

/// Create a response packet.
///
/// Response format: `[request_id: bytes[16], response_data: any]`
///
/// # Arguments
/// * `request_id` - The request ID to respond to
/// * `response_data` - The response data (already msgpack-encoded)
///
/// # Returns
/// The packed response or error
pub fn pack_response(request_id: &[u8; 16], response_data: &[u8]) -> Result<Vec<u8>, RequestError> {
    // Deserialize response_data to include it properly in the array
    let response_value = rmpv::decode::read_value(&mut std::io::Cursor::new(response_data))
        .map_err(|_| RequestError::SerializationError)?;

    let response = rmpv::Value::Array(vec![
        rmpv::Value::Binary(request_id.to_vec()),
        response_value,
    ]);

    let mut packed = Vec::new();
    rmpv::encode::write_value(&mut packed, &response)
        .map_err(|_| RequestError::SerializationError)?;

    Ok(packed)
}

/// Compute a request ID from the packed request data.
///
/// This matches Python's `RNS.Identity.truncated_hash(packed_request)`.
pub fn compute_request_id(packed_request: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(packed_request);
    let result = hasher.finalize();

    let mut id = [0u8; 16];
    id.copy_from_slice(&result[..16]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_hash() {
        let hash = RequestRouter::path_hash("/status");
        assert_eq!(hash.len(), 16);

        // Same path should give same hash
        let hash2 = RequestRouter::path_hash("/status");
        assert_eq!(hash, hash2);

        // Different path should give different hash
        let hash3 = RequestRouter::path_hash("/path");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_allow_policy() {
        let identity: [u8; 16] = [1u8; 16];
        let other_identity: [u8; 16] = [2u8; 16];

        // AllowNone denies everything
        let policy = AllowPolicy::AllowNone;
        assert!(!policy.is_allowed(Some(&identity)));
        assert!(!policy.is_allowed(None));

        // AllowAll allows any identified peer
        let policy = AllowPolicy::AllowAll;
        assert!(policy.is_allowed(Some(&identity)));
        assert!(!policy.is_allowed(None));

        // AllowList only allows listed identities
        let (policy, _handle) = AllowPolicy::new_allow_list(vec![identity]);
        assert!(policy.is_allowed(Some(&identity)));
        assert!(!policy.is_allowed(Some(&other_identity)));
        assert!(!policy.is_allowed(None));

        // AllowList can be mutated at runtime via the shared handle
        let (policy, handle) = AllowPolicy::new_allow_list(vec![identity]);
        assert!(!policy.is_allowed(Some(&other_identity)));
        handle.write().expect("lock").push(other_identity);
        assert!(policy.is_allowed(Some(&other_identity)));
        // Removing from the list is also reflected
        handle.write().expect("lock").retain(|h| *h != identity);
        assert!(!policy.is_allowed(Some(&identity)));
    }

    #[test]
    fn test_request_router() {
        let mut router = RequestRouter::new();

        // Register a handler
        let handler = RequestHandler::new_sync(
            "/status",
            |_path, _data, _req_id, _link_id, _identity, _time| Some(b"ok".to_vec()),
            AllowPolicy::AllowAll,
        );

        router.register(handler);

        assert!(router.has_handler("/status"));
        assert!(!router.has_handler("/unknown"));
        assert_eq!(router.len(), 1);
    }

    #[tokio::test]
    async fn test_request_handler_invocation() {
        let handler = RequestHandler::new_sync(
            "/echo",
            |_path, data, _req_id, _link_id, _identity, _time| Some(data.to_vec()),
            AllowPolicy::AllowAll,
        );

        let identity: [u8; 16] = [1u8; 16];
        let request_id: [u8; 16] = [2u8; 16];

        assert!(handler.is_allowed(Some(&identity)));

        let result = handler.invoke(b"hello", &request_id, b"link", Some(&identity), 0.0).await;
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn test_async_request_handler() {
        let handler = RequestHandler::new(
            "/async-echo",
            |_path, data, _req_id, _link_id, _identity, _time| async move {
                Some(data)
            },
            AllowPolicy::AllowAll,
        );

        let identity: [u8; 16] = [1u8; 16];
        let request_id: [u8; 16] = [2u8; 16];

        let result = handler.invoke(b"async hello", &request_id, b"link", Some(&identity), 0.0).await;
        assert_eq!(result, Some(b"async hello".to_vec()));
    }

    #[test]
    fn test_parse_request() {
        // Create a valid request: [timestamp, path_hash, data]
        let path_hash = RequestRouter::path_hash("/status");

        let request = rmpv::Value::Array(vec![
            rmpv::Value::F64(1234567890.0),
            rmpv::Value::Binary(path_hash.to_vec()),
            rmpv::Value::Boolean(true),
        ]);

        let mut packed = Vec::new();
        rmpv::encode::write_value(&mut packed, &request).unwrap();

        let (timestamp, parsed_hash, _data) = parse_request(&packed).unwrap();

        assert!((timestamp - 1234567890.0).abs() < 0.001);
        assert_eq!(parsed_hash, path_hash);
    }

    #[test]
    fn test_pack_response() {
        let request_id: [u8; 16] = [1u8; 16];

        // Encode response data as msgpack
        let mut response_data = Vec::new();
        rmpv::encode::write_value(&mut response_data, &rmpv::Value::String("hello".into())).unwrap();

        let packed = pack_response(&request_id, &response_data).unwrap();

        // Verify it can be unpacked
        let unpacked = rmpv::decode::read_value(&mut std::io::Cursor::new(&packed)).unwrap();
        let arr = unpacked.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_slice().unwrap(), &request_id);
    }

    #[test]
    fn test_compute_request_id() {
        let data = b"test request data";
        let id1 = compute_request_id(data);
        let id2 = compute_request_id(data);

        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16);

        // Different data should give different ID
        let id3 = compute_request_id(b"different data");
        assert_ne!(id1, id3);
    }
}
