//! Proof strategies and request handling for destinations
//!
//! This module implements proof strategies that determine how destinations
//! respond to incoming packets, and provides request handler registration.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::RnsError;
use crate::hash::AddressHash;
use crate::packet::Packet;

/// Proof strategy for a destination
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum ProofStrategy {
    /// Never generate proofs automatically
    #[default]
    None = 0x00,
    /// Let the application decide whether to prove
    App = 0x01,
    /// Always generate proofs for all packets
    All = 0x02,
}


impl From<u8> for ProofStrategy {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ProofStrategy::None,
            0x01 => ProofStrategy::App,
            0x02 => ProofStrategy::All,
            _ => ProofStrategy::None,
        }
    }
}

/// Request policy for determining which requests to allow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum RequestPolicy {
    /// Deny all requests
    #[default]
    AllowNone = 0x00,
    /// Allow all requests
    AllowAll = 0x01,
    /// Only allow requests from identities in the allow list
    AllowList = 0x02,
}


/// Response data from a request handler
#[derive(Debug, Clone)]
pub struct RequestResponse {
    /// Response data
    pub data: Vec<u8>,
    /// Whether to compress the response
    pub compress: bool,
}

impl RequestResponse {
    /// Create a new response with data
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            compress: false,
        }
    }

    /// Create a compressed response
    pub fn compressed(data: Vec<u8>) -> Self {
        Self {
            data,
            compress: true,
        }
    }
}

/// Type alias for request handler function
pub type RequestHandlerFn = Arc<dyn Fn(&str, &[u8], Option<&AddressHash>) -> Option<RequestResponse> + Send + Sync>;

/// A registered request handler
pub struct RequestHandler {
    /// The path this handler responds to
    pub path: String,
    /// The handler function
    pub handler: RequestHandlerFn,
    /// Request policy
    pub policy: RequestPolicy,
    /// List of allowed identity hashes (for AllowList policy)
    pub allowed_list: Vec<AddressHash>,
    /// Whether to auto-compress responses
    pub auto_compress: bool,
}

impl std::fmt::Debug for RequestHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestHandler")
            .field("path", &self.path)
            .field("policy", &self.policy)
            .field("allowed_list_count", &self.allowed_list.len())
            .field("auto_compress", &self.auto_compress)
            .finish()
    }
}

/// Manager for request handlers on a destination
#[derive(Debug, Default)]
pub struct RequestHandlerRegistry {
    /// Registered handlers by path
    handlers: RwLock<HashMap<String, RequestHandler>>,
}

impl RequestHandlerRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a request handler for a path
    pub fn register<F>(
        &self,
        path: &str,
        handler: F,
        policy: RequestPolicy,
        allowed_list: Vec<AddressHash>,
        auto_compress: bool,
    ) -> Result<(), RnsError>
    where
        F: Fn(&str, &[u8], Option<&AddressHash>) -> Option<RequestResponse> + Send + Sync + 'static,
    {
        let mut handlers = self.handlers.write().map_err(|_| RnsError::InvalidArgument)?;

        handlers.insert(
            path.to_string(),
            RequestHandler {
                path: path.to_string(),
                handler: Arc::new(handler),
                policy,
                allowed_list,
                auto_compress,
            },
        );

        Ok(())
    }

    /// Deregister a request handler
    pub fn deregister(&self, path: &str) -> Option<RequestHandler> {
        self.handlers.write().ok()?.remove(path)
    }

    /// Check if a handler exists for a path
    pub fn has_handler(&self, path: &str) -> bool {
        self.handlers.read().map(|h| h.contains_key(path)).unwrap_or(false)
    }

    /// Handle a request
    pub fn handle_request(
        &self,
        path: &str,
        data: &[u8],
        requester: Option<&AddressHash>,
    ) -> Option<RequestResponse> {
        let handlers = self.handlers.read().ok()?;
        let handler = handlers.get(path)?;

        // Check policy
        match handler.policy {
            RequestPolicy::AllowNone => return None,
            RequestPolicy::AllowList => {
                if let Some(requester_hash) = requester {
                    if !handler.allowed_list.iter().any(|h| h.as_slice() == requester_hash.as_slice()) {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            RequestPolicy::AllowAll => {}
        }

        // Call the handler
        let mut response = (handler.handler)(path, data, requester)?;

        // Apply auto-compression if enabled
        if handler.auto_compress {
            response.compress = true;
        }

        Some(response)
    }

    /// Get the number of registered handlers
    pub fn len(&self) -> usize {
        self.handlers.read().map(|h| h.len()).unwrap_or(0)
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// List all registered paths
    pub fn paths(&self) -> Vec<String> {
        self.handlers
            .read()
            .map(|h| h.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Proof request callback type
pub type ProofRequestCallback = Arc<dyn Fn(&Packet) -> bool + Send + Sync>;

/// Configuration for destination proof handling
#[derive(Default)]
pub struct ProofConfig {
    /// The proof strategy
    pub strategy: ProofStrategy,
    /// Optional callback for PROVE_APP strategy
    pub callback: Option<ProofRequestCallback>,
}

impl ProofConfig {
    /// Create a new proof config with a strategy
    pub fn new(strategy: ProofStrategy) -> Self {
        Self {
            strategy,
            callback: None,
        }
    }

    /// Set the proof callback for PROVE_APP strategy
    pub fn with_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&Packet) -> bool + Send + Sync + 'static,
    {
        self.callback = Some(Arc::new(callback));
        self
    }

    /// Determine if a proof should be sent for a packet
    pub fn should_prove(&self, packet: &Packet) -> bool {
        match self.strategy {
            ProofStrategy::None => false,
            ProofStrategy::All => true,
            ProofStrategy::App => {
                if let Some(ref callback) = self.callback {
                    callback(packet)
                } else {
                    false
                }
            }
        }
    }
}

impl std::fmt::Debug for ProofConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofConfig")
            .field("strategy", &self.strategy)
            .field("has_callback", &self.callback.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_strategy_default() {
        assert_eq!(ProofStrategy::default(), ProofStrategy::None);
    }

    #[test]
    fn test_proof_strategy_from_u8() {
        assert_eq!(ProofStrategy::from(0x00), ProofStrategy::None);
        assert_eq!(ProofStrategy::from(0x01), ProofStrategy::App);
        assert_eq!(ProofStrategy::from(0x02), ProofStrategy::All);
        assert_eq!(ProofStrategy::from(0xFF), ProofStrategy::None);
    }

    #[test]
    fn test_request_handler_registry() {
        let registry = RequestHandlerRegistry::new();

        registry
            .register(
                "/test",
                |_path, data, _requester| Some(RequestResponse::new(data.to_vec())),
                RequestPolicy::AllowAll,
                vec![],
                false,
            )
            .unwrap();

        assert!(registry.has_handler("/test"));
        assert!(!registry.has_handler("/unknown"));

        let response = registry.handle_request("/test", b"hello", None);
        assert!(response.is_some());
        assert_eq!(response.unwrap().data, b"hello");
    }

    #[test]
    fn test_request_handler_allow_list() {
        let registry = RequestHandlerRegistry::new();
        let allowed_hash = AddressHash::new_from_slice(&[1u8; 32]);

        registry
            .register(
                "/restricted",
                |_path, _data, _requester| Some(RequestResponse::new(b"secret".to_vec())),
                RequestPolicy::AllowList,
                vec![allowed_hash.clone()],
                false,
            )
            .unwrap();

        // Request without identity should fail
        assert!(registry.handle_request("/restricted", b"", None).is_none());

        // Request with wrong identity should fail
        let wrong_hash = AddressHash::new_from_slice(&[2u8; 32]);
        assert!(registry.handle_request("/restricted", b"", Some(&wrong_hash)).is_none());

        // Request with allowed identity should succeed
        assert!(registry.handle_request("/restricted", b"", Some(&allowed_hash)).is_some());
    }

    #[test]
    fn test_proof_config() {
        let config = ProofConfig::new(ProofStrategy::All);
        // Can't easily test should_prove without a real packet, but we can verify strategy
        assert_eq!(config.strategy, ProofStrategy::All);
    }

    #[test]
    fn test_request_response() {
        let response = RequestResponse::new(b"data".to_vec());
        assert!(!response.compress);

        let compressed = RequestResponse::compressed(b"data".to_vec());
        assert!(compressed.compress);
    }

    #[test]
    fn test_request_handler_allow_none() {
        let registry = RequestHandlerRegistry::new();

        registry
            .register(
                "/denied",
                |_path, _data, _requester| Some(RequestResponse::new(b"should not see".to_vec())),
                RequestPolicy::AllowNone,
                vec![],
                false,
            )
            .unwrap();

        // AllowNone policy should always deny
        assert!(registry.handle_request("/denied", b"", None).is_none());
        let any_hash = AddressHash::new_from_slice(&[1u8; 32]);
        assert!(registry.handle_request("/denied", b"", Some(&any_hash)).is_none());
    }

    #[test]
    fn test_request_handler_deregister() {
        let registry = RequestHandlerRegistry::new();

        registry
            .register(
                "/temp",
                |_path, _data, _requester| Some(RequestResponse::new(b"temp".to_vec())),
                RequestPolicy::AllowAll,
                vec![],
                false,
            )
            .unwrap();

        assert!(registry.has_handler("/temp"));
        assert_eq!(registry.len(), 1);

        // Deregister
        let removed = registry.deregister("/temp");
        assert!(removed.is_some());
        assert!(!registry.has_handler("/temp"));
        assert_eq!(registry.len(), 0);

        // Deregister again should return None
        assert!(registry.deregister("/temp").is_none());
    }

    #[test]
    fn test_request_handler_paths() {
        let registry = RequestHandlerRegistry::new();

        registry
            .register("/path1", |_, _, _| None, RequestPolicy::AllowAll, vec![], false)
            .unwrap();
        registry
            .register("/path2", |_, _, _| None, RequestPolicy::AllowAll, vec![], false)
            .unwrap();

        let paths = registry.paths();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"/path1".to_string()));
        assert!(paths.contains(&"/path2".to_string()));
    }

    #[test]
    fn test_request_handler_auto_compress() {
        let registry = RequestHandlerRegistry::new();

        registry
            .register(
                "/compress",
                |_path, _data, _requester| Some(RequestResponse::new(b"data".to_vec())),
                RequestPolicy::AllowAll,
                vec![],
                true, // auto_compress enabled
            )
            .unwrap();

        let response = registry.handle_request("/compress", b"", None);
        assert!(response.is_some());
        assert!(response.unwrap().compress);
    }

    #[test]
    fn test_request_handler_returns_none() {
        let registry = RequestHandlerRegistry::new();

        registry
            .register(
                "/nullable",
                |_path, _data, _requester| None, // Handler returns None
                RequestPolicy::AllowAll,
                vec![],
                false,
            )
            .unwrap();

        // Even though policy allows, handler returns None
        assert!(registry.handle_request("/nullable", b"", None).is_none());
    }
}
