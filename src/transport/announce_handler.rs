//! Announce handler registration for the transport layer.
//!
//! This module provides the types and APIs for registering announce handlers,
//! which are callbacks that receive announce notifications. This mirrors Python's
//! `Transport.register_announce_handler()` API.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::destination::DestinationName;
use crate::hash::{AddressHash, Hash};
use crate::identity::Identity;
use crate::packet::PacketDataBuffer;

/// Counter for generating unique handler IDs.
static HANDLER_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Unique handle for an announce handler registration.
///
/// Used to deregister the handler later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnnounceHandlerHandle(u64);

impl AnnounceHandlerHandle {
    /// Create a new unique handler handle.
    fn new() -> Self {
        Self(HANDLER_ID_COUNTER.fetch_add(1, Ordering::SeqCst))
    }
}

/// Data passed to announce callbacks.
///
/// Contains all information about a received announce.
#[derive(Clone)]
pub struct AnnounceData {
    /// Destination hash from the announce
    pub destination_hash: AddressHash,
    /// Identity of the announcer
    pub announced_identity: Identity,
    /// Application-specific data from the announce (may be empty)
    pub app_data: Option<PacketDataBuffer>,
    /// Hash of the announce packet
    pub announce_packet_hash: Hash,
    /// Whether this is a path response (not a live announce)
    pub is_path_response: bool,
}

impl std::fmt::Debug for AnnounceData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnnounceData")
            .field("destination_hash", &self.destination_hash)
            .field("announced_identity", &"<Identity>")
            .field("app_data", &self.app_data.as_ref().map(|d| d.len()))
            .field("announce_packet_hash", &self.announce_packet_hash)
            .field("is_path_response", &self.is_path_response)
            .finish()
    }
}

/// Configuration for an announce handler.
#[derive(Clone)]
pub struct AnnounceHandlerConfig {
    /// Optional aspect filter - only receive announces matching this aspect
    ///
    /// If None, receives all announces.
    /// If Some, only receives announces where the destination name starts with
    /// this aspect (e.g., "nomadnetwork" matches "nomadnetwork.node").
    pub aspect_filter: Option<DestinationName>,
    /// Whether to also receive path responses in addition to live announces
    pub receive_path_responses: bool,
}

impl std::fmt::Debug for AnnounceHandlerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnnounceHandlerConfig")
            .field("aspect_filter", &self.aspect_filter.is_some())
            .field("receive_path_responses", &self.receive_path_responses)
            .finish()
    }
}

impl Default for AnnounceHandlerConfig {
    fn default() -> Self {
        Self {
            aspect_filter: None,
            receive_path_responses: false,
        }
    }
}

impl AnnounceHandlerConfig {
    /// Create a new config with the specified aspect filter.
    pub fn with_aspect_filter(aspect_filter: DestinationName) -> Self {
        Self {
            aspect_filter: Some(aspect_filter),
            receive_path_responses: false,
        }
    }

    /// Enable receiving path responses in addition to live announces.
    pub fn receive_path_responses(mut self) -> Self {
        self.receive_path_responses = true;
        self
    }
}

/// Trait for announce callbacks.
///
/// Implement this trait to receive announce notifications.
pub trait AnnounceCallback: Send + Sync + 'static {
    /// Called when an announce is received that matches the handler's filter.
    ///
    /// # Arguments
    ///
    /// * `data` - The announce data containing all relevant information
    fn received_announce(&self, data: AnnounceData);
}

/// Function-based implementation of AnnounceCallback.
impl<F> AnnounceCallback for F
where
    F: Fn(AnnounceData) + Send + Sync + 'static,
{
    fn received_announce(&self, data: AnnounceData) {
        self(data)
    }
}

/// A registered announce handler.
pub(crate) struct RegisteredHandler {
    /// Unique handle for this registration
    pub handle: AnnounceHandlerHandle,
    /// Configuration for this handler
    pub config: AnnounceHandlerConfig,
    /// The callback to invoke
    pub callback: Arc<dyn AnnounceCallback>,
}

impl std::fmt::Debug for RegisteredHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredHandler")
            .field("handle", &self.handle)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Registry of announce handlers.
///
/// Thread-safe container for registered announce handlers.
#[derive(Debug, Default)]
pub struct AnnounceHandlerRegistry {
    handlers: Vec<RegisteredHandler>,
}

impl AnnounceHandlerRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an announce handler.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the handler (aspect filter, etc.)
    /// * `callback` - The callback to invoke when matching announces are received
    ///
    /// # Returns
    ///
    /// A handle that can be used to deregister the handler later.
    pub fn register(
        &mut self,
        config: AnnounceHandlerConfig,
        callback: Arc<dyn AnnounceCallback>,
    ) -> AnnounceHandlerHandle {
        let handle = AnnounceHandlerHandle::new();
        self.handlers.push(RegisteredHandler {
            handle,
            config,
            callback,
        });
        handle
    }

    /// Deregister an announce handler.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle returned from `register()`
    pub fn deregister(&mut self, handle: AnnounceHandlerHandle) {
        self.handlers.retain(|h| h.handle != handle);
    }

    /// Notify all matching handlers of an announce.
    ///
    /// # Arguments
    ///
    /// * `data` - The announce data to distribute
    /// * `name_hash` - The name hash from the announce (for aspect filtering)
    pub fn notify(&self, data: AnnounceData, name_hash: Option<&Hash>) {
        for handler in &self.handlers {
            // Skip path responses unless handler is configured to receive them
            if data.is_path_response && !handler.config.receive_path_responses {
                continue;
            }

            // Check aspect filter
            if let Some(ref filter) = handler.config.aspect_filter {
                if let Some(nh) = name_hash {
                    // Compare name hashes
                    // Note: This is a simplified check - full implementation would
                    // need to match the aspect hierarchy
                    if filter.as_name_hash_slice() != nh.as_slice() {
                        continue;
                    }
                } else {
                    // No name hash available, skip filtered handlers
                    continue;
                }
            }

            // Invoke the callback
            handler.callback.received_announce(data.clone());
        }
    }

    /// Notify all matching handlers of an announce, spawning each callback
    /// in a separate tokio task to prevent slow handlers from blocking packet processing.
    pub fn notify_spawned(&self, data: AnnounceData, name_hash: Option<&Hash>) {
        for handler in &self.handlers {
            // Skip path responses unless handler is configured to receive them
            if data.is_path_response && !handler.config.receive_path_responses {
                continue;
            }

            // Check aspect filter
            if let Some(ref filter) = handler.config.aspect_filter {
                if let Some(nh) = name_hash {
                    if filter.as_name_hash_slice() != nh.as_slice() {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            // Clone the data and callback for the spawned task
            let data = data.clone();
            let callback = handler.callback.clone();
            tokio::spawn(async move {
                callback.received_announce(data);
            });
        }
    }

    /// Get the number of registered handlers.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Check if there are no registered handlers.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn test_handler_registration() {
        let mut registry = AnnounceHandlerRegistry::new();
        assert!(registry.is_empty());

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let handle = registry.register(
            AnnounceHandlerConfig::default(),
            Arc::new(move |_: AnnounceData| {
                call_count_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        assert_eq!(registry.len(), 1);

        // Create test announce data
        let data = AnnounceData {
            destination_hash: AddressHash::new_empty(),
            announced_identity: Identity::default(),
            app_data: None,
            announce_packet_hash: Hash::new_empty(),
            is_path_response: false,
        };

        registry.notify(data.clone(), None);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        registry.deregister(handle);
        assert!(registry.is_empty());

        registry.notify(data, None);
        assert_eq!(call_count.load(Ordering::SeqCst), 1); // No change
    }

    #[test]
    fn test_path_response_filtering() {
        let mut registry = AnnounceHandlerRegistry::new();

        let live_count = Arc::new(AtomicUsize::new(0));
        let live_count_clone = live_count.clone();

        let all_count = Arc::new(AtomicUsize::new(0));
        let all_count_clone = all_count.clone();

        // Handler that only receives live announces
        registry.register(
            AnnounceHandlerConfig::default(),
            Arc::new(move |_: AnnounceData| {
                live_count_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        // Handler that receives path responses too
        registry.register(
            AnnounceHandlerConfig::default().receive_path_responses(),
            Arc::new(move |_: AnnounceData| {
                all_count_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        // Send live announce
        let live_data = AnnounceData {
            destination_hash: AddressHash::new_empty(),
            announced_identity: Identity::default(),
            app_data: None,
            announce_packet_hash: Hash::new_empty(),
            is_path_response: false,
        };
        registry.notify(live_data, None);

        assert_eq!(live_count.load(Ordering::SeqCst), 1);
        assert_eq!(all_count.load(Ordering::SeqCst), 1);

        // Send path response
        let path_data = AnnounceData {
            destination_hash: AddressHash::new_empty(),
            announced_identity: Identity::default(),
            app_data: None,
            announce_packet_hash: Hash::new_empty(),
            is_path_response: true,
        };
        registry.notify(path_data, None);

        assert_eq!(live_count.load(Ordering::SeqCst), 1); // No change
        assert_eq!(all_count.load(Ordering::SeqCst), 2);
    }
}
