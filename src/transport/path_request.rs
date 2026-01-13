//! Path request handling for discovering routes to destinations.
//!
//! This module implements the path request/response protocol for
//! discovering routes to destinations across the network.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_core::{CryptoRngCore, OsRng};

use crate::destination::plain::PlainDestination;
use crate::hash::{AddressHash, Hash};
use crate::error::RnsError;
use crate::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext,
    PacketDataBuffer, PacketType, PropagationType,
};

/// Default path request timeout
pub const PATH_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Default interval between path request retries
pub const PATH_REQUEST_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum path request retries
pub const PATH_REQUEST_MAX_RETRIES: u32 = 5;

/// Minimum grace time before allowing another path request
pub const PATH_REQUEST_GRACE: Duration = Duration::from_secs(2);

/// Maximum pending path requests
pub const MAX_PENDING_REQUESTS: usize = 1000;

/// Grace time before answering a path request (matches Python PATH_REQUEST_GRACE = 0.4s)
pub const PATH_REQUEST_RESPONSE_GRACE: Duration = Duration::from_millis(400);

/// Additional grace time for roaming-mode interfaces (matches Python PATH_REQUEST_RG = 1.5s)
pub const PATH_REQUEST_ROAMING_GRACE: Duration = Duration::from_millis(1500);

/// Maximum unique path request tags to remember for deduplication
pub const MAX_PR_TAGS: usize = 32000;

/// Length of request tag in bytes (truncated hash)
pub const REQUEST_TAG_LENGTH: usize = 16;

/// Cache for tracking unique path request tags to prevent duplicate processing.
///
/// Uses FIFO eviction when the cache exceeds MAX_PR_TAGS entries.
/// Each tag is a 32-byte value: destination_hash(16) + request_tag(16).
#[derive(Debug, Default)]
pub struct PathRequestTagCache {
    tags: VecDeque<[u8; 32]>,
}

impl PathRequestTagCache {
    /// Create a new empty tag cache
    pub fn new() -> Self {
        Self {
            tags: VecDeque::new(),
        }
    }

    /// Check if a unique tag exists in the cache
    pub fn contains(&self, unique_tag: &[u8; 32]) -> bool {
        self.tags.iter().any(|t| t == unique_tag)
    }

    /// Insert a unique tag into the cache.
    ///
    /// If the cache exceeds MAX_PR_TAGS, older entries are evicted (FIFO).
    pub fn insert(&mut self, unique_tag: [u8; 32]) {
        // Don't insert duplicates
        if self.contains(&unique_tag) {
            return;
        }

        self.tags.push_back(unique_tag);

        // Evict oldest entries if over capacity
        while self.tags.len() > MAX_PR_TAGS {
            self.tags.pop_front();
        }
    }

    /// Get the number of cached tags
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// Clear all cached tags
    pub fn clear(&mut self) {
        self.tags.clear();
    }
}

/// State of a path request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRequestState {
    /// Request has been sent, awaiting response
    Pending,
    /// Path has been found
    Found,
    /// Request timed out
    TimedOut,
    /// Request was cancelled
    Cancelled,
}

/// A pending path request
#[allow(clippy::type_complexity)]
pub struct PathRequest {
    /// Destination hash being requested
    pub destination: AddressHash,
    /// When the request was created
    pub created_at: Instant,
    /// When the request was last sent
    pub last_sent: Instant,
    /// Number of times the request has been sent
    pub retries: u32,
    /// Current state
    pub state: PathRequestState,
    /// Optional callback when path is found
    pub callback: Option<Arc<dyn Fn(&AddressHash, bool) + Send + Sync>>,
    /// Whether this is a local request (vs on behalf of another node)
    pub local: bool,
    /// Tag for identifying the request
    pub tag: Option<String>,
}

impl PathRequest {
    /// Create a new path request
    pub fn new(destination: AddressHash, local: bool) -> Self {
        let now = Instant::now();
        Self {
            destination,
            created_at: now,
            last_sent: now,
            retries: 0,
            state: PathRequestState::Pending,
            callback: None,
            local,
            tag: None,
        }
    }

    /// Create a new path request with callback
    pub fn with_callback<F>(destination: AddressHash, local: bool, callback: F) -> Self
    where
        F: Fn(&AddressHash, bool) + Send + Sync + 'static,
    {
        let mut req = Self::new(destination, local);
        req.callback = Some(Arc::new(callback));
        req
    }

    /// Check if request has timed out
    pub fn is_timed_out(&self) -> bool {
        self.created_at.elapsed() > PATH_REQUEST_TIMEOUT
    }

    /// Check if request should be retried
    pub fn should_retry(&self) -> bool {
        !self.is_timed_out()
            && self.retries < PATH_REQUEST_MAX_RETRIES
            && self.last_sent.elapsed() > PATH_REQUEST_RETRY_INTERVAL
            && self.state == PathRequestState::Pending
    }

    /// Mark as sent (retry)
    pub fn mark_sent(&mut self) {
        self.retries += 1;
        self.last_sent = Instant::now();
    }

    /// Mark as found
    pub fn mark_found(&mut self) {
        self.state = PathRequestState::Found;
        if let Some(ref callback) = self.callback {
            callback(&self.destination, true);
        }
    }

    /// Mark as timed out
    pub fn mark_timed_out(&mut self) {
        self.state = PathRequestState::TimedOut;
        if let Some(ref callback) = self.callback {
            callback(&self.destination, false);
        }
    }

    /// Mark as cancelled
    pub fn cancel(&mut self) {
        self.state = PathRequestState::Cancelled;
    }
}

/// Callback type for path request completion
pub type PathCallback = Arc<dyn Fn(&AddressHash, bool) + Send + Sync>;

/// Manager for path requests
#[derive(Default)]
pub struct PathRequestManager {
    /// Pending requests by destination hash
    requests: Mutex<HashMap<AddressHash, PathRequest>>,
    /// Discovery requests (on behalf of other nodes)
    discovery_requests: Mutex<HashMap<AddressHash, PathRequest>>,
    /// Rate limiting: last request time per destination
    last_request_time: Mutex<HashMap<AddressHash, Instant>>,
}

impl PathRequestManager {
    /// Create a new path request manager
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            discovery_requests: Mutex::new(HashMap::new()),
            last_request_time: Mutex::new(HashMap::new()),
        }
    }

    /// Generate a random request tag (16 bytes)
    pub fn generate_request_tag<R: CryptoRngCore>(rng: R) -> [u8; REQUEST_TAG_LENGTH] {
        let hash = Hash::new_from_rand(rng);
        let mut tag = [0u8; REQUEST_TAG_LENGTH];
        tag.copy_from_slice(&hash.as_bytes()[..REQUEST_TAG_LENGTH]);
        tag
    }

    /// Get the address hash for the path request control destination.
    ///
    /// This is the PLAIN destination "rnstransport.path.request" that all
    /// nodes listen on for incoming path requests.
    pub fn path_request_destination_hash() -> AddressHash {
        *PlainDestination::new("rnstransport", "path.request")
            .address_hash()
    }

    /// Build path request packet data.
    ///
    /// The packet format depends on whether transport is enabled:
    /// - With transport: destination_hash(16) + transport_id(16) + tag(16) = 48 bytes
    /// - Without transport: destination_hash(16) + tag(16) = 32 bytes
    ///
    /// Returns the packet data buffer and the generated request tag.
    pub fn build_request_data(
        destination: &AddressHash,
        transport_identity: Option<&AddressHash>,
    ) -> (PacketDataBuffer, [u8; REQUEST_TAG_LENGTH]) {
        let request_tag = Self::generate_request_tag(OsRng);

        let mut data = PacketDataBuffer::new();
        // Write destination hash (first 16 bytes of the 32-byte hash)
        data.chain_safe_write(&destination.as_slice()[..REQUEST_TAG_LENGTH]);

        // If transport enabled, include our transport identity hash
        if let Some(transport_id) = transport_identity {
            data.chain_safe_write(&transport_id.as_slice()[..REQUEST_TAG_LENGTH]);
        }

        // Write the request tag
        data.chain_safe_write(&request_tag);

        (data, request_tag)
    }

    /// Create a complete path request packet ready to send.
    ///
    /// The packet is a broadcast DATA packet to the PLAIN destination
    /// "rnstransport.path.request".
    ///
    /// Returns the packet and the generated request tag.
    pub fn create_request_packet(
        destination: &AddressHash,
        transport_identity: Option<&AddressHash>,
    ) -> (Packet, [u8; REQUEST_TAG_LENGTH]) {
        let path_request_dest = Self::path_request_destination_hash();
        let (data, tag) = Self::build_request_data(destination, transport_identity);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Plain,
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination: path_request_dest,
            transport: None,
            context: PacketContext::None,
            data,
        };

        (packet, tag)
    }

    /// Parse path request packet data.
    ///
    /// Returns (destination_hash, optional_transport_id, optional_tag_bytes).
    pub fn parse_request_data(
        data: &[u8],
    ) -> Option<(AddressHash, Option<AddressHash>, Option<[u8; REQUEST_TAG_LENGTH]>)> {
        // Minimum: destination hash (16 bytes)
        if data.len() < REQUEST_TAG_LENGTH {
            return None;
        }

        // Parse destination hash (raw 16 bytes, not hashed)
        let mut dest_bytes = [0u8; REQUEST_TAG_LENGTH];
        dest_bytes.copy_from_slice(&data[..REQUEST_TAG_LENGTH]);
        let destination_hash = AddressHash::new(dest_bytes);

        // Parse transport ID and tag based on length
        let (transport_id, tag_bytes) = if data.len() > REQUEST_TAG_LENGTH * 2 {
            // Has transport ID: dest(16) + transport(16) + tag(up to 16)
            let mut transport_bytes = [0u8; REQUEST_TAG_LENGTH];
            transport_bytes.copy_from_slice(&data[REQUEST_TAG_LENGTH..REQUEST_TAG_LENGTH * 2]);
            let transport_id = AddressHash::new(transport_bytes);

            let tag_start = REQUEST_TAG_LENGTH * 2;
            let tag_end = (tag_start + REQUEST_TAG_LENGTH).min(data.len());
            let mut tag = [0u8; REQUEST_TAG_LENGTH];
            let tag_len = tag_end - tag_start;
            tag[..tag_len].copy_from_slice(&data[tag_start..tag_end]);

            (Some(transport_id), Some(tag))
        } else if data.len() > REQUEST_TAG_LENGTH {
            // No transport ID: dest(16) + tag(remaining, up to 16)
            let tag_end = (REQUEST_TAG_LENGTH * 2).min(data.len());
            let mut tag = [0u8; REQUEST_TAG_LENGTH];
            let tag_len = tag_end - REQUEST_TAG_LENGTH;
            tag[..tag_len].copy_from_slice(&data[REQUEST_TAG_LENGTH..tag_end]);

            (None, Some(tag))
        } else {
            // Only destination hash, no tag
            (None, None)
        };

        Some((destination_hash, transport_id, tag_bytes))
    }

    /// Request a path to a destination
    pub fn request_path(
        &self,
        destination: AddressHash,
        callback: Option<PathCallback>,
    ) -> Result<bool, RnsError> {
        let mut requests = self.requests.lock().unwrap();

        // Check if already pending
        if requests.contains_key(&destination) {
            return Ok(false);
        }

        // Check rate limiting
        let mut last_times = self.last_request_time.lock().unwrap();
        if let Some(last_time) = last_times.get(&destination) {
            if last_time.elapsed() < PATH_REQUEST_GRACE {
                return Ok(false);
            }
        }

        // Check capacity
        if requests.len() >= MAX_PENDING_REQUESTS {
            // Clean up old requests first
            drop(requests);
            self.cleanup();
            requests = self.requests.lock().unwrap();

            if requests.len() >= MAX_PENDING_REQUESTS {
                return Err(RnsError::OutOfMemory);
            }
        }

        // Create request
        let mut request = PathRequest::new(destination, true);
        if let Some(cb) = callback {
            request.callback = Some(cb);
        }

        requests.insert(destination, request);
        last_times.insert(destination, Instant::now());

        Ok(true)
    }

    /// Request path on behalf of another node (discovery)
    pub fn request_discovery_path(&self, destination: AddressHash) -> Result<bool, RnsError> {
        let mut requests = self.discovery_requests.lock().unwrap();

        if requests.contains_key(&destination) {
            return Ok(false);
        }

        let request = PathRequest::new(destination, false);
        requests.insert(destination, request);

        Ok(true)
    }

    /// Cancel a pending path request
    pub fn cancel(&self, destination: &AddressHash) -> bool {
        let mut requests = self.requests.lock().unwrap();
        if let Some(request) = requests.get_mut(destination) {
            request.cancel();
            true
        } else {
            false
        }
    }

    /// Notify that a path was found
    pub fn path_found(&self, destination: &AddressHash) {
        let mut requests = self.requests.lock().unwrap();
        if let Some(request) = requests.get_mut(destination) {
            request.mark_found();
        }

        let mut discovery = self.discovery_requests.lock().unwrap();
        if let Some(request) = discovery.get_mut(destination) {
            request.mark_found();
        }
    }

    /// Check if a path request is pending
    pub fn is_pending(&self, destination: &AddressHash) -> bool {
        let requests = self.requests.lock().unwrap();
        requests
            .get(destination)
            .map(|r| r.state == PathRequestState::Pending)
            .unwrap_or(false)
    }

    /// Get requests that need to be retried
    pub fn get_retry_needed(&self) -> Vec<AddressHash> {
        let mut requests = self.requests.lock().unwrap();
        let mut to_retry = Vec::new();

        for (dest, request) in requests.iter_mut() {
            if request.should_retry() {
                request.mark_sent();
                to_retry.push(*dest);
            }
        }

        to_retry
    }

    /// Clean up completed and timed out requests
    pub fn cleanup(&self) {
        let mut requests = self.requests.lock().unwrap();

        // Mark timed out requests
        for request in requests.values_mut() {
            if request.is_timed_out() && request.state == PathRequestState::Pending {
                request.mark_timed_out();
            }
        }

        // Remove completed requests
        requests.retain(|_, r| r.state == PathRequestState::Pending);

        // Same for discovery requests
        let mut discovery = self.discovery_requests.lock().unwrap();
        for request in discovery.values_mut() {
            if request.is_timed_out() && request.state == PathRequestState::Pending {
                request.state = PathRequestState::TimedOut;
            }
        }
        discovery.retain(|_, r| r.state == PathRequestState::Pending);

        // Clean up rate limiting cache
        let mut last_times = self.last_request_time.lock().unwrap();
        let cutoff = Instant::now() - PATH_REQUEST_TIMEOUT;
        last_times.retain(|_, time| *time > cutoff);
    }

    /// Get number of pending local requests
    pub fn pending_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    /// Get number of pending discovery requests
    pub fn discovery_count(&self) -> usize {
        self.discovery_requests.lock().unwrap().len()
    }

    /// Await a path to a destination (blocking)
    pub fn await_path(&self, destination: AddressHash, timeout: Duration) -> bool {
        let start = Instant::now();

        // Create the request
        let _ = self.request_path(destination, None);

        // Poll until found or timeout
        while start.elapsed() < timeout {
            // Check if path was found
            {
                let requests = self.requests.lock().unwrap();
                if let Some(request) = requests.get(&destination) {
                    if request.state == PathRequestState::Found {
                        return true;
                    }
                    if request.state != PathRequestState::Pending {
                        return false;
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(50));
        }

        // Timed out
        let mut requests = self.requests.lock().unwrap();
        if let Some(request) = requests.get_mut(&destination) {
            request.mark_timed_out();
        }

        false
    }
}

impl std::fmt::Debug for PathRequestManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathRequestManager")
            .field("pending_count", &self.pending_count())
            .field("discovery_count", &self.discovery_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_request_creation() {
        let dest = AddressHash::new_from_slice(&[1u8; 32]);
        let request = PathRequest::new(dest.clone(), true);

        assert_eq!(request.state, PathRequestState::Pending);
        assert!(request.local);
        assert_eq!(request.retries, 0);
    }

    #[test]
    fn test_path_request_manager() {
        let manager = PathRequestManager::new();

        let dest = AddressHash::new_from_slice(&[1u8; 32]);
        assert!(manager.request_path(dest.clone(), None).unwrap());
        assert!(manager.is_pending(&dest));

        // Can't request again
        assert!(!manager.request_path(dest.clone(), None).unwrap());

        // Mark found
        manager.path_found(&dest);

        // Should be removed on cleanup
        manager.cleanup();
        assert!(!manager.is_pending(&dest));
    }

    #[test]
    fn test_path_request_timeout() {
        let dest = AddressHash::new_from_slice(&[1u8; 32]);
        let mut request = PathRequest::new(dest, true);

        assert!(!request.is_timed_out());

        // Note: We can't easily test actual timeout without waiting
        // but we can test the state transition
        request.mark_timed_out();
        assert_eq!(request.state, PathRequestState::TimedOut);
    }

    #[test]
    fn test_discovery_requests() {
        let manager = PathRequestManager::new();

        let dest = AddressHash::new_from_slice(&[1u8; 32]);
        assert!(manager.request_discovery_path(dest.clone()).unwrap());
        assert_eq!(manager.discovery_count(), 1);
    }

    #[test]
    fn test_path_request_tag_cache() {
        let mut cache = PathRequestTagCache::new();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        // Insert a tag
        let tag1 = [1u8; 32];
        cache.insert(tag1);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&tag1));

        // Insert same tag again - should not duplicate
        cache.insert(tag1);
        assert_eq!(cache.len(), 1);

        // Insert different tag
        let tag2 = [2u8; 32];
        cache.insert(tag2);
        assert_eq!(cache.len(), 2);
        assert!(cache.contains(&tag1));
        assert!(cache.contains(&tag2));

        // Non-existent tag
        let tag3 = [3u8; 32];
        assert!(!cache.contains(&tag3));

        // Clear
        cache.clear();
        assert!(cache.is_empty());
        assert!(!cache.contains(&tag1));
    }

    #[test]
    fn test_path_request_destination_hash() {
        // Should produce consistent hash
        let hash1 = PathRequestManager::path_request_destination_hash();
        let hash2 = PathRequestManager::path_request_destination_hash();
        assert_eq!(hash1.as_slice(), hash2.as_slice());

        // Should not be all zeros
        assert!(!hash1.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_build_request_data_without_transport() {
        let dest = AddressHash::new_from_slice(&[0xAB; 32]);
        let (data, tag) = PathRequestManager::build_request_data(&dest, None);

        // Without transport: dest(16) + tag(16) = 32 bytes
        assert_eq!(data.len(), 32);

        // First 16 bytes should be destination hash
        assert_eq!(&data.as_slice()[..16], &dest.as_slice()[..16]);

        // Last 16 bytes should be the tag
        assert_eq!(&data.as_slice()[16..32], &tag);
    }

    #[test]
    fn test_build_request_data_with_transport() {
        let dest = AddressHash::new_from_slice(&[0xAB; 32]);
        let transport_id = AddressHash::new_from_slice(&[0xCD; 32]);
        let (data, tag) = PathRequestManager::build_request_data(&dest, Some(&transport_id));

        // With transport: dest(16) + transport(16) + tag(16) = 48 bytes
        assert_eq!(data.len(), 48);

        // First 16 bytes should be destination hash
        assert_eq!(&data.as_slice()[..16], &dest.as_slice()[..16]);

        // Next 16 bytes should be transport ID
        assert_eq!(&data.as_slice()[16..32], &transport_id.as_slice()[..16]);

        // Last 16 bytes should be the tag
        assert_eq!(&data.as_slice()[32..48], &tag);
    }

    #[test]
    fn test_create_request_packet() {
        let dest = AddressHash::new_from_slice(&[0xAB; 32]);
        let (packet, _tag) = PathRequestManager::create_request_packet(&dest, None);

        // Verify packet properties
        assert_eq!(packet.header.packet_type, PacketType::Data);
        assert_eq!(packet.header.destination_type, DestinationType::Plain);
        assert_eq!(packet.header.propagation_type, PropagationType::Broadcast);
        assert_eq!(packet.header.header_type, HeaderType::Type1);
        assert_eq!(packet.header.hops, 0);
        assert_eq!(packet.context, PacketContext::None);

        // Destination should be path request control destination
        let expected_dest = PathRequestManager::path_request_destination_hash();
        assert_eq!(packet.destination.as_slice(), expected_dest.as_slice());
    }

    #[test]
    fn test_parse_request_data_minimal() {
        // Just destination hash (16 bytes) - no tag
        let data = [0xAB; 16];
        let result = PathRequestManager::parse_request_data(&data);

        assert!(result.is_some());
        let (dest, transport, tag) = result.unwrap();
        assert_eq!(&dest.as_slice()[..16], &data[..16]);
        assert!(transport.is_none());
        assert!(tag.is_none());
    }

    #[test]
    fn test_parse_request_data_with_tag() {
        // Destination (16) + tag (16) = 32 bytes
        let mut data = [0u8; 32];
        data[..16].fill(0xAB); // destination
        data[16..].fill(0xCD); // tag

        let result = PathRequestManager::parse_request_data(&data);

        assert!(result.is_some());
        let (dest, transport, tag) = result.unwrap();
        assert_eq!(&dest.as_slice()[..16], &data[..16]);
        assert!(transport.is_none());
        assert!(tag.is_some());
        assert_eq!(&tag.unwrap()[..], &data[16..]);
    }

    #[test]
    fn test_parse_request_data_with_transport() {
        // Destination (16) + transport (16) + tag (16) = 48 bytes
        let mut data = [0u8; 48];
        data[..16].fill(0xAB);   // destination
        data[16..32].fill(0xCD); // transport
        data[32..].fill(0xEF);   // tag

        let result = PathRequestManager::parse_request_data(&data);

        assert!(result.is_some());
        let (dest, transport, tag) = result.unwrap();
        assert_eq!(&dest.as_slice()[..16], &data[..16]);
        assert!(transport.is_some());
        assert_eq!(&transport.unwrap().as_slice()[..16], &data[16..32]);
        assert!(tag.is_some());
        assert_eq!(&tag.unwrap()[..], &data[32..]);
    }

    #[test]
    fn test_parse_request_data_too_short() {
        // Less than 16 bytes should fail
        let data = [0xAB; 15];
        let result = PathRequestManager::parse_request_data(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_roundtrip_request_data() {
        // Build and parse should roundtrip correctly
        let dest = AddressHash::new_from_slice(&[0xAB; 32]);
        let transport_id = AddressHash::new_from_slice(&[0xCD; 32]);

        let (data, original_tag) = PathRequestManager::build_request_data(&dest, Some(&transport_id));
        let result = PathRequestManager::parse_request_data(data.as_slice());

        assert!(result.is_some());
        let (parsed_dest, parsed_transport, parsed_tag) = result.unwrap();

        // First 16 bytes should match
        assert_eq!(&parsed_dest.as_slice()[..16], &dest.as_slice()[..16]);
        assert!(parsed_transport.is_some());
        assert_eq!(&parsed_transport.unwrap().as_slice()[..16], &transport_id.as_slice()[..16]);
        assert!(parsed_tag.is_some());
        assert_eq!(parsed_tag.unwrap(), original_tag);
    }
}
