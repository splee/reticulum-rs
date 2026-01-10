//! Path request handling for discovering routes to destinations.
//!
//! This module implements the path request/response protocol for
//! discovering routes to destinations across the network.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::error::RnsError;

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
        let mut request = PathRequest::new(destination.clone(), true);
        if let Some(cb) = callback {
            request.callback = Some(cb);
        }

        requests.insert(destination.clone(), request);
        last_times.insert(destination, Instant::now());

        Ok(true)
    }

    /// Request path on behalf of another node (discovery)
    pub fn request_discovery_path(&self, destination: AddressHash) -> Result<bool, RnsError> {
        let mut requests = self.discovery_requests.lock().unwrap();

        if requests.contains_key(&destination) {
            return Ok(false);
        }

        let request = PathRequest::new(destination.clone(), false);
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
                to_retry.push(dest.clone());
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
        let _ = self.request_path(destination.clone(), None);

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
}
