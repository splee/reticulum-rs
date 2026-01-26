//! Request receipt for tracking request/response state on links.
//!
//! This module provides the RequestReceipt type that tracks the state of
//! requests sent over a Link, mirroring Python's RNS.Link.RequestReceipt.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// Status of a request receipt.
///
/// Matches Python's RequestReceipt status constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestReceiptStatus {
    /// Request failed (timeout or error)
    Failed = 0x00,
    /// Request has been sent
    Sent = 0x01,
    /// Request has been delivered (proof received)
    Delivered = 0x02,
    /// Response is being received
    Receiving = 0x03,
    /// Response is ready
    Ready = 0x04,
}

impl Default for RequestReceiptStatus {
    fn default() -> Self {
        Self::Sent
    }
}

/// Callback type for response received events.
pub type ResponseCallback = Arc<dyn Fn(&RequestReceipt) + Send + Sync>;

/// Callback type for request failed events.
pub type FailedCallback = Arc<dyn Fn(&RequestReceipt) + Send + Sync>;

/// Callback type for progress update events.
pub type ProgressCallback = Arc<dyn Fn(&RequestReceipt) + Send + Sync>;

/// Container for request receipt callbacks.
#[derive(Clone, Default)]
pub struct RequestReceiptCallbacks {
    /// Called when response is received
    pub response: Option<ResponseCallback>,
    /// Called when request fails
    pub failed: Option<FailedCallback>,
    /// Called on progress updates
    pub progress: Option<ProgressCallback>,
}

impl std::fmt::Debug for RequestReceiptCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestReceiptCallbacks")
            .field("response", &self.response.is_some())
            .field("failed", &self.failed.is_some())
            .field("progress", &self.progress.is_some())
            .finish()
    }
}

/// Receipt for a request sent over a link.
///
/// Tracks the state of a request from sent through delivery to response.
/// Mirrors Python's RNS.Link.RequestReceipt class.
#[derive(Debug)]
pub struct RequestReceipt {
    /// Unique identifier for this request (truncated hash)
    request_id: [u8; 16],
    /// Current status of the request
    status: RequestReceiptStatus,
    /// Response data when ready
    response: Option<Vec<u8>>,
    /// Response metadata when ready
    metadata: Option<Vec<u8>>,
    /// Transfer progress (0.0 to 1.0)
    progress: f32,
    /// When the request was sent
    sent_at: Instant,
    /// Timeout duration for this request
    timeout: Duration,
    /// When the request concluded (success or failure)
    concluded_at: Option<Instant>,
    /// When the response was fully received
    response_concluded_at: Option<Instant>,
    /// Request size in bytes
    request_size: Option<usize>,
    /// Response transfer size in bytes
    response_transfer_size: Option<usize>,
    /// Response size in bytes (uncompressed)
    response_size: Option<usize>,
    /// Callbacks for this request
    callbacks: RequestReceiptCallbacks,
}

impl RequestReceipt {
    /// Create a new request receipt.
    ///
    /// # Arguments
    ///
    /// * `request_id` - The truncated hash identifying this request
    /// * `timeout` - Maximum time to wait for response
    /// * `request_size` - Size of the request data in bytes
    pub fn new(request_id: [u8; 16], timeout: Duration, request_size: Option<usize>) -> Self {
        Self {
            request_id,
            status: RequestReceiptStatus::Sent,
            response: None,
            metadata: None,
            progress: 0.0,
            sent_at: Instant::now(),
            timeout,
            concluded_at: None,
            response_concluded_at: None,
            request_size,
            response_transfer_size: None,
            response_size: None,
            callbacks: RequestReceiptCallbacks::default(),
        }
    }

    /// Get the request ID.
    pub fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Get the current status.
    pub fn status(&self) -> RequestReceiptStatus {
        self.status
    }

    /// Get the response data if ready.
    pub fn response(&self) -> Option<&[u8]> {
        self.response.as_deref()
    }

    /// Get the response metadata if available.
    pub fn metadata(&self) -> Option<&[u8]> {
        self.metadata.as_deref()
    }

    /// Get the response time (time from sent to response received).
    ///
    /// Returns None if response has not been received yet.
    pub fn response_time(&self) -> Option<Duration> {
        self.response_concluded_at.map(|t| t.duration_since(self.sent_at))
    }

    /// Get the current progress (0.0 to 1.0).
    pub fn progress(&self) -> f32 {
        self.progress
    }

    /// Check if the request has concluded (either success or failure).
    pub fn concluded(&self) -> bool {
        matches!(
            self.status,
            RequestReceiptStatus::Ready | RequestReceiptStatus::Failed
        )
    }

    /// Check if the request has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.sent_at.elapsed() > self.timeout
    }

    /// Set the response callback.
    pub fn set_response_callback<F>(&mut self, callback: F)
    where
        F: Fn(&RequestReceipt) + Send + Sync + 'static,
    {
        self.callbacks.response = Some(Arc::new(callback));
    }

    /// Set the failed callback.
    pub fn set_failed_callback<F>(&mut self, callback: F)
    where
        F: Fn(&RequestReceipt) + Send + Sync + 'static,
    {
        self.callbacks.failed = Some(Arc::new(callback));
    }

    /// Set the progress callback.
    pub fn set_progress_callback<F>(&mut self, callback: F)
    where
        F: Fn(&RequestReceipt) + Send + Sync + 'static,
    {
        self.callbacks.progress = Some(Arc::new(callback));
    }

    /// Mark the request as delivered.
    pub(crate) fn set_delivered(&mut self) {
        self.status = RequestReceiptStatus::Delivered;
    }

    /// Mark the request as receiving response.
    pub(crate) fn set_receiving(&mut self, progress: f32) {
        self.status = RequestReceiptStatus::Receiving;
        self.progress = progress;

        if let Some(ref callback) = self.callbacks.progress {
            callback(self);
        }
    }

    /// Mark the request as ready with response data.
    pub(crate) fn set_ready(&mut self, response: Vec<u8>, metadata: Option<Vec<u8>>) {
        self.status = RequestReceiptStatus::Ready;
        self.response = Some(response);
        self.metadata = metadata;
        self.progress = 1.0;
        self.response_concluded_at = Some(Instant::now());

        if let Some(ref callback) = self.callbacks.progress {
            callback(self);
        }

        if let Some(ref callback) = self.callbacks.response {
            callback(self);
        }
    }

    /// Mark the request as failed.
    pub(crate) fn set_failed(&mut self) {
        self.status = RequestReceiptStatus::Failed;
        self.concluded_at = Some(Instant::now());

        if let Some(ref callback) = self.callbacks.failed {
            callback(self);
        }
    }
}

/// Shared request receipt that can be safely accessed from multiple tasks.
pub type SharedRequestReceipt = Arc<Mutex<RequestReceipt>>;

/// Create a new shared request receipt.
pub fn new_shared_request_receipt(
    request_id: [u8; 16],
    timeout: Duration,
    request_size: Option<usize>,
) -> SharedRequestReceipt {
    Arc::new(Mutex::new(RequestReceipt::new(
        request_id,
        timeout,
        request_size,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_receipt_status_progression() {
        let mut receipt = RequestReceipt::new([0u8; 16], Duration::from_secs(30), None);

        assert_eq!(receipt.status(), RequestReceiptStatus::Sent);
        assert!(!receipt.concluded());

        receipt.set_delivered();
        assert_eq!(receipt.status(), RequestReceiptStatus::Delivered);
        assert!(!receipt.concluded());

        receipt.set_receiving(0.5);
        assert_eq!(receipt.status(), RequestReceiptStatus::Receiving);
        assert!((receipt.progress() - 0.5).abs() < f32::EPSILON);
        assert!(!receipt.concluded());

        receipt.set_ready(vec![1, 2, 3], None);
        assert_eq!(receipt.status(), RequestReceiptStatus::Ready);
        assert!((receipt.progress() - 1.0).abs() < f32::EPSILON);
        assert!(receipt.concluded());
        assert_eq!(receipt.response(), Some([1, 2, 3].as_slice()));
    }

    #[test]
    fn test_request_receipt_failure() {
        let mut receipt = RequestReceipt::new([0u8; 16], Duration::from_secs(30), None);

        receipt.set_failed();
        assert_eq!(receipt.status(), RequestReceiptStatus::Failed);
        assert!(receipt.concluded());
    }

    #[test]
    fn test_request_receipt_timeout_check() {
        let receipt = RequestReceipt::new([0u8; 16], Duration::from_millis(1), None);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        assert!(receipt.is_timed_out());
    }

    #[test]
    fn test_request_receipt_request_id() {
        let id: [u8; 16] = [0xAB; 16];
        let receipt = RequestReceipt::new(id, Duration::from_secs(30), None);

        assert_eq!(receipt.request_id(), &id);
    }

    #[test]
    fn test_request_receipt_response_time() {
        let mut receipt = RequestReceipt::new([0u8; 16], Duration::from_secs(30), None);

        // Response time should be None before ready
        assert!(receipt.response_time().is_none());

        receipt.set_ready(vec![1, 2, 3], None);

        // Response time should be Some after ready
        assert!(receipt.response_time().is_some());
    }

    #[test]
    fn test_request_receipt_metadata() {
        let mut receipt = RequestReceipt::new([0u8; 16], Duration::from_secs(30), None);

        // Metadata should be None initially
        assert!(receipt.metadata().is_none());

        receipt.set_ready(vec![1], Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));

        // Metadata should be available after ready
        assert!(receipt.metadata().is_some());
        assert_eq!(receipt.metadata().unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_request_receipt_status_enum_values() {
        assert_eq!(RequestReceiptStatus::Failed as u8, 0x00);
        assert_eq!(RequestReceiptStatus::Sent as u8, 0x01);
        assert_eq!(RequestReceiptStatus::Delivered as u8, 0x02);
        assert_eq!(RequestReceiptStatus::Receiving as u8, 0x03);
        assert_eq!(RequestReceiptStatus::Ready as u8, 0x04);
    }

    #[test]
    fn test_request_receipt_progress_updates() {
        let mut receipt = RequestReceipt::new([0u8; 16], Duration::from_secs(30), None);

        // Initial progress should be 0
        assert!((receipt.progress() - 0.0).abs() < f32::EPSILON);

        // Progress during receiving
        receipt.set_receiving(0.25);
        assert!((receipt.progress() - 0.25).abs() < f32::EPSILON);

        receipt.set_receiving(0.75);
        assert!((receipt.progress() - 0.75).abs() < f32::EPSILON);

        // Progress after ready should be 1.0
        receipt.set_ready(vec![], None);
        assert!((receipt.progress() - 1.0).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_new_shared_request_receipt() {
        let id: [u8; 16] = [0xCD; 16];
        let shared = new_shared_request_receipt(id, Duration::from_secs(60), Some(1024));

        let receipt = shared.lock().await;
        assert_eq!(receipt.request_id(), &id);
        assert_eq!(receipt.status(), RequestReceiptStatus::Sent);
    }

    #[test]
    fn test_request_receipt_not_timed_out_initially() {
        let receipt = RequestReceipt::new([0u8; 16], Duration::from_secs(3600), None);

        // Should not be timed out with 1 hour timeout
        assert!(!receipt.is_timed_out());
    }

    #[test]
    fn test_request_receipt_empty_response() {
        let mut receipt = RequestReceipt::new([0u8; 16], Duration::from_secs(30), None);

        receipt.set_ready(vec![], None);

        assert_eq!(receipt.status(), RequestReceiptStatus::Ready);
        assert!(receipt.concluded());
        assert_eq!(receipt.response(), Some([].as_slice()));
    }
}
