//! Resource configuration and progress types.
//!
//! This module contains configuration and progress tracking types for resource transfers.

use std::time::Duration;

use super::constants::{AUTO_COMPRESS_MAX_SIZE, MAX_ADV_RETRIES, MAX_EFFICIENT_SIZE, MAX_RETRIES};
use super::status::ResourceStatus;
use crate::packet::RETICULUM_MDU;

/// Progress information for resource transfer
#[derive(Debug, Clone)]
pub struct ResourceProgress {
    /// Current status
    pub status: ResourceStatus,
    /// Total size of resource data
    pub total_size: usize,
    /// Size of data transferred
    pub transfer_size: usize,
    /// Number of total parts
    pub total_parts: usize,
    /// Number of parts processed (sent or received)
    pub processed_parts: usize,
    /// Current segment index (1-based)
    pub segment_index: usize,
    /// Total number of segments
    pub total_segments: usize,
    /// Whether the resource is compressed
    pub compressed: bool,
    /// Round-trip time estimate
    pub rtt: Option<Duration>,
    /// Expected in-flight rate (bits per second)
    pub eifr: Option<f64>,
}

impl ResourceProgress {
    /// Get progress as a value between 0.0 and 1.0
    pub fn get_progress(&self) -> f64 {
        if self.status == ResourceStatus::Complete && self.segment_index == self.total_segments {
            return 1.0;
        }

        if self.total_parts == 0 {
            return 0.0;
        }

        if !self.is_split() {
            return self.processed_parts as f64 / self.total_parts as f64;
        }

        // For split resources, calculate based on segments
        let max_parts_per_segment =
            (MAX_EFFICIENT_SIZE as f64 / RETICULUM_MDU as f64).ceil() as usize;
        let previously_processed = (self.segment_index - 1) * max_parts_per_segment;

        let current_segment_factor = if self.total_parts < max_parts_per_segment {
            max_parts_per_segment as f64 / self.total_parts as f64
        } else {
            1.0
        };

        let effective_processed =
            previously_processed as f64 + self.processed_parts as f64 * current_segment_factor;
        let effective_total = self.total_segments * max_parts_per_segment;

        (effective_processed / effective_total as f64).min(1.0)
    }

    /// Get segment-local progress (ignoring other segments).
    /// Returns value between 0.0 and 1.0 for current segment only.
    pub fn get_segment_progress(&self) -> f64 {
        if self.status == ResourceStatus::Complete && self.segment_index == self.total_segments {
            return 1.0;
        }
        if self.total_parts == 0 {
            return 0.0;
        }
        (self.processed_parts as f64 / self.total_parts as f64).min(1.0)
    }

    /// Check if resource is split into multiple segments
    pub fn is_split(&self) -> bool {
        self.total_segments > 1
    }
}

/// Configuration for a resource transfer
#[derive(Clone)]
pub struct ResourceConfig {
    /// Whether to auto-compress the resource
    pub auto_compress: bool,
    /// Maximum size for auto-compression
    pub auto_compress_limit: usize,
    /// Transfer timeout
    pub timeout: Option<Duration>,
    /// Maximum retries
    pub max_retries: u32,
    /// Maximum advertisement retries
    pub max_adv_retries: u32,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            auto_compress: true,
            auto_compress_limit: AUTO_COMPRESS_MAX_SIZE,
            timeout: None,
            max_retries: MAX_RETRIES,
            max_adv_retries: MAX_ADV_RETRIES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_progress() {
        let progress = ResourceProgress {
            status: ResourceStatus::Transferring,
            total_size: 10000,
            transfer_size: 5000,
            total_parts: 10,
            processed_parts: 5,
            segment_index: 1,
            total_segments: 1,
            compressed: false,
            rtt: Some(Duration::from_millis(100)),
            eifr: Some(50000.0),
        };

        let p = progress.get_progress();
        assert!((p - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_resource_config_default() {
        let config = ResourceConfig::default();
        assert!(config.auto_compress);
        assert_eq!(config.auto_compress_limit, AUTO_COMPRESS_MAX_SIZE);
        assert_eq!(config.max_retries, MAX_RETRIES);
        assert_eq!(config.max_adv_retries, MAX_ADV_RETRIES);
    }
}
