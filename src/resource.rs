//! Resource transfer system for large data transfers over Reticulum links.
//!
//! The Resource system allows transferring arbitrary amounts of data over a link.
//! It automatically handles sequencing, compression, coordination, and checksumming.
//!
//! Key features:
//! - Segmentation for large data transfers
//! - Hashmap-based integrity checking
//! - Flow control windowing
//! - Compression support (bz2)
//! - Progress callbacks

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use rand_core::CryptoRngCore;
use sha2::Digest;

use crate::error::RnsError;
use crate::hash::Hash;
use crate::packet::PACKET_MDU;

/// Length of the map hash for each part
pub const MAPHASH_LEN: usize = 4;
/// Length of the random hash prepended to data
pub const RANDOM_HASH_SIZE: usize = 4;

/// The initial window size at beginning of transfer
pub const WINDOW_INITIAL: usize = 4;
/// Absolute minimum window size during transfer
pub const WINDOW_MIN: usize = 2;
/// The maximum window size for transfers on slow links
pub const WINDOW_MAX_SLOW: usize = 10;
/// The maximum window size for transfers on very slow links
pub const WINDOW_MAX_VERY_SLOW: usize = 4;
/// The maximum window size for transfers on fast links
pub const WINDOW_MAX_FAST: usize = 75;
/// Global maximum window (for calculating maps and guard segments)
pub const WINDOW_MAX: usize = WINDOW_MAX_FAST;

/// Minimum allowed flexibility of window size
pub const WINDOW_FLEXIBILITY: usize = 4;

/// Fast rate threshold rounds before using fast window size
pub const FAST_RATE_THRESHOLD: usize = WINDOW_MAX_SLOW - WINDOW_INITIAL - 2;
/// Very slow rate threshold rounds before capping window
pub const VERY_SLOW_RATE_THRESHOLD: usize = 2;

/// Rate threshold for fast links (bytes per second) - 50 Kbps
pub const RATE_FAST: f64 = (50.0 * 1000.0) / 8.0;
/// Rate threshold for very slow links (bytes per second) - 2 Kbps
pub const RATE_VERY_SLOW: f64 = (2.0 * 1000.0) / 8.0;

/// Maximum efficient size for a single resource segment (about 1 MB)
/// Capped at 16777215 (0xFFFFFF) to fit in 3 bytes in advertisements
pub const MAX_EFFICIENT_SIZE: usize = 1 * 1024 * 1024 - 1;

/// Maximum metadata size (about 16 MB)
pub const METADATA_MAX_SIZE: usize = 16 * 1024 * 1024 - 1;

/// Maximum size to auto-compress before sending
pub const AUTO_COMPRESS_MAX_SIZE: usize = 64 * 1024 * 1024;

/// Response max grace time
pub const RESPONSE_MAX_GRACE_TIME: f64 = 10.0;

/// Part timeout factor
pub const PART_TIMEOUT_FACTOR: f64 = 4.0;
/// Part timeout factor after RTT is known
pub const PART_TIMEOUT_FACTOR_AFTER_RTT: f64 = 2.0;
/// Proof timeout factor
pub const PROOF_TIMEOUT_FACTOR: f64 = 3.0;

/// Maximum retries for resource transfer
pub const MAX_RETRIES: u32 = 16;
/// Maximum retries for advertisement
pub const MAX_ADV_RETRIES: u32 = 4;

/// Sender grace time
pub const SENDER_GRACE_TIME: f64 = 10.0;
/// Processing grace time
pub const PROCESSING_GRACE: f64 = 1.0;
/// Retry grace time
pub const RETRY_GRACE_TIME: f64 = 0.25;
/// Per-retry delay
pub const PER_RETRY_DELAY: f64 = 0.5;

/// Watchdog max sleep time
pub const WATCHDOG_MAX_SLEEP: f64 = 1.0;

/// Hashmap status indicators
pub const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;

/// Resource status
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ResourceStatus {
    /// No status
    None = 0x00,
    /// Resource is queued for transfer
    Queued = 0x01,
    /// Resource advertisement has been sent
    Advertised = 0x02,
    /// Resource is currently transferring
    Transferring = 0x03,
    /// Waiting for proof after all parts sent
    AwaitingProof = 0x04,
    /// Assembling received parts
    Assembling = 0x05,
    /// Transfer completed successfully
    Complete = 0x06,
    /// Transfer failed
    Failed = 0x07,
    /// Resource data is corrupt
    Corrupt = 0x08,
}

impl Default for ResourceStatus {
    fn default() -> Self {
        ResourceStatus::None
    }
}

impl From<u8> for ResourceStatus {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ResourceStatus::None,
            0x01 => ResourceStatus::Queued,
            0x02 => ResourceStatus::Advertised,
            0x03 => ResourceStatus::Transferring,
            0x04 => ResourceStatus::AwaitingProof,
            0x05 => ResourceStatus::Assembling,
            0x06 => ResourceStatus::Complete,
            0x07 => ResourceStatus::Failed,
            0x08 => ResourceStatus::Corrupt,
            _ => ResourceStatus::None,
        }
    }
}

/// Flags for resource advertisements
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceFlags {
    /// Whether the resource is encrypted
    pub encrypted: bool,
    /// Whether the resource is compressed
    pub compressed: bool,
    /// Whether the resource is split into segments
    pub split: bool,
    /// Whether this is a request
    pub is_request: bool,
    /// Whether this is a response
    pub is_response: bool,
    /// Whether the resource has metadata
    pub has_metadata: bool,
}

impl ResourceFlags {
    /// Pack flags into a single byte
    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.encrypted {
            flags |= 0x01;
        }
        if self.compressed {
            flags |= 0x02;
        }
        if self.split {
            flags |= 0x04;
        }
        if self.is_request {
            flags |= 0x08;
        }
        if self.is_response {
            flags |= 0x10;
        }
        if self.has_metadata {
            flags |= 0x20;
        }
        flags
    }

    /// Unpack flags from a single byte
    pub fn from_byte(byte: u8) -> Self {
        Self {
            encrypted: (byte & 0x01) != 0,
            compressed: (byte & 0x02) != 0,
            split: (byte & 0x04) != 0,
            is_request: (byte & 0x08) != 0,
            is_response: (byte & 0x10) != 0,
            has_metadata: (byte & 0x20) != 0,
        }
    }
}

/// A resource part ready for transmission
#[derive(Debug, Clone)]
pub struct ResourcePart {
    /// The data for this part
    pub data: Vec<u8>,
    /// The map hash for this part
    pub map_hash: [u8; MAPHASH_LEN],
    /// Whether this part has been sent
    pub sent: bool,
}

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
            (MAX_EFFICIENT_SIZE as f64 / PACKET_MDU as f64).ceil() as usize;
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

    /// Check if resource is split into multiple segments
    pub fn is_split(&self) -> bool {
        self.total_segments > 1
    }
}

/// Type alias for progress callback
pub type ProgressCallback = Arc<dyn Fn(&ResourceProgress) + Send + Sync>;

/// Type alias for completion callback
pub type CompletionCallback = Arc<dyn Fn(&Resource, bool) + Send + Sync>;

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

/// A resource for transferring data over a link
pub struct Resource {
    /// Current status
    status: RwLock<ResourceStatus>,

    /// Resource hash (full hash of data + random_hash)
    hash: [u8; 32],
    /// Truncated hash for identification
    truncated_hash: [u8; 16],
    /// Original hash (for multi-segment resources)
    original_hash: [u8; 32],
    /// Random hash prepended to data
    random_hash: [u8; RANDOM_HASH_SIZE],
    /// Expected proof hash
    expected_proof: [u8; 32],

    /// Uncompressed data size
    uncompressed_size: usize,
    /// Compressed/transfer size
    size: usize,
    /// Total data size including metadata
    total_size: usize,

    /// Resource flags
    flags: ResourceFlags,

    /// Parts for outgoing resource
    parts: Vec<ResourcePart>,
    /// Hashmap bytes
    hashmap: Vec<u8>,
    /// Total number of parts
    total_parts: usize,
    /// Number of sent parts (for outgoing)
    sent_parts: usize,

    /// Received parts for incoming resource
    received_parts: Vec<Option<Vec<u8>>>,
    /// Count of received parts
    received_count: usize,
    /// Outstanding parts waiting to be received
    outstanding_parts: usize,

    /// Segment index (1-based)
    segment_index: usize,
    /// Total number of segments
    total_segments: usize,

    /// Whether we are the initiator
    initiator: bool,

    /// Window size
    window: usize,
    /// Maximum window size
    window_max: usize,
    /// Minimum window size
    window_min: usize,
    /// Window flexibility
    window_flexibility: usize,

    /// Round-trip time estimate
    rtt: Option<Duration>,
    /// Expected in-flight rate (bytes per second)
    eifr: Option<f64>,
    /// Fast rate rounds counter
    fast_rate_rounds: usize,
    /// Very slow rate rounds counter
    very_slow_rate_rounds: usize,

    /// Bytes received in current RTT cycle
    rtt_rxd_bytes: usize,
    /// Bytes received at last part request
    rtt_rxd_bytes_at_part_req: usize,
    /// Request-response RTT rate
    req_resp_rtt_rate: f64,
    /// Request data RTT rate
    req_data_rtt_rate: f64,

    /// Time of last activity
    last_activity: Instant,
    /// Time when transfer started
    started_transferring: Option<Instant>,
    /// Time of last part sent
    last_part_sent: Option<Instant>,

    /// Retries remaining
    retries_left: u32,

    /// Configuration
    config: ResourceConfig,

    /// Request ID for request/response pattern
    request_id: Option<[u8; 16]>,

    /// Metadata bytes
    metadata: Option<Vec<u8>>,

    /// Progress callback
    progress_callback: Option<ProgressCallback>,
    /// Completion callback
    completion_callback: Option<CompletionCallback>,

    /// SDU (Service Data Unit) size for parts
    sdu: usize,

    /// Hashmap height (how many entries have been received)
    hashmap_height: usize,
    /// Whether waiting for hashmap update
    waiting_for_hmu: bool,
    /// Consecutive completed height
    consecutive_completed_height: isize,
    /// Receiver's minimum consecutive height (for outgoing)
    receiver_min_consecutive_height: usize,
}

impl Resource {
    /// Create a new outgoing resource from data
    pub fn new<R: CryptoRngCore>(
        rng: &mut R,
        data: &[u8],
        config: ResourceConfig,
        metadata: Option<&[u8]>,
    ) -> Result<Self, RnsError> {
        let sdu = PACKET_MDU - 64; // Leave room for headers

        // Handle metadata
        let (metadata_bytes, has_metadata) = if let Some(meta) = metadata {
            if meta.len() > METADATA_MAX_SIZE {
                return Err(RnsError::InvalidArgument);
            }
            // Pack metadata with 3-byte length prefix
            let mut packed = Vec::with_capacity(3 + meta.len());
            packed.push((meta.len() >> 16) as u8);
            packed.push((meta.len() >> 8) as u8);
            packed.push(meta.len() as u8);
            packed.extend_from_slice(meta);
            (Some(packed), true)
        } else {
            (None, false)
        };

        let metadata_size = metadata_bytes.as_ref().map(|m| m.len()).unwrap_or(0);

        // Combine metadata and data
        let mut full_data = Vec::with_capacity(metadata_size + data.len());
        if let Some(ref meta) = metadata_bytes {
            full_data.extend_from_slice(meta);
        }
        full_data.extend_from_slice(data);

        let uncompressed_size = full_data.len();
        let total_size = uncompressed_size;

        // Try compression if enabled and data is small enough
        let (processed_data, compressed) =
            if config.auto_compress && uncompressed_size <= config.auto_compress_limit {
                match compress_bz2(&full_data) {
                    Ok(compressed_data) if compressed_data.len() < uncompressed_size => {
                        (compressed_data, true)
                    }
                    _ => (full_data, false),
                }
            } else {
                (full_data, false)
            };

        // Generate random hash
        let mut random_hash = [0u8; RANDOM_HASH_SIZE];
        rng.fill_bytes(&mut random_hash);

        // Prepend random hash and (in a real implementation) encrypt
        let mut final_data = Vec::with_capacity(RANDOM_HASH_SIZE + processed_data.len());
        final_data.extend_from_slice(&random_hash);
        final_data.extend_from_slice(&processed_data);

        // In production, this would be encrypted using link.encrypt()
        // For now, we just mark it as encrypted
        let encrypted = true;

        let size = final_data.len();

        // Calculate hashes
        let hash = Hash::new(
            Hash::generator()
                .chain_update(data)
                .chain_update(&random_hash)
                .finalize()
                .into(),
        );

        let truncated_hash = {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&hash.as_bytes()[..16]);
            arr
        };

        let original_hash = *hash.as_bytes();

        let expected_proof = Hash::new(
            Hash::generator()
                .chain_update(data)
                .chain_update(hash.as_bytes())
                .finalize()
                .into(),
        );

        // Calculate number of parts
        let total_parts = (size + sdu - 1) / sdu;

        // Build parts and hashmap
        let mut parts = Vec::with_capacity(total_parts);
        let mut hashmap = Vec::with_capacity(total_parts * MAPHASH_LEN);
        let mut collision_guard = Vec::with_capacity(total_parts.min(256));

        for i in 0..total_parts {
            let start = i * sdu;
            let end = ((i + 1) * sdu).min(size);
            let part_data = final_data[start..end].to_vec();

            // Calculate map hash for this part
            let map_hash = Self::calculate_map_hash(&part_data, &random_hash);

            // Check for collisions
            if collision_guard.contains(&map_hash) {
                // In production, we would regenerate with a new random hash
                // For now, just return an error
                return Err(RnsError::CryptoError);
            }
            collision_guard.push(map_hash);
            if collision_guard.len() > 256 {
                collision_guard.remove(0);
            }

            hashmap.extend_from_slice(&map_hash);
            parts.push(ResourcePart {
                data: part_data,
                map_hash,
                sent: false,
            });
        }

        // Determine if we need to split into segments
        let total_segments = if total_size > MAX_EFFICIENT_SIZE {
            (total_size + MAX_EFFICIENT_SIZE - 1) / MAX_EFFICIENT_SIZE
        } else {
            1
        };

        let flags = ResourceFlags {
            encrypted,
            compressed,
            split: total_segments > 1,
            is_request: false,
            is_response: false,
            has_metadata,
        };

        Ok(Self {
            status: RwLock::new(ResourceStatus::None),
            hash: *hash.as_bytes(),
            truncated_hash,
            original_hash,
            random_hash,
            expected_proof: *expected_proof.as_bytes(),
            uncompressed_size,
            size,
            total_size,
            flags,
            parts,
            hashmap,
            total_parts,
            sent_parts: 0,
            received_parts: Vec::new(),
            received_count: 0,
            outstanding_parts: 0,
            segment_index: 1,
            total_segments,
            initiator: true,
            window: WINDOW_INITIAL,
            window_max: WINDOW_MAX_SLOW,
            window_min: WINDOW_MIN,
            window_flexibility: WINDOW_FLEXIBILITY,
            rtt: None,
            eifr: None,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
            rtt_rxd_bytes: 0,
            rtt_rxd_bytes_at_part_req: 0,
            req_resp_rtt_rate: 0.0,
            req_data_rtt_rate: 0.0,
            last_activity: Instant::now(),
            started_transferring: None,
            last_part_sent: None,
            retries_left: config.max_retries,
            config,
            request_id: None,
            metadata: metadata_bytes,
            progress_callback: None,
            completion_callback: None,
            sdu,
            hashmap_height: 0,
            waiting_for_hmu: false,
            consecutive_completed_height: -1,
            receiver_min_consecutive_height: 0,
        })
    }

    /// Create an incoming resource from an advertisement
    pub fn from_advertisement(adv: &ResourceAdvertisement, sdu: usize) -> Result<Self, RnsError> {
        let flags = adv.flags;
        let total_parts = adv.num_parts;

        // Copy hashmap from advertisement and calculate height
        let hashmap = adv.hashmap.clone();
        let hashmap_height = hashmap.len() / MAPHASH_LEN;

        Ok(Self {
            status: RwLock::new(ResourceStatus::Transferring),
            hash: adv.hash,
            truncated_hash: {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&adv.hash[..16]);
                arr
            },
            original_hash: adv.original_hash,
            random_hash: adv.random_hash,
            expected_proof: [0u8; 32], // Will be calculated on completion
            uncompressed_size: adv.data_size,
            size: adv.transfer_size,
            total_size: adv.data_size,
            flags,
            parts: Vec::new(),
            hashmap,
            total_parts,
            sent_parts: 0,
            received_parts: vec![None; total_parts],
            received_count: 0,
            outstanding_parts: 0,
            segment_index: adv.segment_index,
            total_segments: adv.total_segments,
            initiator: false,
            window: WINDOW_INITIAL,
            window_max: WINDOW_MAX_SLOW,
            window_min: WINDOW_MIN,
            window_flexibility: WINDOW_FLEXIBILITY,
            rtt: None,
            eifr: None,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
            rtt_rxd_bytes: 0,
            rtt_rxd_bytes_at_part_req: 0,
            req_resp_rtt_rate: 0.0,
            req_data_rtt_rate: 0.0,
            last_activity: Instant::now(),
            started_transferring: Some(Instant::now()),
            last_part_sent: None,
            retries_left: MAX_RETRIES,
            config: ResourceConfig::default(),
            request_id: adv.request_id,
            metadata: None,
            progress_callback: None,
            completion_callback: None,
            sdu,
            hashmap_height,
            waiting_for_hmu: false,
            consecutive_completed_height: -1,
            receiver_min_consecutive_height: 0,
        })
    }

    /// Calculate the map hash for a part.
    /// Python: full_hash(data + random_hash)[:MAPHASH_LEN]
    fn calculate_map_hash(data: &[u8], random_hash: &[u8; RANDOM_HASH_SIZE]) -> [u8; MAPHASH_LEN] {
        let full_hash = Hash::new(
            Hash::generator()
                .chain_update(data)
                .chain_update(random_hash)
                .finalize()
                .into(),
        );
        let mut result = [0u8; MAPHASH_LEN];
        result.copy_from_slice(&full_hash.as_bytes()[..MAPHASH_LEN]);
        result
    }

    /// Get current status
    pub fn status(&self) -> ResourceStatus {
        *self.status.read().unwrap()
    }

    /// Set status
    pub fn set_status(&self, status: ResourceStatus) {
        *self.status.write().unwrap() = status;
    }

    /// Get resource hash
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Get truncated hash
    pub fn truncated_hash(&self) -> &[u8; 16] {
        &self.truncated_hash
    }

    /// Get original hash (for segmented resources)
    pub fn original_hash(&self) -> &[u8; 32] {
        &self.original_hash
    }

    /// Get the resource size (transfer size)
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get the total data size
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Get total number of parts
    pub fn total_parts(&self) -> usize {
        self.total_parts
    }

    /// Get number of segments
    pub fn total_segments(&self) -> usize {
        self.total_segments
    }

    /// Get current segment index
    pub fn segment_index(&self) -> usize {
        self.segment_index
    }

    /// Check if resource is compressed
    pub fn is_compressed(&self) -> bool {
        self.flags.compressed
    }

    /// Check if resource is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.flags.encrypted
    }

    /// Check if we are the initiator
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Get progress information
    pub fn progress(&self) -> ResourceProgress {
        let processed = if self.initiator {
            self.sent_parts
        } else {
            self.received_count
        };

        ResourceProgress {
            status: self.status(),
            total_size: self.total_size,
            transfer_size: self.size,
            total_parts: self.total_parts,
            processed_parts: processed,
            segment_index: self.segment_index,
            total_segments: self.total_segments,
            compressed: self.flags.compressed,
            rtt: self.rtt,
            eifr: self.eifr,
        }
    }

    /// Set progress callback
    pub fn set_progress_callback(&mut self, callback: ProgressCallback) {
        self.progress_callback = Some(callback);
    }

    /// Set completion callback
    pub fn set_completion_callback(&mut self, callback: CompletionCallback) {
        self.completion_callback = Some(callback);
    }

    /// Create a resource advertisement
    pub fn create_advertisement(&self) -> ResourceAdvertisement {
        ResourceAdvertisement {
            transfer_size: self.size,
            data_size: self.total_size,
            num_parts: self.total_parts,
            hash: self.hash,
            random_hash: self.random_hash,
            original_hash: self.original_hash,
            segment_index: self.segment_index,
            total_segments: self.total_segments,
            request_id: self.request_id,
            flags: self.flags,
            hashmap: self.hashmap.clone(),
        }
    }

    /// Update hashmap from a hashmap update packet
    pub fn update_hashmap(&mut self, segment: usize, hashmap_data: &[u8]) {
        let seg_len = ResourceAdvertisement::HASHMAP_MAX_LEN;
        let hashes = hashmap_data.len() / MAPHASH_LEN;

        // Ensure our hashmap vec is large enough
        let needed_size = (segment * seg_len + hashes) * MAPHASH_LEN;
        if self.hashmap.len() < needed_size {
            self.hashmap.resize(needed_size, 0);
        }

        for i in 0..hashes {
            let src_start = i * MAPHASH_LEN;
            let src_end = (i + 1) * MAPHASH_LEN;
            let dst_idx = (i + segment * seg_len) * MAPHASH_LEN;

            if dst_idx + MAPHASH_LEN <= self.hashmap.len() {
                self.hashmap[dst_idx..dst_idx + MAPHASH_LEN]
                    .copy_from_slice(&hashmap_data[src_start..src_end]);
            }
        }

        self.hashmap_height = segment * seg_len + hashes;
        self.waiting_for_hmu = false;
    }

    /// Get part at index
    pub fn get_part(&self, index: usize) -> Option<&ResourcePart> {
        self.parts.get(index)
    }

    /// Mark part as sent
    pub fn mark_part_sent(&mut self, index: usize) {
        if let Some(part) = self.parts.get_mut(index) {
            if !part.sent {
                part.sent = true;
                self.sent_parts += 1;
                self.last_part_sent = Some(Instant::now());
            }
        }
    }

    /// Receive a part by map hash
    pub fn receive_part(&mut self, data: Vec<u8>) -> bool {
        let map_hash = Self::calculate_map_hash(&data, &self.random_hash);

        log::debug!(
            "receive_part: data {} bytes, first 20: {:?}, calculated map_hash {:?}",
            data.len(),
            &data[..data.len().min(20)],
            &map_hash
        );
        log::debug!(
            "receive_part: random_hash {:?}, hashmap {} bytes, hashmap_height {}, consecutive_completed_height {}",
            &self.random_hash,
            self.hashmap.len(),
            self.hashmap_height,
            self.consecutive_completed_height
        );

        // Search for matching hash in window
        let start = (self.consecutive_completed_height + 1) as usize;
        let end = (start + self.window).min(self.total_parts);

        log::debug!("receive_part: searching from {} to {}", start, end);

        for i in start..end {
            let hash_start = i * MAPHASH_LEN;
            let hash_end = hash_start + MAPHASH_LEN;

            if hash_end <= self.hashmap.len() {
                let expected_hash = &self.hashmap[hash_start..hash_end];
                log::debug!(
                    "receive_part: part {}, expected_hash {:?}",
                    i,
                    expected_hash
                );
                if expected_hash == map_hash {
                    if self.received_parts[i].is_none() {
                        self.received_parts[i] = Some(data);
                        self.rtt_rxd_bytes += self.sdu;
                        self.received_count += 1;
                        self.outstanding_parts = self.outstanding_parts.saturating_sub(1);

                        // Update consecutive completed height
                        if i as isize == self.consecutive_completed_height + 1 {
                            self.consecutive_completed_height = i as isize;

                            // Extend if consecutive
                            let mut cp = (self.consecutive_completed_height + 1) as usize;
                            while cp < self.received_parts.len()
                                && self.received_parts[cp].is_some()
                            {
                                self.consecutive_completed_height = cp as isize;
                                cp += 1;
                            }
                        }

                        // Trigger progress callback
                        if let Some(ref callback) = self.progress_callback {
                            callback(&self.progress());
                        }

                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if all parts have been received
    pub fn is_complete(&self) -> bool {
        self.received_count == self.total_parts
    }

    /// Assemble received parts into final data.
    ///
    /// The `decrypt_fn` is called to decrypt the assembled data stream if the resource
    /// is encrypted. It should accept the encrypted data and return the decrypted data.
    /// This is typically `link.decrypt()` from the Link that received the resource.
    pub fn assemble_with_decryption<F>(&mut self, decrypt_fn: F) -> Result<Vec<u8>, RnsError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, RnsError>,
    {
        if !self.is_complete() {
            return Err(RnsError::InvalidArgument);
        }

        self.set_status(ResourceStatus::Assembling);

        // Concatenate all parts
        let mut stream = Vec::with_capacity(self.size);
        for part in &self.received_parts {
            if let Some(data) = part {
                stream.extend_from_slice(data);
            }
        }

        // Decrypt if resource is encrypted
        let decrypted = if self.flags.encrypted {
            decrypt_fn(&stream)?
        } else {
            stream
        };

        // Strip off random hash (which was prepended to the data before encryption)
        if decrypted.len() < RANDOM_HASH_SIZE {
            self.set_status(ResourceStatus::Corrupt);
            return Err(RnsError::InvalidArgument);
        }
        let data = &decrypted[RANDOM_HASH_SIZE..];

        // Decompress if needed
        let final_data = if self.flags.compressed {
            decompress_bz2(data)?
        } else {
            data.to_vec()
        };

        // Verify hash: Hash(uncompressed_data + random_hash)
        let calculated_hash = Hash::new(
            Hash::generator()
                .chain_update(&final_data)
                .chain_update(&self.random_hash)
                .finalize()
                .into(),
        );

        if calculated_hash.as_bytes() != &self.hash {
            log::error!(
                "Resource hash mismatch: expected {}, calculated {}",
                hex::encode(&self.hash),
                hex::encode(calculated_hash.as_bytes())
            );
            self.set_status(ResourceStatus::Corrupt);
            return Err(RnsError::IncorrectHash);
        }

        self.set_status(ResourceStatus::Complete);

        // Trigger completion callback
        if let Some(ref callback) = self.completion_callback {
            callback(self, true);
        }

        Ok(final_data)
    }

    /// Assemble received parts into final data (for unencrypted resources).
    /// Use `assemble_with_decryption` for encrypted resources.
    pub fn assemble(&mut self) -> Result<Vec<u8>, RnsError> {
        self.assemble_with_decryption(|data| Ok(data.to_vec()))
    }

    /// Get the raw assembled data (encrypted) without decryption.
    /// This is useful when you need to handle decryption externally (e.g., in an async context).
    /// Returns None if resource is not complete.
    pub fn get_raw_assembled_data(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let mut stream = Vec::with_capacity(self.size);
        for part in &self.received_parts {
            if let Some(data) = part {
                stream.extend_from_slice(data);
            }
        }
        Some(stream)
    }

    /// Finalize assembly with pre-decrypted data.
    /// Call this after decrypting the raw assembled data externally.
    /// The decrypted_data should be the result of decrypting `get_raw_assembled_data()`.
    pub fn finalize_assembly(&mut self, decrypted_data: Vec<u8>) -> Result<Vec<u8>, RnsError> {
        if !self.is_complete() {
            return Err(RnsError::InvalidArgument);
        }

        self.set_status(ResourceStatus::Assembling);

        // Strip off random hash (which was prepended to the data before encryption)
        if decrypted_data.len() < RANDOM_HASH_SIZE {
            self.set_status(ResourceStatus::Corrupt);
            return Err(RnsError::InvalidArgument);
        }
        let data = &decrypted_data[RANDOM_HASH_SIZE..];

        // Decompress if needed
        let final_data = if self.flags.compressed {
            decompress_bz2(data)?
        } else {
            data.to_vec()
        };

        // Verify hash: Hash(uncompressed_data + random_hash)
        let calculated_hash = Hash::new(
            Hash::generator()
                .chain_update(&final_data)
                .chain_update(&self.random_hash)
                .finalize()
                .into(),
        );

        if calculated_hash.as_bytes() != &self.hash {
            log::error!(
                "Resource hash mismatch: expected {}, calculated {}",
                hex::encode(&self.hash),
                hex::encode(calculated_hash.as_bytes())
            );
            self.set_status(ResourceStatus::Corrupt);
            return Err(RnsError::IncorrectHash);
        }

        self.set_status(ResourceStatus::Complete);

        // Trigger completion callback
        if let Some(ref callback) = self.completion_callback {
            callback(self, true);
        }

        Ok(final_data)
    }

    /// Cancel the resource transfer
    pub fn cancel(&mut self) {
        if self.status() < ResourceStatus::Complete {
            self.set_status(ResourceStatus::Failed);

            if let Some(ref callback) = self.completion_callback {
                callback(self, false);
            }
        }
    }

    /// Update RTT measurement
    pub fn update_rtt(&mut self, rtt: Duration) {
        if let Some(current_rtt) = self.rtt {
            // Smooth RTT updates
            if rtt < current_rtt {
                let adjustment = current_rtt.as_secs_f64() * 0.05;
                self.rtt = Some(Duration::from_secs_f64(
                    (current_rtt.as_secs_f64() - adjustment).max(rtt.as_secs_f64()),
                ));
            } else {
                let adjustment = current_rtt.as_secs_f64() * 0.05;
                self.rtt = Some(Duration::from_secs_f64(
                    (current_rtt.as_secs_f64() + adjustment).min(rtt.as_secs_f64()),
                ));
            }
        } else {
            self.rtt = Some(rtt);
        }
    }

    /// Update expected in-flight rate
    pub fn update_eifr(&mut self, link_rtt: Duration, link_establishment_cost: usize) {
        let rtt = self.rtt.unwrap_or(link_rtt);

        if self.req_data_rtt_rate != 0.0 {
            self.eifr = Some(self.req_data_rtt_rate * 8.0);
        } else if let Some(prev_eifr) = self.eifr {
            // Keep previous
            self.eifr = Some(prev_eifr);
        } else {
            // Estimate from link establishment
            self.eifr = Some(
                (link_establishment_cost as f64 * 8.0) / rtt.as_secs_f64(),
            );
        }
    }

    /// Adjust window based on transfer rate
    pub fn adjust_window(&mut self) {
        // Check for fast rate
        if self.req_resp_rtt_rate > RATE_FAST && self.fast_rate_rounds < FAST_RATE_THRESHOLD {
            self.fast_rate_rounds += 1;
            if self.fast_rate_rounds == FAST_RATE_THRESHOLD {
                self.window_max = WINDOW_MAX_FAST;
            }
        }

        // Check for very slow rate
        if self.fast_rate_rounds == 0
            && self.req_data_rtt_rate < RATE_VERY_SLOW
            && self.very_slow_rate_rounds < VERY_SLOW_RATE_THRESHOLD
        {
            self.very_slow_rate_rounds += 1;
            if self.very_slow_rate_rounds == VERY_SLOW_RATE_THRESHOLD {
                self.window_max = WINDOW_MAX_VERY_SLOW;
            }
        }

        // Increase window if all outstanding parts received
        if self.outstanding_parts == 0 && self.window < self.window_max {
            self.window += 1;
            if (self.window - self.window_min) > (self.window_flexibility - 1) {
                self.window_min += 1;
            }
        }
    }

    /// Get the current window size
    pub fn window(&self) -> usize {
        self.window
    }

    /// Decrease window on timeout
    pub fn decrease_window(&mut self) {
        if self.window > self.window_min {
            self.window -= 1;
            if self.window_max > self.window_min {
                self.window_max -= 1;
                if (self.window_max - self.window) > (self.window_flexibility - 1) {
                    self.window_max -= 1;
                }
            }
        }
    }

    /// Generate a request for the next batch of parts (for incoming resources).
    /// Returns the request data bytes to be sent in a RESOURCE_REQ packet.
    /// Format: [hashmap_exhausted_flag] [last_map_hash if exhausted] [resource_hash:16] [part_hashes...]
    pub fn request_next(&mut self) -> Option<Vec<u8>> {
        if self.status() == ResourceStatus::Failed || self.status() == ResourceStatus::Complete {
            return None;
        }

        if self.waiting_for_hmu {
            return None;
        }

        self.outstanding_parts = 0;
        let mut hashmap_exhausted = HASHMAP_IS_NOT_EXHAUSTED;
        let mut requested_hashes: Vec<u8> = Vec::new();

        let search_start = (self.consecutive_completed_height + 1) as usize;
        let search_size = self.window;
        let mut i = 0;
        let mut pn = search_start;

        // Iterate through parts we need
        for idx in search_start..(search_start + search_size).min(self.total_parts) {
            // Check if we already have this part
            if self.received_parts.get(idx).map(|p| p.is_none()).unwrap_or(true) {
                // Get the hash for this part from the hashmap
                let hash_start = pn * MAPHASH_LEN;
                let hash_end = hash_start + MAPHASH_LEN;

                if hash_end <= self.hashmap.len() && hash_end <= self.hashmap_height * MAPHASH_LEN {
                    // We have the hash, request this part
                    requested_hashes.extend_from_slice(&self.hashmap[hash_start..hash_end]);
                    self.outstanding_parts += 1;
                    i += 1;
                } else {
                    // Need more hashmap entries
                    hashmap_exhausted = HASHMAP_IS_EXHAUSTED;
                }
            }
            pn += 1;

            if i >= self.window || hashmap_exhausted == HASHMAP_IS_EXHAUSTED {
                break;
            }
        }

        // Build the request data
        let mut request_data = Vec::new();
        request_data.push(hashmap_exhausted);

        if hashmap_exhausted == HASHMAP_IS_EXHAUSTED {
            // Add the last map hash we have
            if self.hashmap_height > 0 {
                let last_hash_start = (self.hashmap_height - 1) * MAPHASH_LEN;
                let last_hash_end = last_hash_start + MAPHASH_LEN;
                if last_hash_end <= self.hashmap.len() {
                    request_data.extend_from_slice(&self.hashmap[last_hash_start..last_hash_end]);
                } else {
                    // No hashmap yet, send zeros
                    request_data.extend_from_slice(&[0u8; MAPHASH_LEN]);
                }
            } else {
                request_data.extend_from_slice(&[0u8; MAPHASH_LEN]);
            }
            self.waiting_for_hmu = true;
        }

        // Add resource hash (full 32 bytes, as Python expects)
        request_data.extend_from_slice(&self.hash);

        // Add requested part hashes
        request_data.extend_from_slice(&requested_hashes);

        if !requested_hashes.is_empty() || hashmap_exhausted == HASHMAP_IS_EXHAUSTED {
            self.set_status(ResourceStatus::Transferring);
            Some(request_data)
        } else {
            None
        }
    }

    /// Handle an incoming resource request (for outgoing resources).
    /// Returns a list of part indices that should be sent.
    pub fn handle_request(&mut self, request_data: &[u8]) -> Result<(bool, Vec<usize>), RnsError> {
        if request_data.is_empty() {
            return Err(RnsError::InvalidArgument);
        }

        let wants_more_hashmap = request_data[0] == HASHMAP_IS_EXHAUSTED;
        let pad = if wants_more_hashmap {
            1 + MAPHASH_LEN
        } else {
            1
        };

        // Skip past the header and resource hash (full 32 bytes)
        let hash_size = 32; // Full hash size as Python expects
        if request_data.len() < pad + hash_size {
            return Err(RnsError::InvalidArgument);
        }

        let requested_hashes = &request_data[pad + hash_size..];

        // Define search scope based on receiver's state
        let search_start = self.receiver_min_consecutive_height;
        let search_end = search_start + ResourceAdvertisement::COLLISION_GUARD_SIZE;

        let mut parts_to_send = Vec::new();

        // Parse requested hashes and find matching parts
        for i in 0..(requested_hashes.len() / MAPHASH_LEN) {
            let hash_start = i * MAPHASH_LEN;
            let hash_end = hash_start + MAPHASH_LEN;
            let requested_hash = &requested_hashes[hash_start..hash_end];

            // Search for this hash in our parts
            for idx in search_start..search_end.min(self.parts.len()) {
                if &self.parts[idx].map_hash == requested_hash {
                    parts_to_send.push(idx);
                    break;
                }
            }
        }

        // Update status
        if self.status() != ResourceStatus::Transferring {
            self.set_status(ResourceStatus::Transferring);
        }
        self.retries_left = MAX_RETRIES;

        Ok((wants_more_hashmap, parts_to_send))
    }

    /// Get hashmap data for a hashmap update packet.
    /// Returns data to send in RESOURCE_HMU packet.
    pub fn get_hashmap_update(&self, segment: usize) -> Vec<u8> {
        let seg_len = ResourceAdvertisement::HASHMAP_MAX_LEN;
        let hashmap_start = segment * seg_len * MAPHASH_LEN;
        let hashmap_end = ((segment + 1) * seg_len * MAPHASH_LEN).min(self.hashmap.len());

        let mut update_data = Vec::new();
        // Add resource hash (truncated)
        update_data.extend_from_slice(&self.truncated_hash);
        // Add hashmap segment
        if hashmap_start < self.hashmap.len() {
            update_data.extend_from_slice(&self.hashmap[hashmap_start..hashmap_end]);
        }
        update_data
    }

    /// Generate proof data for a completed resource.
    /// Returns data to send in RESOURCE_PRF packet.
    pub fn generate_proof(&self) -> Vec<u8> {
        let mut proof_data = Vec::new();
        // Add resource hash (truncated)
        proof_data.extend_from_slice(&self.truncated_hash);
        // Add the expected proof hash
        let proof_hash = Hash::new(
            Hash::generator()
                .chain_update(&self.hash)
                .chain_update(&self.random_hash)
                .finalize()
                .into(),
        );
        proof_data.extend_from_slice(proof_hash.as_bytes());
        proof_data
    }

    /// Verify a proof from the receiver.
    pub fn verify_proof(&self, proof_data: &[u8]) -> bool {
        if proof_data.len() < 16 + 32 {
            return false;
        }

        // Verify the resource hash matches
        if &proof_data[..16] != &self.truncated_hash {
            return false;
        }

        // Calculate expected proof
        let expected_proof = Hash::new(
            Hash::generator()
                .chain_update(&self.hash)
                .chain_update(&self.random_hash)
                .finalize()
                .into(),
        );

        &proof_data[16..48] == expected_proof.as_bytes()
    }

    /// Get part data for sending (for outgoing resources).
    pub fn get_part_data(&self, index: usize) -> Option<&[u8]> {
        self.parts.get(index).map(|p| p.data.as_slice())
    }
}

impl std::fmt::Debug for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resource")
            .field("status", &self.status())
            .field("hash", &hex::encode(&self.hash[..8]))
            .field("size", &self.size)
            .field("total_parts", &self.total_parts)
            .field("initiator", &self.initiator)
            .finish()
    }
}

/// Helper module for hex encoding (used in Debug)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Resource advertisement for announcing a resource
#[derive(Debug, Clone)]
pub struct ResourceAdvertisement {
    /// Transfer size (after compression/encryption)
    pub transfer_size: usize,
    /// Total uncompressed data size
    pub data_size: usize,
    /// Number of parts
    pub num_parts: usize,
    /// Resource hash
    pub hash: [u8; 32],
    /// Random hash
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    /// Original hash (for multi-segment)
    pub original_hash: [u8; 32],
    /// Segment index (1-based)
    pub segment_index: usize,
    /// Total segments
    pub total_segments: usize,
    /// Request ID (for request/response pattern)
    pub request_id: Option<[u8; 16]>,
    /// Resource flags
    pub flags: ResourceFlags,
    /// Hashmap (first segment only)
    pub hashmap: Vec<u8>,
}

impl ResourceAdvertisement {
    /// Overhead in bytes for advertisement packet
    pub const OVERHEAD: usize = 134;

    /// Maximum hashmap entries that fit in an advertisement
    pub const HASHMAP_MAX_LEN: usize = (464 - Self::OVERHEAD) / MAPHASH_LEN; // Approximate MDU - overhead

    /// Collision guard size for hashmap
    pub const COLLISION_GUARD_SIZE: usize = 2 * WINDOW_MAX + Self::HASHMAP_MAX_LEN;

    /// Pack the advertisement into bytes using MessagePack map format
    pub fn pack(&self, segment: usize) -> Result<Vec<u8>, RnsError> {
        use std::collections::BTreeMap;

        // Calculate hashmap slice for this segment
        let hashmap_start = segment * Self::HASHMAP_MAX_LEN * MAPHASH_LEN;
        let hashmap_end =
            ((segment + 1) * Self::HASHMAP_MAX_LEN * MAPHASH_LEN).min(self.hashmap.len());

        let hashmap_slice = if hashmap_start < self.hashmap.len() {
            self.hashmap[hashmap_start..hashmap_end].to_vec()
        } else {
            vec![]
        };

        // Build a map that matches Python's dictionary structure
        let mut map: BTreeMap<String, rmpv::Value> = BTreeMap::new();
        map.insert("t".to_string(), rmpv::Value::from(self.transfer_size as u64));
        map.insert("d".to_string(), rmpv::Value::from(self.data_size as u64));
        map.insert("n".to_string(), rmpv::Value::from(self.num_parts as u64));
        map.insert("h".to_string(), rmpv::Value::Binary(self.hash.to_vec()));
        map.insert("r".to_string(), rmpv::Value::Binary(self.random_hash.to_vec()));
        map.insert("o".to_string(), rmpv::Value::Binary(self.original_hash.to_vec()));
        map.insert("i".to_string(), rmpv::Value::from(self.segment_index as u64));
        map.insert("l".to_string(), rmpv::Value::from(self.total_segments as u64));

        // Handle optional request_id
        if let Some(ref req_id) = self.request_id {
            map.insert("q".to_string(), rmpv::Value::Binary(req_id.to_vec()));
        } else {
            map.insert("q".to_string(), rmpv::Value::Nil);
        }

        map.insert("f".to_string(), rmpv::Value::from(self.flags.to_byte() as u64));
        map.insert("m".to_string(), rmpv::Value::Binary(hashmap_slice));

        // Serialize as map
        let value = rmpv::Value::Map(
            map.into_iter()
                .map(|(k, v)| (rmpv::Value::String(k.into()), v))
                .collect()
        );

        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &value)
            .map_err(|_| RnsError::InvalidArgument)?;

        Ok(buf)
    }

    /// Unpack an advertisement from bytes
    pub fn unpack(data: &[u8]) -> Result<Self, RnsError> {
        let value = rmpv::decode::read_value(&mut &data[..])
            .map_err(|_| RnsError::InvalidArgument)?;

        let map = match value {
            rmpv::Value::Map(m) => m,
            _ => return Err(RnsError::InvalidArgument),
        };

        // Helper to extract values from the map
        let get_value = |key: &str| -> Option<&rmpv::Value> {
            map.iter()
                .find(|(k, _)| {
                    match k {
                        rmpv::Value::String(s) => s.as_str() == Some(key),
                        _ => false,
                    }
                })
                .map(|(_, v)| v)
        };

        let get_u64 = |key: &str| -> Result<u64, RnsError> {
            get_value(key)
                .and_then(|v| v.as_u64())
                .ok_or(RnsError::InvalidArgument)
        };

        let get_bytes = |key: &str| -> Result<Vec<u8>, RnsError> {
            get_value(key)
                .and_then(|v| match v {
                    rmpv::Value::Binary(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or(RnsError::InvalidArgument)
        };

        let transfer_size = get_u64("t")? as usize;
        let data_size = get_u64("d")? as usize;
        let num_parts = get_u64("n")? as usize;

        let hash: [u8; 32] = get_bytes("h")?
            .try_into()
            .map_err(|_| RnsError::InvalidArgument)?;

        let random_hash: [u8; RANDOM_HASH_SIZE] = get_bytes("r")?
            .try_into()
            .map_err(|_| RnsError::InvalidArgument)?;

        let original_hash: [u8; 32] = get_bytes("o")?
            .try_into()
            .map_err(|_| RnsError::InvalidArgument)?;

        let segment_index = get_u64("i")? as usize;
        let total_segments = get_u64("l")? as usize;

        let request_id = get_value("q")
            .and_then(|v| match v {
                rmpv::Value::Binary(b) if b.len() == 16 => {
                    let arr: [u8; 16] = b.clone().try_into().ok()?;
                    Some(arr)
                }
                rmpv::Value::Nil => None,
                _ => None,
            });

        let flags = ResourceFlags::from_byte(get_u64("f")? as u8);
        let hashmap = get_bytes("m")?;

        Ok(Self {
            transfer_size,
            data_size,
            num_parts,
            hash,
            random_hash,
            original_hash,
            segment_index,
            total_segments,
            request_id,
            flags,
            hashmap,
        })
    }

    /// Check if this is a request advertisement
    pub fn is_request(&self) -> bool {
        self.request_id.is_some() && self.flags.is_request
    }

    /// Check if this is a response advertisement
    pub fn is_response(&self) -> bool {
        self.request_id.is_some() && self.flags.is_response
    }
}

/// Compress data using bz2 compression (compatible with Python bz2 module)
fn compress_bz2(data: &[u8]) -> Result<Vec<u8>, RnsError> {
    use bzip2::write::BzEncoder;
    use bzip2::Compression;
    use std::io::Write;

    let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| {
            log::error!("bz2 compression failed: {:?}", e);
            RnsError::InvalidArgument
        })?;
    encoder.finish().map_err(|e| {
        log::error!("bz2 compression finalize failed: {:?}", e);
        RnsError::InvalidArgument
    })
}

/// Decompress bz2-compressed data
fn decompress_bz2(data: &[u8]) -> Result<Vec<u8>, RnsError> {
    use bzip2::read::BzDecoder;
    use std::io::Read;

    let mut decoder = BzDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| {
            log::error!("bz2 decompression failed: {:?}", e);
            RnsError::InvalidArgument
        })?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_resource_flags() {
        let flags = ResourceFlags {
            encrypted: true,
            compressed: true,
            split: false,
            is_request: true,
            is_response: false,
            has_metadata: true,
        };

        let byte = flags.to_byte();
        let restored = ResourceFlags::from_byte(byte);

        assert_eq!(flags.encrypted, restored.encrypted);
        assert_eq!(flags.compressed, restored.compressed);
        assert_eq!(flags.split, restored.split);
        assert_eq!(flags.is_request, restored.is_request);
        assert_eq!(flags.is_response, restored.is_response);
        assert_eq!(flags.has_metadata, restored.has_metadata);
    }

    #[test]
    fn test_resource_status_conversion() {
        assert_eq!(ResourceStatus::from(0x00), ResourceStatus::None);
        assert_eq!(ResourceStatus::from(0x03), ResourceStatus::Transferring);
        assert_eq!(ResourceStatus::from(0x06), ResourceStatus::Complete);
        assert_eq!(ResourceStatus::from(0xFF), ResourceStatus::None);
    }

    #[test]
    fn test_resource_creation() {
        let mut rng = OsRng;
        let data = b"Hello, Resource Transfer!";

        let resource =
            Resource::new(&mut rng, data, ResourceConfig::default(), None).expect("create resource");

        // Total size is the uncompressed data length (not including random hash)
        assert_eq!(resource.total_size(), data.len());
        assert!(resource.total_parts() > 0);
        assert!(resource.is_initiator());
    }

    #[test]
    fn test_resource_with_metadata() {
        let mut rng = OsRng;
        let data = b"Data with metadata";
        let metadata = b"filename.txt";

        let resource =
            Resource::new(&mut rng, data, ResourceConfig::default(), Some(metadata))
                .expect("create resource");

        assert!(resource.flags.has_metadata);
    }

    #[test]
    fn test_resource_advertisement_pack_unpack() {
        let adv = ResourceAdvertisement {
            transfer_size: 1024,
            data_size: 2048,
            num_parts: 5,
            hash: [1u8; 32],
            random_hash: [2u8; RANDOM_HASH_SIZE],
            original_hash: [3u8; 32],
            segment_index: 1,
            total_segments: 1,
            request_id: None,
            flags: ResourceFlags::default(),
            hashmap: vec![0u8; 20],
        };

        let packed = adv.pack(0).expect("pack advertisement");
        let unpacked = ResourceAdvertisement::unpack(&packed).expect("unpack advertisement");

        assert_eq!(adv.transfer_size, unpacked.transfer_size);
        assert_eq!(adv.data_size, unpacked.data_size);
        assert_eq!(adv.num_parts, unpacked.num_parts);
        assert_eq!(adv.hash, unpacked.hash);
        assert_eq!(adv.segment_index, unpacked.segment_index);
    }

    #[test]
    fn test_compression() {
        let data = b"This is some test data that should compress well. ".repeat(100);
        let compressed = compress_bz2(&data).expect("compress");
        let decompressed = decompress_bz2(&compressed).expect("decompress");
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

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
}
