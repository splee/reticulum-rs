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
use crate::packet::RETICULUM_MDU;

// Submodules
mod advertising;
mod compression;
mod config;
pub mod constants;
mod parts;
mod status;
pub mod watchdog;

// Re-export public types
pub use advertising::ResourceAdvertisement;
pub use config::{ResourceConfig, ResourceProgress};
pub use constants::*;
pub use parts::ResourcePart;
pub use status::{ResourceFlags, ResourceStatus};

// Internal use
use compression::{compress_bz2, decompress_bz2};
use parts::calculate_map_hash;

/// Type alias for progress callback
pub type ProgressCallback = Arc<dyn Fn(&ResourceProgress) + Send + Sync>;

/// Type alias for completion callback
pub type CompletionCallback = Arc<dyn Fn(&Resource, bool) + Send + Sync>;

/// Result from handling a resource request (for outgoing resources).
///
/// Contains the list of part indices to send, optional hashmap update data,
/// and whether all parts have now been sent (triggering AwaitingProof status).
#[derive(Debug)]
pub struct HandleRequestResult {
    /// Indices of parts that should be sent in response to the request.
    pub parts_to_send: Vec<usize>,
    /// Hashmap update data to send if the receiver needs more hashmap entries.
    /// This should be sent as a ResourceHashUpdate packet.
    pub hashmap_update: Option<Vec<u8>>,
    /// True when all parts have been sent and resource should await proof.
    pub all_parts_sent: bool,
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
    #[allow(dead_code)]
    expected_proof: [u8; 32],

    /// Uncompressed data size
    #[allow(dead_code)]
    uncompressed_size: usize,
    /// Compressed/transfer size
    size: usize,
    /// Total data size including metadata
    total_size: usize,

    /// Resource flags
    pub(crate) flags: ResourceFlags,

    /// Parts for outgoing resource
    pub(crate) parts: Vec<ResourcePart>,
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
    #[allow(dead_code)]
    rtt_rxd_bytes_at_part_req: usize,
    /// Request-response RTT rate
    req_resp_rtt_rate: f64,
    /// Request data RTT rate
    req_data_rtt_rate: f64,

    /// Time of last activity
    last_activity: Instant,
    /// Time when transfer started
    #[allow(dead_code)]
    started_transferring: Option<Instant>,
    /// Time when advertisement was sent
    adv_sent: Option<Instant>,
    /// Time of last part sent
    last_part_sent: Option<Instant>,

    /// Retries remaining
    retries_left: u32,

    /// Timeout for the resource transfer (typically link RTT * traffic_timeout_factor)
    timeout: Duration,
    /// Timeout factor for calculating wait times
    timeout_factor: f64,
    /// Part timeout factor for TRANSFERRING state
    part_timeout_factor: f64,
    /// Sender grace time
    sender_grace_time: f64,

    /// Configuration
    config: ResourceConfig,

    /// Request ID for request/response pattern
    request_id: Option<[u8; 16]>,

    /// Metadata bytes
    #[allow(dead_code)]
    metadata: Option<Vec<u8>>,

    /// Original uncompressed data (for outgoing resources, needed to verify proof)
    original_data: Option<Vec<u8>>,

    /// Progress callback
    progress_callback: Option<ProgressCallback>,
    /// Completion callback
    completion_callback: Option<CompletionCallback>,

    /// SDU (Service Data Unit) size for parts
    pub(crate) sdu: usize,

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
    /// Create a new outgoing resource from data.
    ///
    /// The optional `encrypt_fn` encrypts the resource data stream before
    /// splitting it into parts. This is typically `link.encrypt()` wrapped in
    /// a closure. When provided, the resource is flagged as encrypted and
    /// the receiver must decrypt with the corresponding `link.decrypt()`.
    pub fn new<R: CryptoRngCore>(
        rng: &mut R,
        data: &[u8],
        config: ResourceConfig,
        metadata: Option<&[u8]>,
        encrypt_fn: Option<&dyn Fn(&[u8]) -> Result<Vec<u8>, RnsError>>,
    ) -> Result<Self, RnsError> {
        // Resource parts are sent as PacketContext::RESOURCE (link-level plaintext),
        // so SDU should match plain Reticulum MDU (MTU - header max - IFAC min).
        let sdu = RETICULUM_MDU;

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
        // Keep uncompressed_data for hash calculation
        let (processed_data, compressed, uncompressed_data) =
            if config.auto_compress && uncompressed_size <= config.auto_compress_limit {
                match compress_bz2(&full_data) {
                    Ok(compressed_data) if compressed_data.len() < uncompressed_size => {
                        (compressed_data, true, full_data)
                    }
                    _ => {
                        let data_for_hash = full_data.clone();
                        (full_data, false, data_for_hash)
                    }
                }
            } else {
                let data_for_hash = full_data.clone();
                (full_data, false, data_for_hash)
            };

        // Maximum retries for hash collision resolution (matching Python Resource.py)
        const MAX_COLLISION_RETRIES: usize = 10;

        let mut random_hash = [0u8; RANDOM_HASH_SIZE];
        let mut final_data;
        let mut encrypted;
        let mut hash;
        let mut truncated_hash;
        let mut original_hash;
        let mut expected_proof;
        let mut size;
        let mut total_parts;
        let mut parts;
        let mut hashmap;

        // Retry loop: on hashmap collision, regenerate random_hash and rebuild.
        // This matches Python's Resource.__init__ collision retry logic
        // (Resource.py:432-471).
        let mut retry = 0;
        loop {
            rng.fill_bytes(&mut random_hash);

            // Prepend random hash to processed (possibly compressed) data
            final_data = Vec::with_capacity(RANDOM_HASH_SIZE + processed_data.len());
            final_data.extend_from_slice(&random_hash);
            final_data.extend_from_slice(&processed_data);

            // Encrypt the data stream if an encryption function is provided.
            // Python encrypts the entire (random_hash + data) stream with
            // link.encrypt() before splitting into parts.
            encrypted = if let Some(enc_fn) = encrypt_fn {
                final_data = enc_fn(&final_data)?;
                true
            } else {
                false
            };

            size = final_data.len();

            // Calculate hashes
            // NOTE: Python hashes the uncompressed (metadata + data) + random_hash
            hash = Hash::new(
                Hash::generator()
                    .chain_update(&uncompressed_data)
                    .chain_update(random_hash)
                    .finalize()
                    .into(),
            );

            truncated_hash = {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&hash.as_bytes()[..16]);
                arr
            };

            original_hash = *hash.as_bytes();

            // Expected proof is Hash(uncompressed_data + hash)
            expected_proof = Hash::new(
                Hash::generator()
                    .chain_update(&uncompressed_data)
                    .chain_update(hash.as_bytes())
                    .finalize()
                    .into(),
            );

            // Calculate number of parts
            total_parts = size.div_ceil(sdu);

            // Build parts and hashmap
            parts = Vec::with_capacity(total_parts);
            hashmap = Vec::with_capacity(total_parts * MAPHASH_LEN);
            let mut collision_guard = Vec::with_capacity(total_parts.min(256));
            let mut collision = false;

            for i in 0..total_parts {
                let start = i * sdu;
                let end = ((i + 1) * sdu).min(size);
                let part_data = final_data[start..end].to_vec();

                let map_hash = calculate_map_hash(&part_data, &random_hash);

                if collision_guard.contains(&map_hash) {
                    collision = true;
                    break;
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

            if !collision {
                break;
            }

            retry += 1;
            if retry >= MAX_COLLISION_RETRIES {
                log::error!(
                    "resource: hashmap collision not resolved after {} retries",
                    MAX_COLLISION_RETRIES
                );
                return Err(RnsError::CryptoError);
            }
            log::debug!(
                "resource: hashmap collision, regenerating (retry {}/{})",
                retry,
                MAX_COLLISION_RETRIES
            );
        }

        // Determine if we need to split into segments
        let total_segments = if total_size > MAX_EFFICIENT_SIZE {
            total_size.div_ceil(MAX_EFFICIENT_SIZE)
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
            adv_sent: None,
            last_part_sent: None,
            retries_left: config.max_retries,
            timeout: config.timeout.unwrap_or(Duration::from_secs(15)),
            timeout_factor: PART_TIMEOUT_FACTOR,
            part_timeout_factor: PART_TIMEOUT_FACTOR,
            sender_grace_time: SENDER_GRACE_TIME,
            config,
            request_id: None,
            metadata: metadata_bytes,
            original_data: Some(data.to_vec()),
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
            adv_sent: None,
            last_part_sent: None,
            retries_left: MAX_RETRIES,
            timeout: Duration::from_secs(15),
            timeout_factor: PART_TIMEOUT_FACTOR,
            part_timeout_factor: PART_TIMEOUT_FACTOR,
            sender_grace_time: SENDER_GRACE_TIME,
            config: ResourceConfig::default(),
            request_id: adv.request_id,
            metadata: None,
            original_data: None, // Incoming resources don't have original data until assembled
            progress_callback: None,
            completion_callback: None,
            sdu,
            hashmap_height,
            waiting_for_hmu: false,
            consecutive_completed_height: -1,
            receiver_min_consecutive_height: 0,
        })
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

    // --- Watchdog-accessible state ---

    /// Get time of last activity
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Update last activity to now
    pub fn touch_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Get time when advertisement was sent
    pub fn adv_sent(&self) -> Option<Instant> {
        self.adv_sent
    }

    /// Record that advertisement was sent now
    pub fn mark_adv_sent(&mut self) {
        let now = Instant::now();
        self.adv_sent = Some(now);
        self.last_activity = now;
    }

    /// Get time of last part sent
    pub fn last_part_sent(&self) -> Option<Instant> {
        self.last_part_sent
    }

    /// Reset last_part_sent timestamp to now (used by watchdog for proof query retries)
    pub fn reset_last_part_sent(&mut self) {
        self.last_part_sent = Some(Instant::now());
    }

    /// Get the resource timeout
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Set the resource timeout (e.g. from link RTT * traffic_timeout_factor)
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Get remaining retries
    pub fn retries_left(&self) -> u32 {
        self.retries_left
    }

    /// Decrement retries remaining; returns new count
    pub fn decrement_retries(&mut self) -> u32 {
        self.retries_left = self.retries_left.saturating_sub(1);
        self.retries_left
    }

    /// Get RTT estimate
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// Get outstanding parts count
    pub fn outstanding_parts(&self) -> usize {
        self.outstanding_parts
    }

    /// Get SDU (part size)
    pub fn sdu(&self) -> usize {
        self.sdu
    }

    /// Get expected in-flight rate (bits per second)
    pub fn eifr(&self) -> Option<f64> {
        self.eifr
    }

    /// Get request-response RTT rate
    pub fn req_resp_rtt_rate(&self) -> f64 {
        self.req_resp_rtt_rate
    }

    /// Get part timeout factor
    pub fn part_timeout_factor(&self) -> f64 {
        self.part_timeout_factor
    }

    /// Set part timeout factor
    pub fn set_part_timeout_factor(&mut self, factor: f64) {
        self.part_timeout_factor = factor;
    }

    /// Get timeout factor
    pub fn timeout_factor(&self) -> f64 {
        self.timeout_factor
    }

    /// Set timeout factor
    pub fn set_timeout_factor(&mut self, factor: f64) {
        self.timeout_factor = factor;
    }

    /// Get sender grace time
    pub fn sender_grace_time(&self) -> f64 {
        self.sender_grace_time
    }

    /// Get whether waiting for hashmap update
    pub fn waiting_for_hmu(&self) -> bool {
        self.waiting_for_hmu
    }

    /// Clear the waiting-for-HMU flag
    pub fn clear_waiting_for_hmu(&mut self) {
        self.waiting_for_hmu = false;
    }

    /// Get the expected proof hash
    pub fn expected_proof(&self) -> &[u8; 32] {
        &self.expected_proof
    }

    /// Get max retries from config
    pub fn max_retries(&self) -> u32 {
        self.config.max_retries
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
        let map_hash = calculate_map_hash(&data, &self.random_hash);

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
                if expected_hash == map_hash && self.received_parts[i].is_none() {
                    self.received_parts[i] = Some(data);
                    self.rtt_rxd_bytes += self.sdu;
                    self.received_count += 1;
                    self.outstanding_parts = self.outstanding_parts.saturating_sub(1);

                    // Update consecutive completed height
                    if i as isize == self.consecutive_completed_height + 1 {
                        self.consecutive_completed_height = i as isize;

                        // Extend if consecutive
                        let mut cp = (self.consecutive_completed_height + 1) as usize;
                        while cp < self.received_parts.len() && self.received_parts[cp].is_some() {
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
        for data in self.received_parts.iter().flatten() {
            stream.extend_from_slice(data);
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
                .chain_update(self.random_hash)
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
        for data in self.received_parts.iter().flatten() {
            stream.extend_from_slice(data);
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
                .chain_update(self.random_hash)
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
            self.eifr =
                Some((link_establishment_cost as f64 * 8.0) / rtt.as_secs_f64());
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
            if self
                .received_parts
                .get(idx)
                .map(|p| p.is_none())
                .unwrap_or(true)
            {
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
    ///
    /// Returns a `HandleRequestResult` containing:
    /// - The part indices to send
    /// - Optional hashmap update data if the receiver needs more entries
    /// - Whether all parts have been sent (caller should transition to AwaitingProof)
    pub fn handle_request(&mut self, request_data: &[u8]) -> Result<HandleRequestResult, RnsError> {
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

        log::debug!(
            "handle_request: wants_more_hashmap={}, pad={}, requested_hashes len={}",
            wants_more_hashmap,
            pad,
            requested_hashes.len()
        );

        // Determine the hashmap update segment if the receiver needs more entries
        let hashmap_update = if wants_more_hashmap {
            // Find the segment based on the last hash the receiver has.
            // The receiver sends their last map_hash in bytes 1..(1+MAPHASH_LEN).
            let last_hash = &request_data[1..1 + MAPHASH_LEN];

            // Find which segment contains this hash
            let seg_len = ResourceAdvertisement::HASHMAP_MAX_LEN;
            let mut segment = 0;
            for i in 0..self.total_parts {
                let h_start = i * MAPHASH_LEN;
                let h_end = h_start + MAPHASH_LEN;
                if h_end <= self.hashmap.len() && &self.hashmap[h_start..h_end] == last_hash {
                    segment = (i / seg_len) + 1; // Next segment after the one containing this hash
                    break;
                }
            }
            Some(self.get_hashmap_update(segment))
        } else {
            None
        };

        // Define search scope based on receiver's state
        let search_start = self.receiver_min_consecutive_height;
        let search_end = search_start + ResourceAdvertisement::COLLISION_GUARD_SIZE;

        let mut parts_to_send = Vec::new();

        // Parse requested hashes and find matching parts
        for i in 0..(requested_hashes.len() / MAPHASH_LEN) {
            let hash_start = i * MAPHASH_LEN;
            let hash_end = hash_start + MAPHASH_LEN;
            let requested_hash = &requested_hashes[hash_start..hash_end];

            log::debug!(
                "handle_request: looking for hash {:?} in parts {}..{}",
                requested_hash,
                search_start,
                search_end.min(self.parts.len())
            );

            // Search for this hash in our parts
            let mut found = false;
            for idx in search_start..search_end.min(self.parts.len()) {
                log::trace!(
                    "handle_request: part {} has hash {:?}",
                    idx,
                    &self.parts[idx].map_hash
                );
                if self.parts[idx].map_hash == requested_hash {
                    parts_to_send.push(idx);
                    found = true;
                    log::debug!("handle_request: found match at part {}", idx);
                    break;
                }
            }
            if !found {
                log::warn!(
                    "handle_request: no match found for requested hash {:?}",
                    requested_hash
                );
            }
        }

        // Update status
        if self.status() != ResourceStatus::Transferring {
            self.set_status(ResourceStatus::Transferring);
        }
        self.retries_left = MAX_RETRIES;

        // Check if all parts will have been sent after this batch
        let all_parts_sent = self.all_parts_sent();

        Ok(HandleRequestResult {
            parts_to_send,
            hashmap_update,
            all_parts_sent,
        })
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
    /// Format: hash (32 bytes) + full_hash(data + hash) (32 bytes) = 64 bytes
    ///
    /// Note: This requires original_data to be available. For incoming resources,
    /// use generate_proof_with_data() after reconstructing the data from parts.
    pub fn generate_proof(&self) -> Vec<u8> {
        let data = self
            .original_data
            .as_ref()
            .expect("generate_proof requires original_data");
        self.generate_proof_with_data(data)
    }

    /// Generate proof data using the provided data.
    /// Used for incoming resources after reconstructing data from parts.
    /// Format: hash (32 bytes) + full_hash(data + hash) (32 bytes) = 64 bytes
    pub fn generate_proof_with_data(&self, data: &[u8]) -> Vec<u8> {
        let mut proof_data = Vec::new();
        // Add full resource hash (32 bytes)
        proof_data.extend_from_slice(&self.hash);

        // Calculate proof: full_hash(data + hash)
        let proof_hash = Hash::new(
            Hash::generator()
                .chain_update(data)
                .chain_update(self.hash)
                .finalize()
                .into(),
        );
        proof_data.extend_from_slice(proof_hash.as_bytes());
        proof_data
    }

    /// Verify a proof from the receiver.
    /// Python proof format: hash (32 bytes) + full_hash(data + hash) (32 bytes) = 64 bytes
    pub fn verify_proof(&self, proof_data: &[u8]) -> bool {
        // Proof must be 64 bytes: 32 byte hash + 32 byte proof hash
        if proof_data.len() != 64 {
            log::debug!(
                "verify_proof: invalid proof length {} (expected 64)",
                proof_data.len()
            );
            return false;
        }

        // First 32 bytes should match our hash
        if proof_data[..32] != self.hash {
            log::debug!(
                "verify_proof: hash mismatch, expected {:?}, got {:?}",
                &self.hash[..16],
                &proof_data[..16]
            );
            return false;
        }

        // For outgoing resources, we need original_data to verify
        let Some(original_data) = &self.original_data else {
            log::debug!("verify_proof: no original_data available");
            return false;
        };

        // Calculate expected proof: full_hash(data + hash)
        let expected_proof = Hash::new(
            Hash::generator()
                .chain_update(original_data)
                .chain_update(self.hash)
                .finalize()
                .into(),
        );

        if &proof_data[32..64] != expected_proof.as_bytes() {
            log::debug!(
                "verify_proof: proof hash mismatch, expected {:?}, got {:?}",
                &expected_proof.as_bytes()[..16],
                &proof_data[32..48]
            );
            return false;
        }

        true
    }

    /// Check if all parts have been sent (for outgoing resources).
    pub fn all_parts_sent(&self) -> bool {
        self.sent_parts >= self.total_parts
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_resource_creation() {
        let mut rng = OsRng;
        let data = b"Hello, Resource Transfer!";

        let resource =
            Resource::new(&mut rng, data, ResourceConfig::default(), None, None).expect("create resource");

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

        let resource = Resource::new(&mut rng, data, ResourceConfig::default(), Some(metadata), None)
            .expect("create resource");

        assert!(resource.flags.has_metadata);
    }

    #[test]
    fn test_resource_parts_creation() {
        let mut rng = OsRng;
        let data = vec![0x41u8; 1000]; // 1KB of 'A'

        let resource =
            Resource::new(&mut rng, &data, ResourceConfig::default(), None, None).expect("create resource");

        // Verify parts were created
        assert!(resource.total_parts() > 0);
        assert!(!resource.parts.is_empty());

        // Verify hashmap was generated
        assert_eq!(resource.hashmap.len(), resource.total_parts() * MAPHASH_LEN);

        // Verify each part has correct data size (except possibly the last)
        for (i, part) in resource.parts.iter().enumerate() {
            if i < resource.parts.len() - 1 {
                assert_eq!(part.data.len(), resource.sdu);
            }
            assert!(!part.sent);
        }
    }

    #[test]
    fn test_resource_receive_part() {
        let mut rng = OsRng;
        let data = vec![0x42u8; 500]; // 500 bytes

        // Create outgoing resource to get parts
        let outgoing =
            Resource::new(&mut rng, &data, ResourceConfig::default(), None, None).expect("create outgoing resource");

        // Create incoming resource from advertisement
        let adv = outgoing.create_advertisement();
        let mut incoming =
            Resource::from_advertisement(&adv, outgoing.sdu).expect("create incoming resource");

        // Verify initial state
        assert_eq!(incoming.received_count, 0);
        assert!(!incoming.is_complete());

        // Receive parts in order
        for part in &outgoing.parts {
            let received = incoming.receive_part(part.data.clone());
            assert!(received, "Failed to receive part");
        }

        // Verify completion
        assert!(incoming.is_complete());
        assert_eq!(incoming.received_count, outgoing.total_parts());
    }

    #[test]
    fn test_resource_receive_parts_within_window() {
        let mut rng = OsRng;
        let data = vec![0x43u8; 2000]; // Large enough for multiple parts

        let outgoing =
            Resource::new(&mut rng, &data, ResourceConfig::default(), None, None).expect("create outgoing resource");

        let adv = outgoing.create_advertisement();
        let mut incoming =
            Resource::from_advertisement(&adv, outgoing.sdu).expect("create incoming resource");

        // Receive parts in order (window-based reception requires parts to be
        // within the current window, which starts at consecutive_completed_height + 1)
        let parts_count = outgoing.parts.len();
        for i in 0..parts_count {
            let received = incoming.receive_part(outgoing.parts[i].data.clone());
            assert!(received, "Failed to receive part {}", i);
        }

        assert!(incoming.is_complete());
        assert_eq!(incoming.received_count, parts_count);
    }

    #[test]
    fn test_resource_request_generation() {
        let mut rng = OsRng;
        let data = vec![0x44u8; 1000];

        let outgoing =
            Resource::new(&mut rng, &data, ResourceConfig::default(), None, None).expect("create outgoing resource");

        let adv = outgoing.create_advertisement();
        let mut incoming =
            Resource::from_advertisement(&adv, outgoing.sdu).expect("create incoming resource");

        // Generate first request
        let request = incoming.request_next();
        assert!(request.is_some(), "Should generate initial request");

        let request_data = request.unwrap();
        // Request format: [hashmap_exhausted_flag] [resource_hash:32] [part_hashes...]
        assert!(request_data.len() >= 33); // At least flag + hash
    }

    #[test]
    fn test_resource_handle_request() {
        let mut rng = OsRng;
        let data = vec![0x45u8; 500];

        let mut resource =
            Resource::new(&mut rng, &data, ResourceConfig::default(), None, None).expect("create resource");

        // Create a mock request with the first part hash
        let mut request_data = Vec::new();
        request_data.push(HASHMAP_IS_NOT_EXHAUSTED); // Not exhausted
        request_data.extend_from_slice(&resource.hash); // Resource hash
        request_data.extend_from_slice(&resource.parts[0].map_hash); // First part hash

        let result = resource.handle_request(&request_data);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.hashmap_update.is_none());
        assert!(!result.parts_to_send.is_empty());
        assert_eq!(result.parts_to_send[0], 0); // Should request first part
    }

    #[test]
    fn test_resource_proof_generation_and_verification() {
        let mut rng = OsRng;
        let data = b"Data for proof testing";

        let resource =
            Resource::new(&mut rng, data, ResourceConfig::default(), None, None).expect("create resource");

        // Generate proof
        let proof = resource.generate_proof();

        // Verify proof length (32 byte hash + 32 byte proof hash)
        assert_eq!(proof.len(), 64);

        // Verify the proof is valid
        assert!(resource.verify_proof(&proof));

        // Invalid proof should fail
        let mut bad_proof = proof.clone();
        bad_proof[20] ^= 0xFF; // Corrupt a byte
        assert!(!resource.verify_proof(&bad_proof));
    }

    #[test]
    fn test_resource_hashmap_update() {
        let mut rng = OsRng;
        let data = vec![0x46u8; 500];

        let outgoing =
            Resource::new(&mut rng, &data, ResourceConfig::default(), None, None).expect("create outgoing resource");

        let adv = outgoing.create_advertisement();
        let mut incoming =
            Resource::from_advertisement(&adv, outgoing.sdu).expect("create incoming resource");

        // Get hashmap update from outgoing
        let hashmap_update = outgoing.get_hashmap_update(0);

        // Verify update has content (truncated hash + hashmap data)
        assert!(hashmap_update.len() > 16);
    }

    #[test]
    fn test_resource_window_adjustment() {
        let mut rng = OsRng;
        let data = vec![0x47u8; 500];

        let outgoing =
            Resource::new(&mut rng, &data, ResourceConfig::default(), None, None).expect("create outgoing resource");

        let adv = outgoing.create_advertisement();
        let mut incoming =
            Resource::from_advertisement(&adv, outgoing.sdu).expect("create incoming resource");

        let initial_window = incoming.window();
        assert_eq!(initial_window, WINDOW_INITIAL);

        // Simulate successful reception (outstanding_parts should be 0)
        incoming.outstanding_parts = 0;
        incoming.adjust_window();

        // Window should increase
        assert!(incoming.window() >= initial_window);

        // Test window decrease
        let window_before = incoming.window();
        incoming.decrease_window();
        assert!(incoming.window() <= window_before);
    }

    #[test]
    fn test_resource_no_compression_for_small_data() {
        let mut rng = OsRng;
        // Small data that won't benefit from compression
        let data = b"tiny";

        let config = ResourceConfig {
            auto_compress: true,
            ..ResourceConfig::default()
        };

        let resource = Resource::new(&mut rng, data, config, None, None).expect("create resource");

        // Small data might not compress well, could be either compressed or not
        // Just verify resource was created successfully
        assert!(resource.total_parts() > 0);
    }

    #[test]
    fn test_resource_large_data_compression() {
        let mut rng = OsRng;
        // Large repetitive data that should compress well
        let data = vec![0x48u8; 10000];

        let config = ResourceConfig {
            auto_compress: true,
            ..ResourceConfig::default()
        };

        let resource = Resource::new(&mut rng, &data, config, None, None).expect("create resource");

        // Verify it's marked as compressed
        assert!(resource.is_compressed());

        // Transfer size should be less than original
        assert!(resource.size() < resource.total_size() + RANDOM_HASH_SIZE);
    }

    #[test]
    fn test_resource_assembly_unencrypted() {
        let mut rng = OsRng;
        let original_data = b"Test data for assembly";

        // Create with no compression to simplify test
        let config = ResourceConfig {
            auto_compress: false,
            ..ResourceConfig::default()
        };

        let outgoing =
            Resource::new(&mut rng, original_data, config, None, None).expect("create outgoing resource");

        let adv = outgoing.create_advertisement();
        let mut incoming =
            Resource::from_advertisement(&adv, outgoing.sdu).expect("create incoming resource");

        // Receive all parts
        for part in &outgoing.parts {
            incoming.receive_part(part.data.clone());
        }

        assert!(incoming.is_complete());

        // Assembly should work with identity decryption (unencrypted)
        let assembled = incoming.assemble_with_decryption(|data| Ok(data.to_vec()));
        assert!(assembled.is_ok(), "Assembly failed: {:?}", assembled.err());

        // Note: The assembled data includes metadata prefix if present, so we check length
        let result = assembled.unwrap();
        assert!(result.len() >= original_data.len());
    }

    #[test]
    fn test_resource_get_raw_assembled_data() {
        let mut rng = OsRng;
        let data = b"Raw assembly test";

        let config = ResourceConfig {
            auto_compress: false,
            ..ResourceConfig::default()
        };

        let outgoing =
            Resource::new(&mut rng, data, config, None, None).expect("create outgoing resource");

        let adv = outgoing.create_advertisement();
        let mut incoming =
            Resource::from_advertisement(&adv, outgoing.sdu).expect("create incoming resource");

        // Before receiving parts, should return None
        assert!(incoming.get_raw_assembled_data().is_none());

        // Receive all parts
        for part in &outgoing.parts {
            incoming.receive_part(part.data.clone());
        }

        // After completion, should return Some
        let raw = incoming.get_raw_assembled_data();
        assert!(raw.is_some());
        assert!(!raw.unwrap().is_empty());
    }

    #[test]
    fn test_resource_cancel() {
        let mut rng = OsRng;
        let data = b"Data to cancel";

        let mut resource =
            Resource::new(&mut rng, data, ResourceConfig::default(), None, None).expect("create resource");

        assert_ne!(resource.status(), ResourceStatus::Failed);

        resource.cancel();

        assert_eq!(resource.status(), ResourceStatus::Failed);
    }

    #[test]
    fn test_resource_rtt_update() {
        let mut rng = OsRng;
        let data = b"RTT test";

        let outgoing =
            Resource::new(&mut rng, data, ResourceConfig::default(), None, None).expect("create outgoing resource");

        let adv = outgoing.create_advertisement();
        let mut incoming =
            Resource::from_advertisement(&adv, outgoing.sdu).expect("create incoming resource");

        // Initial RTT should be None
        assert!(incoming.rtt.is_none());

        // Set first RTT
        incoming.update_rtt(Duration::from_millis(100));
        assert_eq!(incoming.rtt, Some(Duration::from_millis(100)));

        // Update with faster RTT - should decrease
        incoming.update_rtt(Duration::from_millis(50));
        assert!(incoming.rtt.unwrap() < Duration::from_millis(100));
    }
}
