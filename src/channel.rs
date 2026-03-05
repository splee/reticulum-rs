//! Channel system for reliable message delivery over links.
//!
//! Channels provide reliable delivery of messages over a link with:
//! - Automatic retries
//! - Sequencing and ordering
//! - Message type registration
//! - Bi-directional communication
//!
//! Unlike Resource transfers, Channel messages must fit in a single packet.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::error::RnsError;

/// System-reserved message types
pub mod system_types {
    /// Stream data message type (used by Buffer)
    pub const SMT_STREAM_DATA: u16 = 0xff00;
}

/// Channel window configuration constants
pub mod window {
    /// Initial window size at channel setup
    pub const INITIAL: usize = 2;
    /// Absolute minimum window size
    pub const MIN: usize = 2;
    /// Minimum window limit for slow links
    pub const MIN_LIMIT_SLOW: usize = 2;
    /// Minimum window limit for medium speed links
    pub const MIN_LIMIT_MEDIUM: usize = 5;
    /// Minimum window limit for fast links
    pub const MIN_LIMIT_FAST: usize = 16;
    /// Maximum window size for slow links
    pub const MAX_SLOW: usize = 5;
    /// Maximum window size for medium speed links
    pub const MAX_MEDIUM: usize = 12;
    /// Maximum window size for fast links
    pub const MAX_FAST: usize = 48;
    /// Global maximum window size
    pub const MAX: usize = MAX_FAST;
    /// Fast rate threshold rounds
    pub const FAST_RATE_THRESHOLD: usize = 10;
    /// RTT threshold for fast links
    pub const RTT_FAST: f64 = 0.18;
    /// RTT threshold for medium links
    pub const RTT_MEDIUM: f64 = 0.75;
    /// RTT threshold for slow links
    pub const RTT_SLOW: f64 = 1.45;
    /// Minimum window flexibility
    pub const FLEXIBILITY: usize = 4;
}

/// Maximum sequence number (16-bit)
pub const SEQ_MAX: u16 = 0xFFFF;
/// Sequence modulus for wraparound
pub const SEQ_MODULUS: u32 = SEQ_MAX as u32 + 1;

/// Channel exception types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelErrorType {
    /// Message has no type
    NoMsgType = 0,
    /// Invalid message type
    InvalidMsgType = 1,
    /// Message type not registered
    NotRegistered = 2,
    /// Link not ready
    LinkNotReady = 3,
    /// Message already sent
    AlreadySent = 4,
    /// Message too big
    TooBig = 5,
}

/// Message state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum MessageState {
    /// New message, not yet sent
    #[default]
    New = 0,
    /// Message has been sent
    Sent = 1,
    /// Message was delivered
    Delivered = 2,
    /// Message delivery failed
    Failed = 3,
}


/// Trait for messages that can be sent over a channel.
///
/// Messages must be Send + Sync for use across threads, Debug for logging,
/// and Any for downcasting in message handlers.
pub trait MessageBase: Send + Sync + std::fmt::Debug + std::any::Any {
    /// Get the message type ID (must be unique per channel, < 0xf000)
    fn msg_type(&self) -> u16;

    /// Pack the message into bytes
    fn pack(&self) -> Vec<u8>;

    /// Unpack the message from bytes
    fn unpack(&mut self, raw: &[u8]) -> Result<(), RnsError>;

    /// Get a reference to self as Any for downcasting in message handlers.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Factory function type for creating messages from their type
pub type MessageFactory = Box<dyn Fn() -> Box<dyn MessageBase> + Send + Sync>;

/// Callback type for message handlers
pub type MessageCallback = Arc<dyn Fn(&dyn MessageBase) -> bool + Send + Sync>;

/// Internal envelope for tracking messages
#[derive(Debug)]
pub struct Envelope {
    /// Timestamp when envelope was created
    pub timestamp: Instant,
    /// Unique envelope ID
    pub id: u64,
    /// Message sequence number
    pub sequence: u16,
    /// Raw packed data
    pub raw: Vec<u8>,
    /// Number of send attempts
    pub tries: u32,
    /// Whether the envelope is unpacked
    pub unpacked: bool,
    /// Whether the envelope is packed
    pub packed: bool,
    /// Whether the envelope is being tracked
    pub tracked: bool,
    /// Current state
    pub state: MessageState,
}

impl Envelope {
    /// Create a new envelope for sending
    pub fn new_for_send(sequence: u16) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            timestamp: Instant::now(),
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            sequence,
            raw: Vec::new(),
            tries: 0,
            unpacked: false,
            packed: false,
            tracked: false,
            state: MessageState::New,
        }
    }

    /// Create a new envelope from received data
    pub fn new_from_receive(raw: Vec<u8>) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            timestamp: Instant::now(),
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            sequence: 0, // Will be set during unpack
            raw,
            tries: 0,
            unpacked: false,
            packed: true,
            tracked: false,
            state: MessageState::New,
        }
    }

    /// Pack a message into this envelope
    pub fn pack(&mut self, message: &dyn MessageBase) -> Result<(), RnsError> {
        let msg_type = message.msg_type();
        let data = message.pack();
        let length = data.len() as u16;

        // Header: msgtype (2) + sequence (2) + length (2) = 6 bytes
        let mut raw = Vec::with_capacity(6 + data.len());
        raw.extend_from_slice(&msg_type.to_be_bytes());
        raw.extend_from_slice(&self.sequence.to_be_bytes());
        raw.extend_from_slice(&length.to_be_bytes());
        raw.extend_from_slice(&data);

        self.raw = raw;
        self.packed = true;
        Ok(())
    }

    /// Unpack the envelope header
    pub fn unpack_header(&mut self) -> Result<u16, RnsError> {
        if self.raw.len() < 6 {
            return Err(RnsError::InvalidArgument);
        }

        let msg_type = u16::from_be_bytes([self.raw[0], self.raw[1]]);
        self.sequence = u16::from_be_bytes([self.raw[2], self.raw[3]]);
        let _length = u16::from_be_bytes([self.raw[4], self.raw[5]]);

        Ok(msg_type)
    }

    /// Get the message data (after header)
    pub fn message_data(&self) -> &[u8] {
        if self.raw.len() > 6 {
            &self.raw[6..]
        } else {
            &[]
        }
    }
}

/// Channel for reliable message delivery over a link
pub struct Channel {
    /// TX ring buffer
    tx_ring: Mutex<VecDeque<Envelope>>,
    /// RX ring buffer
    rx_ring: Mutex<VecDeque<Envelope>>,
    /// Message factories by type
    message_factories: RwLock<HashMap<u16, MessageFactory>>,
    /// Message callbacks
    message_callbacks: RwLock<Vec<MessageCallback>>,
    /// Next sequence number to send
    next_sequence: Mutex<u16>,
    /// Next expected RX sequence
    next_rx_sequence: Mutex<u16>,
    /// Maximum send retries
    max_tries: u32,
    /// Current window size
    window: Mutex<usize>,
    /// Maximum window size
    window_max: Mutex<usize>,
    /// Minimum window size
    window_min: Mutex<usize>,
    /// Window flexibility
    window_flexibility: usize,
    /// Fast rate rounds counter
    fast_rate_rounds: Mutex<usize>,
    /// Medium rate rounds counter
    medium_rate_rounds: Mutex<usize>,
    /// MDU for this channel (from link)
    mdu: usize,
    /// RTT for this channel (from link)
    rtt: Mutex<Duration>,
    /// Whether channel is usable
    usable: Mutex<bool>,
}

impl Channel {
    /// Create a new channel
    pub fn new(mdu: usize, rtt: Duration) -> Self {
        let rtt_secs = rtt.as_secs_f64();

        let (window, window_max, window_min, window_flexibility) = if rtt_secs > window::RTT_SLOW {
            (1, 1, 1, 1)
        } else {
            (
                window::INITIAL,
                window::MAX_SLOW,
                window::MIN,
                window::FLEXIBILITY,
            )
        };

        Self {
            tx_ring: Mutex::new(VecDeque::new()),
            rx_ring: Mutex::new(VecDeque::new()),
            message_factories: RwLock::new(HashMap::new()),
            message_callbacks: RwLock::new(Vec::new()),
            next_sequence: Mutex::new(0),
            next_rx_sequence: Mutex::new(0),
            max_tries: 5,
            window: Mutex::new(window),
            window_max: Mutex::new(window_max),
            window_min: Mutex::new(window_min),
            window_flexibility,
            fast_rate_rounds: Mutex::new(0),
            medium_rate_rounds: Mutex::new(0),
            mdu,
            rtt: Mutex::new(rtt),
            usable: Mutex::new(true),
        }
    }

    /// Register a message type
    pub fn register_message_type<F>(&self, msg_type: u16, factory: F) -> Result<(), RnsError>
    where
        F: Fn() -> Box<dyn MessageBase> + Send + Sync + 'static,
    {
        self.register_message_type_internal(msg_type, factory, false)
    }

    /// Register a system message type
    pub fn register_system_message_type<F>(&self, msg_type: u16, factory: F) -> Result<(), RnsError>
    where
        F: Fn() -> Box<dyn MessageBase> + Send + Sync + 'static,
    {
        self.register_message_type_internal(msg_type, factory, true)
    }

    fn register_message_type_internal<F>(
        &self,
        msg_type: u16,
        factory: F,
        is_system: bool,
    ) -> Result<(), RnsError>
    where
        F: Fn() -> Box<dyn MessageBase> + Send + Sync + 'static,
    {
        if msg_type >= 0xf000 && !is_system {
            return Err(RnsError::InvalidArgument);
        }

        let mut factories = self.message_factories.write().unwrap();
        factories.insert(msg_type, Box::new(factory));
        Ok(())
    }

    /// Add a message handler
    pub fn add_message_handler(&self, callback: MessageCallback) {
        let mut callbacks = self.message_callbacks.write().unwrap();
        callbacks.push(callback);
    }

    /// Remove a message handler
    pub fn remove_message_handler(&self, callback: &MessageCallback) {
        let mut callbacks = self.message_callbacks.write().unwrap();
        callbacks.retain(|cb| !Arc::ptr_eq(cb, callback));
    }

    /// Check if channel is ready to send
    pub fn is_ready_to_send(&self) -> bool {
        if !*self.usable.lock().unwrap() {
            return false;
        }

        let tx_ring = self.tx_ring.lock().unwrap();
        let window = *self.window.lock().unwrap();

        let outstanding = tx_ring
            .iter()
            .filter(|e| e.state != MessageState::Delivered)
            .count();

        outstanding < window
    }

    /// Get the MDU for messages (accounts for header overhead)
    pub fn mdu(&self) -> usize {
        // Subtract envelope header size (6 bytes: msgtype + sequence + length)
        self.mdu.saturating_sub(6).min(0xFFFF)
    }

    /// Send a message
    pub fn send(&self, message: &dyn MessageBase) -> Result<u64, RnsError> {
        if !self.is_ready_to_send() {
            return Err(RnsError::ConnectionError);
        }

        // Get next sequence number
        let sequence = {
            let mut next_seq = self.next_sequence.lock().unwrap();
            let seq = *next_seq;
            *next_seq = (*next_seq).wrapping_add(1);
            seq
        };

        // Create and pack envelope
        let mut envelope = Envelope::new_for_send(sequence);
        envelope.pack(message)?;

        // Check size
        if envelope.raw.len() > self.mdu {
            return Err(RnsError::OutOfMemory);
        }

        let envelope_id = envelope.id;
        envelope.tries = 1;
        envelope.state = MessageState::Sent;
        envelope.tracked = true;

        // Add to TX ring
        let mut tx_ring = self.tx_ring.lock().unwrap();
        tx_ring.push_back(envelope);

        Ok(envelope_id)
    }

    /// Get raw data to send for an envelope
    pub fn get_send_data(&self, envelope_id: u64) -> Option<Vec<u8>> {
        let tx_ring = self.tx_ring.lock().unwrap();
        tx_ring.iter().find(|e| e.id == envelope_id).map(|e| e.raw.clone())
    }

    /// Mark an envelope as delivered
    pub fn mark_delivered(&self, envelope_id: u64) {
        let mut tx_ring = self.tx_ring.lock().unwrap();
        if let Some(envelope) = tx_ring.iter_mut().find(|e| e.id == envelope_id) {
            envelope.state = MessageState::Delivered;
        }

        // Remove delivered envelopes
        tx_ring.retain(|e| e.state != MessageState::Delivered);

        // Adjust window on success
        let mut window = self.window.lock().unwrap();
        let window_max = *self.window_max.lock().unwrap();
        if *window < window_max {
            *window += 1;
        }

        // Update rate tracking
        let rtt = self.rtt.lock().unwrap().as_secs_f64();
        if rtt > 0.0 {
            if rtt > window::RTT_FAST {
                *self.fast_rate_rounds.lock().unwrap() = 0;

                if rtt > window::RTT_MEDIUM {
                    *self.medium_rate_rounds.lock().unwrap() = 0;
                } else {
                    let mut medium_rounds = self.medium_rate_rounds.lock().unwrap();
                    *medium_rounds += 1;
                    if *self.window_max.lock().unwrap() < window::MAX_MEDIUM
                        && *medium_rounds == window::FAST_RATE_THRESHOLD
                    {
                        *self.window_max.lock().unwrap() = window::MAX_MEDIUM;
                        *self.window_min.lock().unwrap() = window::MIN_LIMIT_MEDIUM;
                    }
                }
            } else {
                let mut fast_rounds = self.fast_rate_rounds.lock().unwrap();
                *fast_rounds += 1;
                if *self.window_max.lock().unwrap() < window::MAX_FAST
                    && *fast_rounds == window::FAST_RATE_THRESHOLD
                {
                    *self.window_max.lock().unwrap() = window::MAX_FAST;
                    *self.window_min.lock().unwrap() = window::MIN_LIMIT_FAST;
                }
            }
        }
    }

    /// Mark an envelope as timed out (needs retry)
    pub fn mark_timeout(&self, envelope_id: u64) -> Result<bool, RnsError> {
        let mut tx_ring = self.tx_ring.lock().unwrap();
        let envelope = tx_ring.iter_mut().find(|e| e.id == envelope_id);

        if let Some(envelope) = envelope {
            if envelope.tries >= self.max_tries {
                envelope.state = MessageState::Failed;
                return Ok(false); // No more retries
            }

            envelope.tries += 1;

            // Decrease window on timeout
            let mut window = self.window.lock().unwrap();
            let window_min = *self.window_min.lock().unwrap();
            if *window > window_min {
                *window -= 1;
            }

            let mut window_max = self.window_max.lock().unwrap();
            if *window_max > (window_min + self.window_flexibility) {
                *window_max -= 1;
            }

            Ok(true) // Should retry
        } else {
            Err(RnsError::InvalidArgument)
        }
    }

    /// Receive data from the channel
    pub fn receive(&self, raw: &[u8]) -> Result<(), RnsError> {
        let mut envelope = Envelope::new_from_receive(raw.to_vec());
        let msg_type = envelope.unpack_header()?;

        // Check sequence validity
        let next_rx_seq = *self.next_rx_sequence.lock().unwrap();
        let window_overflow = (next_rx_seq as u32 + window::MAX as u32) % SEQ_MODULUS;

        if envelope.sequence < next_rx_seq {
            if window_overflow < next_rx_seq as u32 {
                if envelope.sequence as u32 > window_overflow {
                    // Invalid sequence
                    return Ok(());
                }
            } else {
                // Invalid sequence
                return Ok(());
            }
        }

        // Find factory for this message type
        let factories = self.message_factories.read().unwrap();
        let factory = factories.get(&msg_type).ok_or(RnsError::InvalidArgument)?;

        // Create and unpack message
        let mut message = factory();
        message.unpack(envelope.message_data())?;
        envelope.unpacked = true;

        // Emplace in RX ring
        let mut rx_ring = self.rx_ring.lock().unwrap();
        let is_duplicate = rx_ring.iter().any(|e| e.sequence == envelope.sequence);
        if is_duplicate {
            return Ok(());
        }

        envelope.tracked = true;
        rx_ring.push_back(envelope);

        // Process contiguous messages
        drop(rx_ring);
        self.process_rx_ring(&*message)?;

        Ok(())
    }

    fn process_rx_ring(&self, first_message: &dyn MessageBase) -> Result<(), RnsError> {
        let mut next_rx_seq = self.next_rx_sequence.lock().unwrap();
        let callbacks = self.message_callbacks.read().unwrap().clone();

        // Run callbacks for the first message if it's in sequence
        let mut rx_ring = self.rx_ring.lock().unwrap();

        let mut to_remove = Vec::new();
        for envelope in rx_ring.iter() {
            if envelope.sequence == *next_rx_seq {
                to_remove.push(envelope.sequence);
                *next_rx_seq = next_rx_seq.wrapping_add(1);
            }
        }

        // Remove processed envelopes
        rx_ring.retain(|e| !to_remove.contains(&e.sequence));
        drop(rx_ring);

        // Run callbacks
        for callback in &callbacks {
            if callback(first_message) {
                break;
            }
        }

        Ok(())
    }

    /// Update RTT
    pub fn update_rtt(&self, rtt: Duration) {
        *self.rtt.lock().unwrap() = rtt;
    }

    /// Get current window size
    pub fn window(&self) -> usize {
        *self.window.lock().unwrap()
    }

    /// Set usability
    pub fn set_usable(&self, usable: bool) {
        *self.usable.lock().unwrap() = usable;
    }

    /// Shutdown the channel
    pub fn shutdown(&self) {
        *self.usable.lock().unwrap() = false;
        self.tx_ring.lock().unwrap().clear();
        self.rx_ring.lock().unwrap().clear();
        self.message_callbacks.write().unwrap().clear();
    }

    /// Get pending TX envelope count
    pub fn pending_tx_count(&self) -> usize {
        self.tx_ring.lock().unwrap().len()
    }

    /// Get pending RX envelope count
    pub fn pending_rx_count(&self) -> usize {
        self.rx_ring.lock().unwrap().len()
    }
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("mdu", &self.mdu)
            .field("window", &self.window())
            .field("pending_tx", &self.pending_tx_count())
            .field("pending_rx", &self.pending_rx_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple test message
    #[derive(Debug)]
    struct TestMessage {
        data: Vec<u8>,
    }

    impl TestMessage {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
            }
        }
    }

    impl MessageBase for TestMessage {
        fn msg_type(&self) -> u16 {
            0x0001
        }

        fn pack(&self) -> Vec<u8> {
            self.data.clone()
        }

        fn unpack(&mut self, raw: &[u8]) -> Result<(), RnsError> {
            self.data = raw.to_vec();
            Ok(())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn test_channel_creation() {
        let channel = Channel::new(500, Duration::from_millis(100));
        assert!(channel.is_ready_to_send());
        assert!(channel.mdu() > 0);
    }

    #[test]
    fn test_message_registration() {
        let channel = Channel::new(500, Duration::from_millis(100));

        // Register message type
        channel
            .register_message_type(0x0001, || Box::new(TestMessage::new(&[])))
            .expect("register type");

        // System types are allowed
        channel
            .register_system_message_type(0xff00, || Box::new(TestMessage::new(&[])))
            .expect("register system type");

        // Non-system types >= 0xf000 should fail
        assert!(channel
            .register_message_type(0xf000, || Box::new(TestMessage::new(&[])))
            .is_err());
    }

    #[test]
    fn test_envelope_pack_unpack() {
        let msg = TestMessage::new(b"Hello, Channel!");
        let mut envelope = Envelope::new_for_send(42);
        envelope.pack(&msg).expect("pack");

        // Unpack header
        let msg_type = envelope.unpack_header().expect("unpack header");
        assert_eq!(msg_type, 0x0001);
        assert_eq!(envelope.sequence, 42);
        assert_eq!(envelope.message_data(), b"Hello, Channel!");
    }

    #[test]
    fn test_send_message() {
        let channel = Channel::new(500, Duration::from_millis(100));

        let msg = TestMessage::new(b"Test message");
        let envelope_id = channel.send(&msg).expect("send");

        assert!(envelope_id > 0);
        assert_eq!(channel.pending_tx_count(), 1);

        // Mark delivered
        channel.mark_delivered(envelope_id);
        assert_eq!(channel.pending_tx_count(), 0);
    }

    #[test]
    fn test_message_state() {
        assert_eq!(MessageState::default(), MessageState::New);
    }

    #[test]
    fn test_window_constants() {
        assert!(window::MAX >= window::MAX_SLOW);
        assert!(window::MAX >= window::MAX_MEDIUM);
        assert!(window::MAX >= window::MAX_FAST);
    }

    #[test]
    fn test_receive_message() {
        let channel = Channel::new(500, Duration::from_millis(100));

        // Register the message type
        channel
            .register_message_type(0x0001, || Box::new(TestMessage::new(&[])))
            .expect("register type");

        // Add a message handler to verify reception
        let received = std::sync::Arc::new(std::sync::Mutex::new(false));
        let received_clone = received.clone();
        channel.add_message_handler(Arc::new(move |_msg| {
            *received_clone.lock().unwrap() = true;
            true
        }));

        // Create a raw message packet (same format as Envelope::pack produces)
        // Header: msgtype (2) + sequence (2) + length (2) = 6 bytes
        let msg_data = b"Test receive";
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x0001u16.to_be_bytes()); // msg_type
        raw.extend_from_slice(&0u16.to_be_bytes()); // sequence 0
        raw.extend_from_slice(&(msg_data.len() as u16).to_be_bytes()); // length
        raw.extend_from_slice(msg_data);

        // Receive the message
        channel.receive(&raw).expect("receive");

        // Verify handler was called
        assert!(*received.lock().unwrap());
    }

    #[test]
    fn test_channel_shutdown() {
        let channel = Channel::new(500, Duration::from_millis(100));

        let msg = TestMessage::new(b"Test message");
        channel.send(&msg).expect("send");

        assert_eq!(channel.pending_tx_count(), 1);

        // Shutdown should clear everything
        channel.shutdown();

        assert_eq!(channel.pending_tx_count(), 0);
        assert!(!channel.is_ready_to_send());
    }

    #[test]
    fn test_timeout_handling() {
        let channel = Channel::new(500, Duration::from_millis(100));

        let msg = TestMessage::new(b"Test message");
        let envelope_id = channel.send(&msg).expect("send");

        // First timeout should allow retry
        assert!(channel.mark_timeout(envelope_id).expect("timeout 1"));
        assert!(channel.mark_timeout(envelope_id).expect("timeout 2"));
        assert!(channel.mark_timeout(envelope_id).expect("timeout 3"));
        assert!(channel.mark_timeout(envelope_id).expect("timeout 4"));

        // 5th timeout (max_tries=5) should fail
        assert!(!channel.mark_timeout(envelope_id).expect("timeout 5"));
    }

    #[test]
    fn test_channel_mdu() {
        // Channel MDU should account for envelope header overhead (6 bytes)
        let link_mdu = 500;
        let channel = Channel::new(link_mdu, Duration::from_millis(100));

        assert_eq!(channel.mdu(), link_mdu - 6);
    }

    #[test]
    fn test_get_send_data() {
        let channel = Channel::new(500, Duration::from_millis(100));

        let msg = TestMessage::new(b"Test data");
        let envelope_id = channel.send(&msg).expect("send");

        // Should be able to retrieve the packed data
        let data = channel.get_send_data(envelope_id).expect("get data");
        assert!(!data.is_empty());

        // Data should contain the message
        assert!(data.len() > 6); // Header + message data
    }
}
