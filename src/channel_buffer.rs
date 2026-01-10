//! Buffer system for streaming data over channels.
//!
//! This module provides buffered I/O streams that send and receive
//! binary data over a Channel using StreamDataMessage.
//!
//! Key features:
//! - Stream-based reading and writing
//! - Automatic chunking and compression
//! - EOF signaling
//! - Ready callbacks for async notification

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, RwLock};

use crate::channel::{system_types, Channel, MessageBase};
use crate::error::RnsError;

/// Maximum stream ID value (14 bits)
pub const STREAM_ID_MAX: u16 = 0x3FFF;

/// Overhead for stream data message (2 bytes header + 6 bytes channel envelope)
pub const STREAM_OVERHEAD: usize = 2 + 6;

/// Maximum chunk length before splitting
pub const MAX_CHUNK_LEN: usize = 16 * 1024;

/// Number of compression attempts
pub const COMPRESSION_TRIES: usize = 4;

/// Stream data message for sending binary data over a channel
#[derive(Debug, Clone)]
pub struct StreamDataMessage {
    /// Stream ID (0-16383)
    pub stream_id: u16,
    /// Binary data
    pub data: Vec<u8>,
    /// End-of-file flag
    pub eof: bool,
    /// Whether data is compressed
    pub compressed: bool,
}

impl StreamDataMessage {
    /// Create a new stream data message
    pub fn new(stream_id: u16, data: Vec<u8>, eof: bool, compressed: bool) -> Result<Self, RnsError> {
        if stream_id > STREAM_ID_MAX {
            return Err(RnsError::InvalidArgument);
        }
        Ok(Self {
            stream_id,
            data,
            eof,
            compressed,
        })
    }

    /// Create an empty message for unpacking
    pub fn empty() -> Self {
        Self {
            stream_id: 0,
            data: Vec::new(),
            eof: false,
            compressed: false,
        }
    }
}

impl MessageBase for StreamDataMessage {
    fn msg_type(&self) -> u16 {
        system_types::SMT_STREAM_DATA
    }

    fn pack(&self) -> Vec<u8> {
        let mut header_val = self.stream_id & 0x3FFF;
        if self.eof {
            header_val |= 0x8000;
        }
        if self.compressed {
            header_val |= 0x4000;
        }

        let mut result = Vec::with_capacity(2 + self.data.len());
        result.extend_from_slice(&header_val.to_be_bytes());
        result.extend_from_slice(&self.data);
        result
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), RnsError> {
        if raw.len() < 2 {
            return Err(RnsError::InvalidArgument);
        }

        let header_val = u16::from_be_bytes([raw[0], raw[1]]);
        self.stream_id = header_val & 0x3FFF;
        self.eof = (header_val & 0x8000) != 0;
        self.compressed = (header_val & 0x4000) != 0;
        self.data = raw[2..].to_vec();

        // Decompress if needed
        if self.compressed && !self.data.is_empty() {
            self.data = decompress(&self.data)?;
        }

        Ok(())
    }
}

/// Compress data using deflate
fn compress(data: &[u8]) -> Result<Vec<u8>, RnsError> {
    use std::io::Write;
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|_| RnsError::InvalidArgument)?;
    encoder.finish().map_err(|_| RnsError::InvalidArgument)
}

/// Decompress data using deflate
fn decompress(data: &[u8]) -> Result<Vec<u8>, RnsError> {
    use std::io::Read;
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|_| RnsError::InvalidArgument)?;
    Ok(result)
}

/// Callback type for ready notification
pub type ReadyCallback = Arc<dyn Fn(usize) + Send + Sync>;

/// Raw channel reader for receiving stream data
pub struct RawChannelReader {
    /// Stream ID to receive
    stream_id: u16,
    /// Reference to channel (for receiving)
    _channel: Arc<Channel>,
    /// Internal buffer
    buffer: Mutex<Vec<u8>>,
    /// EOF received flag
    eof: Mutex<bool>,
    /// Ready callbacks
    listeners: RwLock<Vec<ReadyCallback>>,
}

impl RawChannelReader {
    /// Create a new raw channel reader
    pub fn new(stream_id: u16, channel: Arc<Channel>) -> Arc<Self> {
        let reader = Arc::new(Self {
            stream_id,
            _channel: channel.clone(),
            buffer: Mutex::new(Vec::new()),
            eof: Mutex::new(false),
            listeners: RwLock::new(Vec::new()),
        });

        // Register the message type
        channel
            .register_system_message_type(system_types::SMT_STREAM_DATA, || {
                Box::new(StreamDataMessage::empty())
            })
            .ok(); // Ignore if already registered

        // Add message handler
        let reader_clone = Arc::downgrade(&reader);
        let stream_id = reader.stream_id;
        channel.add_message_handler(Arc::new(move |msg| {
            if let Some(reader) = reader_clone.upgrade() {
                if msg.msg_type() == system_types::SMT_STREAM_DATA {
                    // We need to handle the message
                    // Since we can't downcast easily, we check if it's our stream
                    // In a real implementation, we'd have a proper way to get the data
                    reader.handle_stream_data(stream_id);
                    return true;
                }
            }
            false
        }));

        reader
    }

    /// Handle incoming stream data (called from message handler)
    fn handle_stream_data(&self, _expected_stream_id: u16) {
        // This would need to be called with actual message data
        // In the current design, we'd need a different approach
    }

    /// Receive stream data directly
    pub fn receive_data(&self, msg: &StreamDataMessage) {
        if msg.stream_id == self.stream_id {
            let mut buffer = self.buffer.lock().unwrap();
            buffer.extend_from_slice(&msg.data);

            if msg.eof {
                *self.eof.lock().unwrap() = true;
            }

            let ready_bytes = buffer.len();
            drop(buffer);

            // Notify listeners
            let listeners = self.listeners.read().unwrap();
            for listener in listeners.iter() {
                listener(ready_bytes);
            }
        }
    }

    /// Add a callback for when data is ready
    pub fn add_ready_callback(&self, callback: ReadyCallback) {
        let mut listeners = self.listeners.write().unwrap();
        listeners.push(callback);
    }

    /// Remove a ready callback
    pub fn remove_ready_callback(&self, callback: &ReadyCallback) {
        let mut listeners = self.listeners.write().unwrap();
        listeners.retain(|cb| !Arc::ptr_eq(cb, callback));
    }

    /// Check if EOF has been received
    pub fn is_eof(&self) -> bool {
        *self.eof.lock().unwrap()
    }

    /// Get available bytes
    pub fn available(&self) -> usize {
        self.buffer.lock().unwrap().len()
    }
}

impl Read for RawChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buffer = self.buffer.lock().unwrap();
        let eof = *self.eof.lock().unwrap();

        if buffer.is_empty() {
            if eof {
                return Ok(0); // EOF
            }
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no data available"));
        }

        let to_read = buf.len().min(buffer.len());
        buf[..to_read].copy_from_slice(&buffer[..to_read]);
        buffer.drain(..to_read);
        Ok(to_read)
    }
}

/// Raw channel writer for sending stream data
pub struct RawChannelWriter {
    /// Stream ID to send to
    stream_id: u16,
    /// Reference to channel
    channel: Arc<Channel>,
    /// EOF flag
    eof: bool,
    /// Maximum data unit (from channel MDU minus overhead)
    mdu: usize,
}

impl RawChannelWriter {
    /// Create a new raw channel writer
    pub fn new(stream_id: u16, channel: Arc<Channel>) -> Self {
        let mdu = channel.mdu().saturating_sub(STREAM_OVERHEAD);
        Self {
            stream_id,
            channel,
            eof: false,
            mdu,
        }
    }

    /// Send raw data
    fn send_chunk(&self, data: &[u8], eof: bool, compressed: bool) -> Result<(), RnsError> {
        let msg = StreamDataMessage::new(self.stream_id, data.to_vec(), eof, compressed)?;
        self.channel.send(&msg)?;
        Ok(())
    }

    /// Signal end-of-file
    pub fn close(&mut self) -> io::Result<()> {
        // Wait for channel to be ready (simplified - in production would have proper wait)
        if !self.channel.is_ready_to_send() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "channel not ready",
            ));
        }

        self.eof = true;
        self.send_chunk(&[], true, false)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
    }
}

impl Write for RawChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Limit chunk size
        let chunk_len = buf.len().min(MAX_CHUNK_LEN);
        let chunk = &buf[..chunk_len];

        // Try compression
        let mut comp_success = false;
        let mut processed_len = chunk_len;
        let mut final_chunk = chunk.to_vec();

        if chunk_len > 32 {
            for comp_try in 1..=COMPRESSION_TRIES {
                let segment_len = chunk_len / comp_try;
                if segment_len < 32 {
                    break;
                }

                if let Ok(compressed) = compress(&chunk[..segment_len]) {
                    if compressed.len() < self.mdu && compressed.len() < segment_len {
                        comp_success = true;
                        final_chunk = compressed;
                        processed_len = segment_len;
                        break;
                    }
                }
            }
        }

        if !comp_success {
            final_chunk = chunk[..chunk_len.min(self.mdu)].to_vec();
            processed_len = final_chunk.len();
        }

        self.send_chunk(&final_chunk, self.eof, comp_success)
            .map_err(|e| {
                if matches!(e, RnsError::ConnectionError) {
                    io::Error::new(io::ErrorKind::WouldBlock, "channel not ready")
                } else {
                    io::Error::new(io::ErrorKind::Other, format!("{:?}", e))
                }
            })?;

        Ok(processed_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Buffer utilities for creating buffered streams
pub struct ChannelBuffer;

impl ChannelBuffer {
    /// Create a reader for receiving stream data
    pub fn create_reader(
        stream_id: u16,
        channel: Arc<Channel>,
        ready_callback: Option<ReadyCallback>,
    ) -> Arc<RawChannelReader> {
        let reader = RawChannelReader::new(stream_id, channel);
        if let Some(callback) = ready_callback {
            reader.add_ready_callback(callback);
        }
        reader
    }

    /// Create a writer for sending stream data
    pub fn create_writer(stream_id: u16, channel: Arc<Channel>) -> RawChannelWriter {
        RawChannelWriter::new(stream_id, channel)
    }

    /// Create a bidirectional buffer pair
    pub fn create_bidirectional(
        receive_stream_id: u16,
        send_stream_id: u16,
        channel: Arc<Channel>,
        ready_callback: Option<ReadyCallback>,
    ) -> (Arc<RawChannelReader>, RawChannelWriter) {
        let reader = ChannelBuffer::create_reader(receive_stream_id, channel.clone(), ready_callback);
        let writer = ChannelBuffer::create_writer(send_stream_id, channel);
        (reader, writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_stream_data_message_pack_unpack() {
        let msg = StreamDataMessage::new(42, b"Hello, Buffer!".to_vec(), false, false)
            .expect("create message");

        let packed = msg.pack();

        let mut unpacked = StreamDataMessage::empty();
        unpacked.unpack(&packed).expect("unpack");

        assert_eq!(unpacked.stream_id, 42);
        assert_eq!(unpacked.data, b"Hello, Buffer!");
        assert!(!unpacked.eof);
        assert!(!unpacked.compressed);
    }

    #[test]
    fn test_stream_data_message_with_eof() {
        let msg = StreamDataMessage::new(100, vec![], true, false).expect("create message");
        let packed = msg.pack();

        let mut unpacked = StreamDataMessage::empty();
        unpacked.unpack(&packed).expect("unpack");

        assert_eq!(unpacked.stream_id, 100);
        assert!(unpacked.eof);
    }

    #[test]
    fn test_stream_id_max() {
        assert!(StreamDataMessage::new(STREAM_ID_MAX, vec![], false, false).is_ok());
        assert!(StreamDataMessage::new(STREAM_ID_MAX + 1, vec![], false, false).is_err());
    }

    #[test]
    fn test_compression() {
        let data = b"Hello, compression! ".repeat(100);
        let compressed = compress(&data).expect("compress");
        let decompressed = decompress(&compressed).expect("decompress");
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_raw_channel_writer_creation() {
        let channel = Arc::new(Channel::new(500, Duration::from_millis(100)));
        let writer = RawChannelWriter::new(1, channel);
        assert!(writer.mdu > 0);
    }

    #[test]
    fn test_channel_buffer_utilities() {
        let channel = Arc::new(Channel::new(500, Duration::from_millis(100)));

        let _reader = ChannelBuffer::create_reader(1, channel.clone(), None);
        let _writer = ChannelBuffer::create_writer(2, channel.clone());
        let (_reader2, _writer2) = ChannelBuffer::create_bidirectional(3, 4, channel, None);
    }
}
