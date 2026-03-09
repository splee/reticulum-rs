//! KISS framing for serial and TCP interfaces.
//!
//! This module provides KISS (Keep It Simple, Stupid) framing used for TNC
//! communication and as an alternative to HDLC for TCP interfaces.
//!
//! KISS framing uses:
//! - FEND (0xC0) as frame delimiter
//! - FESC (0xDB) as escape byte
//! - TFEND (0xDC) replaces escaped FEND
//! - TFESC (0xDD) replaces escaped FESC
//!
//! Python reference: RNS/Interfaces/TCPInterface.py

use crate::{buffer::OutputBuffer, error::RnsError};

/// KISS frame start/end marker
pub const FEND: u8 = 0xC0;
/// KISS frame escape
pub const FESC: u8 = 0xDB;
/// Escaped FEND (transposed FEND)
pub const TFEND: u8 = 0xDC;
/// Escaped FESC (transposed FESC)
pub const TFESC: u8 = 0xDD;
/// Data frame command
pub const CMD_DATA: u8 = 0x00;
/// TX delay command
pub const CMD_TXDELAY: u8 = 0x01;
/// Persistence command
pub const CMD_P: u8 = 0x02;
/// Slot time command
pub const CMD_SLOTTIME: u8 = 0x03;
/// TX tail command
pub const CMD_TXTAIL: u8 = 0x04;
/// Full duplex command
pub const CMD_FULLDUPLEX: u8 = 0x05;
/// Set hardware command
pub const CMD_SETHW: u8 = 0x06;
/// Flow control ready signal
pub const CMD_READY: u8 = 0x0F;
/// Sentinel for "no command parsed yet"
pub const CMD_UNKNOWN: u8 = 0xFE;
/// Return (exit KISS mode) command
pub const CMD_RETURN: u8 = 0xFF;

/// KISS framing encoder/decoder.
///
/// Provides methods to encode data into KISS frames and decode KISS frames
/// back to raw data. The interface mirrors `Hdlc` for consistency.
pub struct Kiss;

impl Kiss {
    /// Write escaped data to the buffer.
    ///
    /// Escapes FEND and FESC bytes according to KISS protocol.
    fn write_escaped(data: &[u8], buffer: &mut OutputBuffer) -> Result<(), RnsError> {
        for &byte in data {
            match byte {
                FEND => buffer.write(&[FESC, TFEND])?,
                FESC => buffer.write(&[FESC, TFESC])?,
                _ => buffer.write_byte(byte)?,
            };
        }
        Ok(())
    }

    /// Encode data into a KISS frame.
    ///
    /// Format: FEND + CMD_DATA + escaped_data + FEND
    ///
    /// # Arguments
    /// * `data` - Raw data to encode
    /// * `buffer` - Output buffer for the encoded frame
    ///
    /// # Returns
    /// Number of bytes written to the buffer
    pub fn encode(data: &[u8], buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write_byte(FEND)?;
        buffer.write_byte(CMD_DATA)?;
        Self::write_escaped(data, buffer)?;
        buffer.write_byte(FEND)?;
        Ok(buffer.offset())
    }

    /// Encode data into a KISS frame with a specific port number.
    ///
    /// Format: FEND + (port << 4 | CMD_DATA) + escaped_data + FEND
    ///
    /// # Arguments
    /// * `data` - Raw data to encode
    /// * `port` - TNC port number (0-15)
    /// * `buffer` - Output buffer for the encoded frame
    ///
    /// # Returns
    /// Number of bytes written to the buffer
    pub fn encode_with_port(data: &[u8], port: u8, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write_byte(FEND)?;
        buffer.write_byte((port.min(15) << 4) | CMD_DATA)?;
        Self::write_escaped(data, buffer)?;
        buffer.write_byte(FEND)?;
        Ok(buffer.offset())
    }

    /// Find a complete KISS frame in the data.
    ///
    /// Returns the start and end indices (inclusive) of the first complete
    /// KISS frame found in the data, or None if no complete frame is found.
    ///
    /// # Arguments
    /// * `data` - Buffer to search for a frame
    ///
    /// # Returns
    /// Some((start, end)) if a complete frame is found, None otherwise
    pub fn find(data: &[u8]) -> Option<(usize, usize)> {
        let mut start = false;
        let mut start_index: usize = 0;

        for (i, &byte) in data.iter().enumerate() {
            if byte != FEND {
                continue;
            }

            if !start {
                start_index = i;
                start = true;
            } else {
                // Found end of frame
                return Some((start_index, i));
            }
        }

        None
    }

    /// Decode a KISS frame to extract the payload data.
    ///
    /// The frame must be complete (starting and ending with FEND).
    /// The command byte is consumed but not validated.
    ///
    /// # Arguments
    /// * `data` - KISS frame data (including FEND markers)
    /// * `output` - Output buffer for decoded data
    ///
    /// # Returns
    /// Number of bytes written to the output buffer
    pub fn decode(data: &[u8], output: &mut OutputBuffer) -> Result<usize, RnsError> {
        let mut started = false;
        let mut finished = false;
        let mut escape = false;
        let mut command_consumed = false;

        for &byte in data {
            if escape {
                escape = false;
                let decoded = match byte {
                    TFEND => FEND,
                    TFESC => FESC,
                    _ => byte, // Invalid escape, pass through
                };
                output.write_byte(decoded)?;
            } else {
                match byte {
                    FEND => {
                        if started {
                            finished = true;
                            break;
                        }
                        started = true;
                    }
                    FESC => {
                        if started && command_consumed {
                            escape = true;
                        }
                    }
                    _ => {
                        if started {
                            if !command_consumed {
                                // First byte after FEND is command byte, skip it
                                command_consumed = true;
                            } else {
                                output.write_byte(byte)?;
                            }
                        }
                    }
                }
            }
        }

        if !finished {
            return Err(RnsError::FramingError);
        }

        Ok(output.offset())
    }

    /// Decode a KISS frame and return the command byte along with the payload.
    ///
    /// # Arguments
    /// * `data` - KISS frame data (including FEND markers)
    /// * `output` - Output buffer for decoded data
    ///
    /// # Returns
    /// Tuple of (command_byte, payload_length)
    pub fn decode_with_command(data: &[u8], output: &mut OutputBuffer) -> Result<(u8, usize), RnsError> {
        let mut started = false;
        let mut finished = false;
        let mut escape = false;
        let mut command_byte: Option<u8> = None;

        for &byte in data {
            if escape {
                escape = false;
                let decoded = match byte {
                    TFEND => FEND,
                    TFESC => FESC,
                    _ => byte,
                };
                output.write_byte(decoded)?;
            } else {
                match byte {
                    FEND => {
                        if started {
                            finished = true;
                            break;
                        }
                        started = true;
                    }
                    FESC => {
                        if started && command_byte.is_some() {
                            escape = true;
                        }
                    }
                    _ => {
                        if started {
                            if command_byte.is_none() {
                                command_byte = Some(byte & 0x0F);
                            } else {
                                output.write_byte(byte)?;
                            }
                        }
                    }
                }
            }
        }

        if !finished {
            return Err(RnsError::FramingError);
        }

        let cmd = command_byte.unwrap_or(CMD_DATA);
        Ok((cmd, output.offset()))
    }

    // =========================================================================
    // Command frame builders for TNC configuration
    // =========================================================================

    /// Build a KISS command frame: [FEND, command, value, FEND]
    pub fn command_frame(command: u8, value: u8) -> [u8; 4] {
        [FEND, command, value, FEND]
    }

    /// Build a preamble (TX delay) configuration frame.
    /// Value is preamble_ms / 10, clamped to 0-255.
    pub fn preamble_frame(preamble_ms: u32) -> [u8; 4] {
        let value = (preamble_ms / 10).min(255) as u8;
        Self::command_frame(CMD_TXDELAY, value)
    }

    /// Build a TX tail configuration frame.
    /// Value is txtail_ms / 10, clamped to 0-255.
    pub fn txtail_frame(txtail_ms: u32) -> [u8; 4] {
        let value = (txtail_ms / 10).min(255) as u8;
        Self::command_frame(CMD_TXTAIL, value)
    }

    /// Build a persistence configuration frame.
    pub fn persistence_frame(persistence: u8) -> [u8; 4] {
        Self::command_frame(CMD_P, persistence)
    }

    /// Build a slot time configuration frame.
    /// Value is slottime_ms / 10, clamped to 0-255.
    pub fn slottime_frame(slottime_ms: u32) -> [u8; 4] {
        let value = (slottime_ms / 10).min(255) as u8;
        Self::command_frame(CMD_SLOTTIME, value)
    }

    /// Build a flow control enable frame (CMD_READY + 0x01).
    pub fn flow_control_frame() -> [u8; 4] {
        Self::command_frame(CMD_READY, 0x01)
    }
}

// =============================================================================
// Streaming KISS parser
// =============================================================================

/// Result of feeding a byte to the streaming parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KissParseResult {
    /// No complete frame yet; keep feeding bytes.
    Pending,
    /// A complete data frame is available; call `take_frame()` or `frame_data()`.
    DataFrame,
    /// A CMD_READY flow control signal was received.
    ReadySignal,
    /// A non-data command frame was received.
    CommandFrame(u8),
}

/// Byte-at-a-time KISS stream parser.
///
/// Mirrors the Python `KISSInterface.readLoop()` state machine:
/// - Tracks `in_frame`, `escape`, and `command` state
/// - Strips the port nibble from the command byte
/// - Returns `KissParseResult` on each byte fed
///
/// The caller is responsible for tracking the 100ms timeout and calling
/// `reset()` when no data has been received for that duration.
pub struct KissStreamParser {
    /// Accumulated payload bytes (data frames only)
    buffer: Vec<u8>,
    /// Maximum payload size (HW_MTU, typically 564)
    max_size: usize,
    /// True while inside a FEND-delimited frame
    in_frame: bool,
    /// True when FESC has been seen and next byte is escaped
    escape: bool,
    /// Parsed command byte (CMD_UNKNOWN until first byte after FEND)
    command: u8,
}

impl KissStreamParser {
    /// Create a new parser with default max_size of 564 (Reticulum HW_MTU).
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(564),
            max_size: 564,
            in_frame: false,
            escape: false,
            command: CMD_UNKNOWN,
        }
    }

    /// Create a new parser with a custom max payload size.
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(max_size),
            max_size,
            in_frame: false,
            escape: false,
            command: CMD_UNKNOWN,
        }
    }

    /// Feed a single byte into the parser.
    ///
    /// Returns the parse result indicating whether a complete frame,
    /// a flow-control signal, or a command was received.
    pub fn feed(&mut self, byte: u8) -> KissParseResult {
        // Check for end of data frame: in_frame, got FEND, and command is CMD_DATA
        if self.in_frame && byte == FEND && self.command == CMD_DATA {
            self.in_frame = false;
            return KissParseResult::DataFrame;
        }

        // FEND starts a new frame (or resets current state if not a data end)
        if byte == FEND {
            self.in_frame = true;
            self.command = CMD_UNKNOWN;
            self.buffer.clear();
            self.escape = false;
            return KissParseResult::Pending;
        }

        // Only process bytes while in a frame and under the size limit
        if self.in_frame && self.buffer.len() < self.max_size {
            // First byte after FEND is the command byte
            if self.buffer.is_empty() && self.command == CMD_UNKNOWN {
                // Strip port nibble (upper 4 bits)
                self.command = byte & 0x0F;

                if self.command == CMD_DATA {
                    // Data frame — continue accumulating bytes
                    return KissParseResult::Pending;
                } else if self.command == CMD_READY {
                    self.in_frame = false;
                    return KissParseResult::ReadySignal;
                } else {
                    // Other command frame
                    let cmd = self.command;
                    self.in_frame = false;
                    return KissParseResult::CommandFrame(cmd);
                }
            }

            // Data accumulation with KISS escape handling
            if self.command == CMD_DATA {
                if self.escape {
                    self.escape = false;
                    let decoded = match byte {
                        TFEND => FEND,
                        TFESC => FESC,
                        _ => byte,
                    };
                    self.buffer.push(decoded);
                } else if byte == FESC {
                    self.escape = true;
                } else {
                    self.buffer.push(byte);
                }
            }
        }

        KissParseResult::Pending
    }

    /// Take the completed frame data, leaving the parser buffer empty.
    pub fn take_frame(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }

    /// Borrow the current frame data.
    pub fn frame_data(&self) -> &[u8] {
        &self.buffer
    }

    /// Reset parser state. Called by the consumer after a timeout (e.g., 100ms
    /// of no data) to prevent hung frames from corrupted data.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.in_frame = false;
        self.escape = false;
        self.command = CMD_UNKNOWN;
    }

    /// Returns true if currently inside a frame.
    pub fn in_frame(&self) -> bool {
        self.in_frame
    }

    /// Returns true if the buffer contains data.
    pub fn has_data(&self) -> bool {
        !self.buffer.is_empty()
    }
}

impl Default for KissStreamParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod encode {
        use super::*;

        #[test]
        fn test_encode_empty_data() {
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::encode(&[], &mut output).unwrap();
            // Empty data: [FEND, CMD_DATA, FEND]
            assert_eq!(len, 3);
            assert_eq!(&buf[..len], &[FEND, CMD_DATA, FEND]);
        }

        #[test]
        fn test_encode_no_special_bytes() {
            let data = [0x01, 0x02, 0x03, 0x04];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::encode(&data, &mut output).unwrap();
            // [FEND, CMD_DATA, 0x01, 0x02, 0x03, 0x04, FEND]
            assert_eq!(len, 7);
            assert_eq!(&buf[..len], &[FEND, CMD_DATA, 0x01, 0x02, 0x03, 0x04, FEND]);
        }

        #[test]
        fn test_encode_escapes_fend() {
            let data = [FEND];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::encode(&data, &mut output).unwrap();
            // [FEND, CMD_DATA, FESC, TFEND, FEND]
            assert_eq!(len, 5);
            assert_eq!(&buf[..len], &[FEND, CMD_DATA, FESC, TFEND, FEND]);
        }

        #[test]
        fn test_encode_escapes_fesc() {
            let data = [FESC];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::encode(&data, &mut output).unwrap();
            // [FEND, CMD_DATA, FESC, TFESC, FEND]
            assert_eq!(len, 5);
            assert_eq!(&buf[..len], &[FEND, CMD_DATA, FESC, TFESC, FEND]);
        }

        #[test]
        fn test_encode_multiple_special_bytes() {
            let data = [FEND, 0x01, FESC, 0x02, FEND];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::encode(&data, &mut output).unwrap();
            let expected = [
                FEND, CMD_DATA,
                FESC, TFEND,  // escaped FEND
                0x01,
                FESC, TFESC,  // escaped FESC
                0x02,
                FESC, TFEND,  // escaped FEND
                FEND,
            ];
            assert_eq!(len, expected.len());
            assert_eq!(&buf[..len], &expected);
        }

        #[test]
        fn test_encode_with_port() {
            let data = [0x01, 0x02];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::encode_with_port(&data, 3, &mut output).unwrap();
            // Port 3 << 4 | 0 = 0x30
            assert_eq!(&buf[..len], &[FEND, 0x30, 0x01, 0x02, FEND]);
        }
    }

    mod find {
        use super::*;

        #[test]
        fn test_find_no_fend() {
            let data = [0x01, 0x02, 0x03, 0x04];
            assert!(Kiss::find(&data).is_none());
        }

        #[test]
        fn test_find_single_fend() {
            let data = [FEND, 0x01, 0x02];
            assert!(Kiss::find(&data).is_none());
        }

        #[test]
        fn test_find_complete_frame() {
            let data = [FEND, CMD_DATA, 0x01, 0x02, FEND];
            let result = Kiss::find(&data);
            assert_eq!(result, Some((0, 4)));
        }

        #[test]
        fn test_find_frame_with_prefix() {
            let data = [0x01, 0x02, FEND, CMD_DATA, 0x03, FEND, 0x04];
            let result = Kiss::find(&data);
            assert_eq!(result, Some((2, 5)));
        }

        #[test]
        fn test_find_empty_data() {
            assert!(Kiss::find(&[]).is_none());
        }
    }

    mod decode {
        use super::*;

        #[test]
        fn test_decode_incomplete_frame() {
            let data = [FEND, CMD_DATA, 0x01, 0x02]; // no closing FEND
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let result = Kiss::decode(&data, &mut output);
            assert!(result.is_err());
        }

        #[test]
        fn test_decode_empty_frame() {
            let data = [FEND, CMD_DATA, FEND];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::decode(&data, &mut output).unwrap();
            assert_eq!(len, 0);
        }

        #[test]
        fn test_decode_no_escapes() {
            let data = [FEND, CMD_DATA, 0x01, 0x02, 0x03, FEND];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::decode(&data, &mut output).unwrap();
            assert_eq!(len, 3);
            assert_eq!(&buf[..len], &[0x01, 0x02, 0x03]);
        }

        #[test]
        fn test_decode_escaped_fend() {
            let data = [FEND, CMD_DATA, FESC, TFEND, FEND];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::decode(&data, &mut output).unwrap();
            assert_eq!(len, 1);
            assert_eq!(buf[0], FEND);
        }

        #[test]
        fn test_decode_escaped_fesc() {
            let data = [FEND, CMD_DATA, FESC, TFESC, FEND];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::decode(&data, &mut output).unwrap();
            assert_eq!(len, 1);
            assert_eq!(buf[0], FESC);
        }

        #[test]
        fn test_decode_mixed_content() {
            // Data: 0x01, FEND, 0x02, FESC, 0x03
            let data = [
                FEND, CMD_DATA,
                0x01,
                FESC, TFEND,
                0x02,
                FESC, TFESC,
                0x03,
                FEND,
            ];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Kiss::decode(&data, &mut output).unwrap();
            assert_eq!(len, 5);
            assert_eq!(&buf[..len], &[0x01, FEND, 0x02, FESC, 0x03]);
        }

        #[test]
        fn test_decode_with_command() {
            // Port 3 << 4 | CMD_DATA = 0x30; after nibble masking should be 0x00
            let data = [FEND, 0x30, 0x01, 0x02, FEND];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let (cmd, len) = Kiss::decode_with_command(&data, &mut output).unwrap();
            assert_eq!(cmd, CMD_DATA); // Port nibble stripped
            assert_eq!(len, 2);
            assert_eq!(&buf[..len], &[0x01, 0x02]);
        }
    }

    mod round_trip {
        use super::*;

        #[test]
        fn test_round_trip_simple_data() {
            let original = [0x01, 0x02, 0x03, 0x04, 0x05];

            // Encode
            let mut encode_buf = [0u8; 64];
            let mut encode_output = OutputBuffer::new(&mut encode_buf);
            let encoded_len = Kiss::encode(&original, &mut encode_output).unwrap();

            // Decode
            let mut decode_buf = [0u8; 64];
            let mut decode_output = OutputBuffer::new(&mut decode_buf);
            let decoded_len = Kiss::decode(&encode_buf[..encoded_len], &mut decode_output).unwrap();

            assert_eq!(decoded_len, original.len());
            assert_eq!(&decode_buf[..decoded_len], &original);
        }

        #[test]
        fn test_round_trip_with_special_bytes() {
            let original = [FEND, 0x42, FESC, 0x43];

            // Encode
            let mut encode_buf = [0u8; 64];
            let mut encode_output = OutputBuffer::new(&mut encode_buf);
            let encoded_len = Kiss::encode(&original, &mut encode_output).unwrap();

            // Decode
            let mut decode_buf = [0u8; 64];
            let mut decode_output = OutputBuffer::new(&mut decode_buf);
            let decoded_len = Kiss::decode(&encode_buf[..encoded_len], &mut decode_output).unwrap();

            assert_eq!(decoded_len, original.len());
            assert_eq!(&decode_buf[..decoded_len], &original);
        }

        #[test]
        fn test_round_trip_all_special_bytes() {
            let original = [FEND, FESC, FEND, FESC];

            // Encode
            let mut encode_buf = [0u8; 64];
            let mut encode_output = OutputBuffer::new(&mut encode_buf);
            let encoded_len = Kiss::encode(&original, &mut encode_output).unwrap();

            // Decode
            let mut decode_buf = [0u8; 64];
            let mut decode_output = OutputBuffer::new(&mut decode_buf);
            let decoded_len = Kiss::decode(&encode_buf[..encoded_len], &mut decode_output).unwrap();

            assert_eq!(decoded_len, original.len());
            assert_eq!(&decode_buf[..decoded_len], &original);
        }

        #[test]
        fn test_round_trip_empty_data() {
            let original: [u8; 0] = [];

            // Encode
            let mut encode_buf = [0u8; 64];
            let mut encode_output = OutputBuffer::new(&mut encode_buf);
            let encoded_len = Kiss::encode(&original, &mut encode_output).unwrap();

            // Decode
            let mut decode_buf = [0u8; 64];
            let mut decode_output = OutputBuffer::new(&mut decode_buf);
            let decoded_len = Kiss::decode(&encode_buf[..encoded_len], &mut decode_output).unwrap();

            assert_eq!(decoded_len, 0);
        }
    }

    mod command_frames {
        use super::*;

        #[test]
        fn test_command_frame_layout() {
            let frame = Kiss::command_frame(CMD_TXDELAY, 35);
            assert_eq!(frame, [FEND, CMD_TXDELAY, 35, FEND]);
        }

        #[test]
        fn test_preamble_frame() {
            // 350ms / 10 = 35
            let frame = Kiss::preamble_frame(350);
            assert_eq!(frame, [FEND, CMD_TXDELAY, 35, FEND]);
        }

        #[test]
        fn test_preamble_frame_clamped() {
            // 3000ms / 10 = 300, clamped to 255
            let frame = Kiss::preamble_frame(3000);
            assert_eq!(frame, [FEND, CMD_TXDELAY, 255, FEND]);
        }

        #[test]
        fn test_txtail_frame() {
            // 20ms / 10 = 2
            let frame = Kiss::txtail_frame(20);
            assert_eq!(frame, [FEND, CMD_TXTAIL, 2, FEND]);
        }

        #[test]
        fn test_persistence_frame() {
            let frame = Kiss::persistence_frame(64);
            assert_eq!(frame, [FEND, CMD_P, 64, FEND]);
        }

        #[test]
        fn test_slottime_frame() {
            // 20ms / 10 = 2
            let frame = Kiss::slottime_frame(20);
            assert_eq!(frame, [FEND, CMD_SLOTTIME, 2, FEND]);
        }

        #[test]
        fn test_flow_control_frame() {
            let frame = Kiss::flow_control_frame();
            assert_eq!(frame, [FEND, CMD_READY, 0x01, FEND]);
        }
    }

    mod stream_parser {
        use super::*;

        /// Helper: feed an entire byte sequence and collect results
        fn feed_all(parser: &mut KissStreamParser, data: &[u8]) -> Vec<KissParseResult> {
            data.iter().map(|&b| parser.feed(b)).collect()
        }

        #[test]
        fn test_simple_data_frame() {
            let mut parser = KissStreamParser::new();
            // FEND, CMD_DATA, 0x01, 0x02, 0x03, FEND
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_DATA), KissParseResult::Pending);
            assert_eq!(parser.feed(0x01), KissParseResult::Pending);
            assert_eq!(parser.feed(0x02), KissParseResult::Pending);
            assert_eq!(parser.feed(0x03), KissParseResult::Pending);
            assert_eq!(parser.feed(FEND), KissParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[0x01, 0x02, 0x03]);
        }

        #[test]
        fn test_escaped_bytes() {
            let mut parser = KissStreamParser::new();
            // FEND, CMD_DATA, FESC, TFEND, FESC, TFESC, FEND
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_DATA), KissParseResult::Pending);
            assert_eq!(parser.feed(FESC), KissParseResult::Pending);
            assert_eq!(parser.feed(TFEND), KissParseResult::Pending);
            assert_eq!(parser.feed(FESC), KissParseResult::Pending);
            assert_eq!(parser.feed(TFESC), KissParseResult::Pending);
            assert_eq!(parser.feed(FEND), KissParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[FEND, FESC]);
        }

        #[test]
        fn test_port_nibble_stripping() {
            let mut parser = KissStreamParser::new();
            // Port 3 << 4 | CMD_DATA = 0x30
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(0x30), KissParseResult::Pending); // port nibble stripped
            assert_eq!(parser.feed(0xAB), KissParseResult::Pending);
            assert_eq!(parser.feed(FEND), KissParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[0xAB]);
        }

        #[test]
        fn test_ready_signal() {
            let mut parser = KissStreamParser::new();
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_READY), KissParseResult::ReadySignal);
        }

        #[test]
        fn test_command_frame() {
            let mut parser = KissStreamParser::new();
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_TXDELAY), KissParseResult::CommandFrame(CMD_TXDELAY));
        }

        #[test]
        fn test_garbage_before_frame() {
            let mut parser = KissStreamParser::new();
            // Garbage bytes before the frame should be ignored
            assert_eq!(parser.feed(0xFF), KissParseResult::Pending);
            assert_eq!(parser.feed(0xAA), KissParseResult::Pending);
            // Now a real frame
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_DATA), KissParseResult::Pending);
            assert_eq!(parser.feed(0x42), KissParseResult::Pending);
            assert_eq!(parser.feed(FEND), KissParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[0x42]);
        }

        #[test]
        fn test_consecutive_frames() {
            let mut parser = KissStreamParser::new();
            // First frame
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_DATA), KissParseResult::Pending);
            assert_eq!(parser.feed(0x01), KissParseResult::Pending);
            assert_eq!(parser.feed(FEND), KissParseResult::DataFrame);
            let frame1 = parser.take_frame();
            assert_eq!(frame1, vec![0x01]);

            // Second frame
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_DATA), KissParseResult::Pending);
            assert_eq!(parser.feed(0x02), KissParseResult::Pending);
            assert_eq!(parser.feed(FEND), KissParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[0x02]);
        }

        #[test]
        fn test_empty_data_frame() {
            let mut parser = KissStreamParser::new();
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_DATA), KissParseResult::Pending);
            assert_eq!(parser.feed(FEND), KissParseResult::DataFrame);
            assert!(parser.frame_data().is_empty());
        }

        #[test]
        fn test_max_size_enforcement() {
            let mut parser = KissStreamParser::with_max_size(3);
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_DATA), KissParseResult::Pending);
            // Feed 5 bytes — only 3 should be accepted
            for i in 0..5u8 {
                parser.feed(i);
            }
            assert_eq!(parser.feed(FEND), KissParseResult::DataFrame);
            assert_eq!(parser.frame_data().len(), 3);
            assert_eq!(parser.frame_data(), &[0, 1, 2]);
        }

        #[test]
        fn test_timeout_reset() {
            let mut parser = KissStreamParser::new();
            // Start a frame
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_DATA), KissParseResult::Pending);
            assert_eq!(parser.feed(0x01), KissParseResult::Pending);
            assert!(parser.in_frame());
            assert!(parser.has_data());

            // Simulate timeout
            parser.reset();
            assert!(!parser.in_frame());
            assert!(!parser.has_data());

            // Should be able to parse a new frame cleanly
            assert_eq!(parser.feed(FEND), KissParseResult::Pending);
            assert_eq!(parser.feed(CMD_DATA), KissParseResult::Pending);
            assert_eq!(parser.feed(0x02), KissParseResult::Pending);
            assert_eq!(parser.feed(FEND), KissParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[0x02]);
        }

        #[test]
        fn test_take_frame_clears_buffer() {
            let mut parser = KissStreamParser::new();
            feed_all(&mut parser, &[FEND, CMD_DATA, 0x01, 0x02, FEND]);
            let frame = parser.take_frame();
            assert_eq!(frame, vec![0x01, 0x02]);
            assert!(parser.frame_data().is_empty());
        }
    }
}
