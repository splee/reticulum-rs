use crate::{buffer::OutputBuffer, error::RnsError};

const HDLC_FRAME_FLAG: u8 = 0x7e;
const HDLC_ESCAPE_BYTE: u8 = 0x7d;
const HDLC_ESCAPE_MASK: u8 = 0b00100000;

/// Minimum decoded payload size for a valid Reticulum frame.
/// Frames smaller than this are silently discarded by consumers.
pub const MIN_FRAME_PAYLOAD: usize = 2;

pub struct Hdlc {}

impl Hdlc {
    pub fn encode(data: &[u8], buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write_byte(HDLC_FRAME_FLAG)?;

        for &byte in data {
            match byte {
                HDLC_FRAME_FLAG | HDLC_ESCAPE_BYTE => {
                    buffer.write(&[HDLC_ESCAPE_BYTE, byte ^ HDLC_ESCAPE_MASK])?;
                }
                _ => {
                    buffer.write_byte(byte)?;
                }
            }
        }

        buffer.write_byte(HDLC_FRAME_FLAG)?;

        Ok(buffer.offset())
    }

    /// Returns start and end index of HDLC frame or None
    pub fn find(data: &[u8]) -> Option<(usize, usize)> {
        let mut start = false;
        let mut end = false;

        let mut start_index: usize = 0;
        let mut end_index: usize = 0;

        for (i, &byte) in data.iter().enumerate() {
            // Search for HDLC frame flags only
            if byte != HDLC_FRAME_FLAG {
                continue;
            }

            // Find start of HDLC frame
            if !start {
                start_index = i;
                start = true;
            }
            // Find end of HDLC frame
            else if !end {
                end_index = i;
                end = true;
            }

            if start && end {
                return Option::Some((start_index, end_index));
            }
        }

        Option::None
    }

    /// Find all complete HDLC frames in the buffer.
    /// Returns Vec of (start, end) index pairs.
    pub fn find_all(data: &[u8]) -> Vec<(usize, usize)> {
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            if let Some((start, end)) = Self::find(&data[offset..]) {
                frames.push((offset + start, offset + end));
                offset += end + 1;
            } else {
                break;
            }
        }
        frames
    }

    pub fn decode(data: &[u8], output: &mut OutputBuffer) -> Result<usize, RnsError> {
        let mut started = false;
        let mut finished = false;
        let mut escape = false;

        for &byte in data {
            if escape {
                escape = false;
                output.write_byte(byte ^ HDLC_ESCAPE_MASK)?;
            } else {
                match byte {
                    HDLC_FRAME_FLAG => {
                        if started {
                            finished = true;
                            break;
                        }

                        started = true;
                    }
                    HDLC_ESCAPE_BYTE => {
                        escape = true;
                    }
                    _ => {
                        output.write_byte(byte)?;
                    }
                }
            }
        }

        if !finished {
            return Err(RnsError::FramingError);
        }

        Ok(output.offset())
    }
}

// =============================================================================
// Streaming HDLC parser
// =============================================================================

/// Result of feeding a byte to the HDLC streaming parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdlcParseResult {
    /// No complete frame yet; keep feeding bytes.
    Pending,
    /// A complete HDLC frame is available; call `take_frame()` or `frame_data()`.
    DataFrame,
}

/// Byte-at-a-time HDLC stream parser for serial interfaces.
///
/// Mirrors the Python `SerialInterface.readLoop()` state machine:
/// - Tracks `in_frame` and `escape` state
/// - Uses 0x7E as frame flag and 0x7D as escape byte
/// - Returns `HdlcParseResult` on each byte fed
///
/// The caller is responsible for tracking the 100ms timeout and calling
/// `reset()` when no data has been received for that duration.
pub struct HdlcStreamParser {
    /// Accumulated payload bytes
    buffer: Vec<u8>,
    /// Maximum payload size (HW_MTU, typically 564)
    max_size: usize,
    /// True while inside a FLAG-delimited frame
    in_frame: bool,
    /// True when ESC has been seen and next byte is escaped
    escape: bool,
}

impl HdlcStreamParser {
    /// Create a new parser with default max_size of 564 (Reticulum HW_MTU).
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(564),
            max_size: 564,
            in_frame: false,
            escape: false,
        }
    }

    /// Create a new parser with a custom max payload size.
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(max_size),
            max_size,
            in_frame: false,
            escape: false,
        }
    }

    /// Feed a single byte into the parser.
    ///
    /// State machine (matches Python `SerialInterface.readLoop()`):
    /// 1. FLAG while not in_frame → start frame, clear buffer
    /// 2. FLAG while in_frame → end frame, return DataFrame
    /// 3. ESC while in_frame → set escape flag
    /// 4. Any byte after ESC → push byte ^ ESC_MASK, clear escape
    /// 5. Normal byte while in_frame and under max_size → push to buffer
    /// 6. Bytes after max_size → silently dropped
    pub fn feed(&mut self, byte: u8) -> HdlcParseResult {
        if byte == HDLC_FRAME_FLAG {
            if self.in_frame {
                // End of frame
                self.in_frame = false;
                self.escape = false;
                return HdlcParseResult::DataFrame;
            } else {
                // Start of frame
                self.in_frame = true;
                self.buffer.clear();
                self.escape = false;
                return HdlcParseResult::Pending;
            }
        }

        if self.in_frame {
            if self.escape {
                self.escape = false;
                if self.buffer.len() < self.max_size {
                    self.buffer.push(byte ^ HDLC_ESCAPE_MASK);
                }
            } else if byte == HDLC_ESCAPE_BYTE {
                self.escape = true;
            } else if self.buffer.len() < self.max_size {
                self.buffer.push(byte);
            }
        }

        HdlcParseResult::Pending
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

impl Default for HdlcStreamParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for HDLC frame encoding.
    mod encode {
        use super::*;

        #[test]
        fn test_encode_empty_data() {
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Hdlc::encode(&[], &mut output).unwrap();
            // Empty data should produce: [FLAG, FLAG]
            assert_eq!(len, 2);
            assert_eq!(&buf[..len], &[HDLC_FRAME_FLAG, HDLC_FRAME_FLAG]);
        }

        #[test]
        fn test_encode_no_special_bytes() {
            let data = [0x01, 0x02, 0x03, 0x04];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Hdlc::encode(&data, &mut output).unwrap();
            // No escaping needed: [FLAG, 0x01, 0x02, 0x03, 0x04, FLAG]
            assert_eq!(len, 6);
            assert_eq!(&buf[..len], &[HDLC_FRAME_FLAG, 0x01, 0x02, 0x03, 0x04, HDLC_FRAME_FLAG]);
        }

        #[test]
        fn test_encode_escapes_frame_flag() {
            // 0x7e (HDLC_FRAME_FLAG) must be escaped
            let data = [HDLC_FRAME_FLAG];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Hdlc::encode(&data, &mut output).unwrap();
            // Escaped: [FLAG, ESCAPE, 0x7e ^ 0x20, FLAG] = [0x7e, 0x7d, 0x5e, 0x7e]
            assert_eq!(len, 4);
            assert_eq!(&buf[..len], &[HDLC_FRAME_FLAG, HDLC_ESCAPE_BYTE, 0x5e, HDLC_FRAME_FLAG]);
        }

        #[test]
        fn test_encode_escapes_escape_byte() {
            // 0x7d (HDLC_ESCAPE_BYTE) must be escaped
            let data = [HDLC_ESCAPE_BYTE];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Hdlc::encode(&data, &mut output).unwrap();
            // Escaped: [FLAG, ESCAPE, 0x7d ^ 0x20, FLAG] = [0x7e, 0x7d, 0x5d, 0x7e]
            assert_eq!(len, 4);
            assert_eq!(&buf[..len], &[HDLC_FRAME_FLAG, HDLC_ESCAPE_BYTE, 0x5d, HDLC_FRAME_FLAG]);
        }

        #[test]
        fn test_encode_multiple_special_bytes() {
            let data = [HDLC_FRAME_FLAG, 0x01, HDLC_ESCAPE_BYTE, 0x02, HDLC_FRAME_FLAG];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Hdlc::encode(&data, &mut output).unwrap();
            // Expected: [FLAG, ESC, 0x5e, 0x01, ESC, 0x5d, 0x02, ESC, 0x5e, FLAG]
            assert_eq!(len, 10);
            let expected = [
                HDLC_FRAME_FLAG,
                HDLC_ESCAPE_BYTE, 0x5e,       // escaped 0x7e
                0x01,
                HDLC_ESCAPE_BYTE, 0x5d,       // escaped 0x7d
                0x02,
                HDLC_ESCAPE_BYTE, 0x5e,       // escaped 0x7e
                HDLC_FRAME_FLAG,
            ];
            assert_eq!(&buf[..len], &expected);
        }

        #[test]
        fn test_encode_buffer_overflow() {
            let data = [0x01, 0x02, 0x03, 0x04, 0x05];
            // Buffer too small for: FLAG + 5 bytes + FLAG = 7 bytes
            let mut buf = [0u8; 5];
            let mut output = OutputBuffer::new(&mut buf);
            let result = Hdlc::encode(&data, &mut output);
            assert!(result.is_err());
        }
    }

    /// Tests for HDLC frame finding.
    mod find {
        use super::*;

        #[test]
        fn test_find_no_flags() {
            let data = [0x01, 0x02, 0x03, 0x04];
            assert!(Hdlc::find(&data).is_none());
        }

        #[test]
        fn test_find_single_flag_incomplete() {
            let data = [HDLC_FRAME_FLAG, 0x01, 0x02];
            assert!(Hdlc::find(&data).is_none());
        }

        #[test]
        fn test_find_complete_frame() {
            let data = [HDLC_FRAME_FLAG, 0x01, 0x02, HDLC_FRAME_FLAG];
            let result = Hdlc::find(&data);
            assert_eq!(result, Some((0, 3)));
        }

        #[test]
        fn test_find_frame_with_prefix() {
            // Frame flags not at the start
            let data = [0x01, 0x02, HDLC_FRAME_FLAG, 0x03, HDLC_FRAME_FLAG, 0x04];
            let result = Hdlc::find(&data);
            assert_eq!(result, Some((2, 4)));
        }

        #[test]
        fn test_find_multiple_frames_returns_first() {
            let data = [
                HDLC_FRAME_FLAG, 0x01, HDLC_FRAME_FLAG,  // first frame
                HDLC_FRAME_FLAG, 0x02, HDLC_FRAME_FLAG,  // second frame
            ];
            let result = Hdlc::find(&data);
            // Should return first complete frame
            assert_eq!(result, Some((0, 2)));
        }

        #[test]
        fn test_find_consecutive_flags() {
            // Two adjacent flags form an empty frame
            let data = [HDLC_FRAME_FLAG, HDLC_FRAME_FLAG];
            let result = Hdlc::find(&data);
            assert_eq!(result, Some((0, 1)));
        }

        #[test]
        fn test_find_empty_data() {
            assert!(Hdlc::find(&[]).is_none());
        }
    }

    /// Tests for finding all HDLC frames in a buffer.
    mod find_all {
        use super::*;

        #[test]
        fn test_find_all_single_frame() {
            let data = [HDLC_FRAME_FLAG, 0x01, 0x02, HDLC_FRAME_FLAG];
            let frames = Hdlc::find_all(&data);
            assert_eq!(frames, vec![(0, 3)]);
        }

        #[test]
        fn test_find_all_multiple_frames() {
            let data = [
                HDLC_FRAME_FLAG, 0x01, HDLC_FRAME_FLAG,  // frame 1
                HDLC_FRAME_FLAG, 0x02, HDLC_FRAME_FLAG,  // frame 2
            ];
            let frames = Hdlc::find_all(&data);
            assert_eq!(frames, vec![(0, 2), (3, 5)]);
        }

        #[test]
        fn test_find_all_no_frames() {
            let data = [0x01, 0x02, 0x03];
            let frames = Hdlc::find_all(&data);
            assert!(frames.is_empty());
        }

        #[test]
        fn test_find_all_garbage_between_frames() {
            let data = [
                HDLC_FRAME_FLAG, 0x01, HDLC_FRAME_FLAG,  // frame 1
                0xFF, 0xFE,                                // garbage
                HDLC_FRAME_FLAG, 0x02, HDLC_FRAME_FLAG,  // frame 2
            ];
            let frames = Hdlc::find_all(&data);
            assert_eq!(frames, vec![(0, 2), (5, 7)]);
        }

        #[test]
        fn test_find_all_empty_data() {
            let frames = Hdlc::find_all(&[]);
            assert!(frames.is_empty());
        }
    }

    /// Tests for HDLC frame decoding.
    mod decode {
        use super::*;

        #[test]
        fn test_decode_incomplete_frame() {
            let data = [HDLC_FRAME_FLAG, 0x01, 0x02]; // no closing flag
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let result = Hdlc::decode(&data, &mut output);
            assert!(result.is_err());
        }

        #[test]
        fn test_decode_empty_frame() {
            let data = [HDLC_FRAME_FLAG, HDLC_FRAME_FLAG];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Hdlc::decode(&data, &mut output).unwrap();
            assert_eq!(len, 0);
        }

        #[test]
        fn test_decode_no_escapes() {
            let data = [HDLC_FRAME_FLAG, 0x01, 0x02, 0x03, HDLC_FRAME_FLAG];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Hdlc::decode(&data, &mut output).unwrap();
            assert_eq!(len, 3);
            assert_eq!(&buf[..len], &[0x01, 0x02, 0x03]);
        }

        #[test]
        fn test_decode_escaped_frame_flag() {
            // Encoded 0x7e: [ESCAPE, 0x5e]
            let data = [HDLC_FRAME_FLAG, HDLC_ESCAPE_BYTE, 0x5e, HDLC_FRAME_FLAG];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Hdlc::decode(&data, &mut output).unwrap();
            assert_eq!(len, 1);
            assert_eq!(buf[0], HDLC_FRAME_FLAG);
        }

        #[test]
        fn test_decode_escaped_escape_byte() {
            // Encoded 0x7d: [ESCAPE, 0x5d]
            let data = [HDLC_FRAME_FLAG, HDLC_ESCAPE_BYTE, 0x5d, HDLC_FRAME_FLAG];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Hdlc::decode(&data, &mut output).unwrap();
            assert_eq!(len, 1);
            assert_eq!(buf[0], HDLC_ESCAPE_BYTE);
        }

        #[test]
        fn test_decode_mixed_content() {
            // Data: 0x01, 0x7e, 0x02, 0x7d, 0x03
            // Encoded: [FLAG, 0x01, ESC, 0x5e, 0x02, ESC, 0x5d, 0x03, FLAG]
            let data = [
                HDLC_FRAME_FLAG,
                0x01,
                HDLC_ESCAPE_BYTE, 0x5e,
                0x02,
                HDLC_ESCAPE_BYTE, 0x5d,
                0x03,
                HDLC_FRAME_FLAG,
            ];
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let len = Hdlc::decode(&data, &mut output).unwrap();
            assert_eq!(len, 5);
            assert_eq!(&buf[..len], &[0x01, HDLC_FRAME_FLAG, 0x02, HDLC_ESCAPE_BYTE, 0x03]);
        }
    }

    /// Round-trip tests: encode then decode should preserve data.
    mod round_trip {
        use super::*;

        #[test]
        fn test_round_trip_simple_data() {
            let original = [0x01, 0x02, 0x03, 0x04, 0x05];

            // Encode
            let mut encode_buf = [0u8; 64];
            let mut encode_output = OutputBuffer::new(&mut encode_buf);
            let encoded_len = Hdlc::encode(&original, &mut encode_output).unwrap();

            // Decode
            let mut decode_buf = [0u8; 64];
            let mut decode_output = OutputBuffer::new(&mut decode_buf);
            let decoded_len = Hdlc::decode(&encode_buf[..encoded_len], &mut decode_output).unwrap();

            assert_eq!(decoded_len, original.len());
            assert_eq!(&decode_buf[..decoded_len], &original);
        }

        #[test]
        fn test_round_trip_with_special_bytes() {
            // Data containing both special bytes
            let original = [HDLC_FRAME_FLAG, 0x42, HDLC_ESCAPE_BYTE, 0x43];

            // Encode
            let mut encode_buf = [0u8; 64];
            let mut encode_output = OutputBuffer::new(&mut encode_buf);
            let encoded_len = Hdlc::encode(&original, &mut encode_output).unwrap();

            // Decode
            let mut decode_buf = [0u8; 64];
            let mut decode_output = OutputBuffer::new(&mut decode_buf);
            let decoded_len = Hdlc::decode(&encode_buf[..encoded_len], &mut decode_output).unwrap();

            assert_eq!(decoded_len, original.len());
            assert_eq!(&decode_buf[..decoded_len], &original);
        }

        #[test]
        fn test_round_trip_all_special_bytes() {
            // Data of only special bytes
            let original = [HDLC_FRAME_FLAG, HDLC_ESCAPE_BYTE, HDLC_FRAME_FLAG, HDLC_ESCAPE_BYTE];

            // Encode
            let mut encode_buf = [0u8; 64];
            let mut encode_output = OutputBuffer::new(&mut encode_buf);
            let encoded_len = Hdlc::encode(&original, &mut encode_output).unwrap();

            // Decode
            let mut decode_buf = [0u8; 64];
            let mut decode_output = OutputBuffer::new(&mut decode_buf);
            let decoded_len = Hdlc::decode(&encode_buf[..encoded_len], &mut decode_output).unwrap();

            assert_eq!(decoded_len, original.len());
            assert_eq!(&decode_buf[..decoded_len], &original);
        }

        #[test]
        fn test_round_trip_empty_data() {
            let original: [u8; 0] = [];

            // Encode
            let mut encode_buf = [0u8; 64];
            let mut encode_output = OutputBuffer::new(&mut encode_buf);
            let encoded_len = Hdlc::encode(&original, &mut encode_output).unwrap();

            // Decode
            let mut decode_buf = [0u8; 64];
            let mut decode_output = OutputBuffer::new(&mut decode_buf);
            let decoded_len = Hdlc::decode(&encode_buf[..encoded_len], &mut decode_output).unwrap();

            assert_eq!(decoded_len, 0);
        }
    }

    mod stream_parser {
        use super::*;

        #[test]
        fn test_simple_data_frame() {
            let mut parser = HdlcStreamParser::new();
            // FLAG, payload, FLAG
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0x01), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0x02), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0x03), HdlcParseResult::Pending);
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[0x01, 0x02, 0x03]);
        }

        #[test]
        fn test_escaped_bytes() {
            let mut parser = HdlcStreamParser::new();
            // FLAG, ESC 0x5E (=FLAG), ESC 0x5D (=ESC), FLAG
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::Pending);
            assert_eq!(parser.feed(HDLC_ESCAPE_BYTE), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0x5e), HdlcParseResult::Pending); // FLAG ^ MASK
            assert_eq!(parser.feed(HDLC_ESCAPE_BYTE), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0x5d), HdlcParseResult::Pending); // ESC ^ MASK
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[HDLC_FRAME_FLAG, HDLC_ESCAPE_BYTE]);
        }

        #[test]
        fn test_garbage_before_frame() {
            let mut parser = HdlcStreamParser::new();
            // Garbage before frame should be ignored
            assert_eq!(parser.feed(0xFF), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0xAA), HdlcParseResult::Pending);
            // Now a real frame
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0x42), HdlcParseResult::Pending);
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[0x42]);
        }

        #[test]
        fn test_consecutive_frames() {
            let mut parser = HdlcStreamParser::new();
            // First frame
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0x01), HdlcParseResult::Pending);
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::DataFrame);
            let frame1 = parser.take_frame();
            assert_eq!(frame1, vec![0x01]);

            // Second frame
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0x02), HdlcParseResult::Pending);
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[0x02]);
        }

        #[test]
        fn test_empty_frame() {
            let mut parser = HdlcStreamParser::new();
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::Pending);
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::DataFrame);
            assert!(parser.frame_data().is_empty());
        }

        #[test]
        fn test_max_size_enforcement() {
            let mut parser = HdlcStreamParser::with_max_size(3);
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::Pending);
            // Feed 5 bytes — only 3 should be accepted
            for i in 0..5u8 {
                parser.feed(i);
            }
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::DataFrame);
            assert_eq!(parser.frame_data().len(), 3);
            assert_eq!(parser.frame_data(), &[0, 1, 2]);
        }

        #[test]
        fn test_timeout_reset() {
            let mut parser = HdlcStreamParser::new();
            // Start a frame
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0x01), HdlcParseResult::Pending);
            assert!(parser.in_frame());
            assert!(parser.has_data());

            // Simulate timeout
            parser.reset();
            assert!(!parser.in_frame());
            assert!(!parser.has_data());

            // Should parse a new frame cleanly
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::Pending);
            assert_eq!(parser.feed(0x02), HdlcParseResult::Pending);
            assert_eq!(parser.feed(HDLC_FRAME_FLAG), HdlcParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &[0x02]);
        }

        #[test]
        fn test_take_frame_clears_buffer() {
            let mut parser = HdlcStreamParser::new();
            for &b in &[HDLC_FRAME_FLAG, 0x01, 0x02, HDLC_FRAME_FLAG] {
                parser.feed(b);
            }
            let frame = parser.take_frame();
            assert_eq!(frame, vec![0x01, 0x02]);
            assert!(parser.frame_data().is_empty());
        }

        #[test]
        fn test_round_trip_with_encode() {
            // Encode some data with Hdlc::encode, then parse byte-by-byte
            let original = [0x01, HDLC_FRAME_FLAG, 0x42, HDLC_ESCAPE_BYTE, 0x03];
            let mut encode_buf = [0u8; 64];
            let mut encode_output = OutputBuffer::new(&mut encode_buf);
            let encoded_len = Hdlc::encode(&original, &mut encode_output).unwrap();

            let mut parser = HdlcStreamParser::new();
            let mut result = HdlcParseResult::Pending;
            for &byte in &encode_buf[..encoded_len] {
                result = parser.feed(byte);
            }
            assert_eq!(result, HdlcParseResult::DataFrame);
            assert_eq!(parser.frame_data(), &original);
        }

        #[test]
        fn test_default_trait() {
            let parser = HdlcStreamParser::default();
            assert!(!parser.in_frame());
            assert!(!parser.has_data());
        }
    }
}
