use crate::{buffer::OutputBuffer, error::RnsError};

const HDLC_FRAME_FLAG: u8 = 0x7e;
const HDLC_ESCAPE_BYTE: u8 = 0x7d;
const HDLC_ESCAPE_MASK: u8 = 0b00100000;

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
            return Err(RnsError::OutOfMemory);
        }

        Ok(output.offset())
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
}
