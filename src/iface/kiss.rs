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
            return Err(RnsError::OutOfMemory);
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
                                command_byte = Some(byte);
                            } else {
                                output.write_byte(byte)?;
                            }
                        }
                    }
                }
            }
        }

        if !finished {
            return Err(RnsError::OutOfMemory);
        }

        let cmd = command_byte.unwrap_or(CMD_DATA);
        Ok((cmd, output.offset()))
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
            let data = [FEND, 0x30, 0x01, 0x02, FEND]; // Port 3
            let mut buf = [0u8; 64];
            let mut output = OutputBuffer::new(&mut buf);
            let (cmd, len) = Kiss::decode_with_command(&data, &mut output).unwrap();
            assert_eq!(cmd, 0x30);
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
}
