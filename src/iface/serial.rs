//! Serial interface implementation for Reticulum.
//!
//! This module provides serial port communication with HDLC framing
//! for interfacing with hardware devices.

use std::time::Duration;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::hash::AddressHash;
use crate::iface::hdlc::Hdlc;
use crate::iface::Interface;
use crate::packet::Packet;
use crate::serde::Serialize;

/// Default baud rate for serial interfaces
pub const DEFAULT_BAUD_RATE: u32 = 115200;

/// Default read timeout in milliseconds
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 100;

/// Maximum frame size
pub const MAX_FRAME_SIZE: usize = 2048;

/// Serial interface configuration
#[derive(Debug, Clone)]
pub struct SerialConfig {
    /// Serial port path (e.g., "/dev/ttyUSB0" or "COM3")
    pub port: String,
    /// Baud rate
    pub baud_rate: u32,
    /// Data bits (5, 6, 7, or 8)
    pub data_bits: u8,
    /// Stop bits (1 or 2)
    pub stop_bits: u8,
    /// Parity (none, odd, even)
    pub parity: Parity,
    /// Flow control
    pub flow_control: FlowControl,
    /// Read timeout
    pub read_timeout: Duration,
    /// Interface address hash
    pub address: AddressHash,
}

impl Default for SerialConfig {
    fn default() -> Self {
        Self {
            port: String::new(),
            baud_rate: DEFAULT_BAUD_RATE,
            data_bits: 8,
            stop_bits: 1,
            parity: Parity::None,
            flow_control: FlowControl::None,
            read_timeout: Duration::from_millis(DEFAULT_READ_TIMEOUT_MS),
            address: AddressHash::new([0u8; 16]),
        }
    }
}

impl SerialConfig {
    /// Create a new serial config with the given port
    pub fn new(port: &str) -> Self {
        Self {
            port: port.to_string(),
            ..Default::default()
        }
    }

    /// Set baud rate
    pub fn with_baud_rate(mut self, baud: u32) -> Self {
        self.baud_rate = baud;
        self
    }

    /// Set address
    pub fn with_address(mut self, address: AddressHash) -> Self {
        self.address = address;
        self
    }
}

/// Parity setting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum Parity {
    #[default]
    None,
    Odd,
    Even,
}


/// Flow control setting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum FlowControl {
    #[default]
    None,
    Hardware,
    Software,
}


/// Serial interface state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialState {
    /// Interface is not connected
    Disconnected,
    /// Interface is connecting
    Connecting,
    /// Interface is connected and ready
    Connected,
    /// Interface encountered an error
    Error,
}

/// Serial interface statistics
#[derive(Debug, Clone, Default)]
pub struct SerialStats {
    /// Packets transmitted
    pub tx_packets: u64,
    /// Packets received
    pub rx_packets: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Transmit errors
    pub tx_errors: u64,
    /// Receive errors
    pub rx_errors: u64,
    /// CRC errors
    pub crc_errors: u64,
}

/// Serial interface for hardware communication
pub struct SerialInterface {
    /// Configuration
    config: SerialConfig,
    /// Current state
    state: SerialState,
    /// Statistics
    stats: SerialStats,
}

impl SerialInterface {
    /// Create a new serial interface
    pub fn new(config: SerialConfig) -> Self {
        Self {
            config,
            state: SerialState::Disconnected,
            stats: SerialStats::default(),
        }
    }

    /// Get the current state
    pub fn state(&self) -> SerialState {
        self.state
    }

    /// Get statistics
    pub fn stats(&self) -> &SerialStats {
        &self.stats
    }

    /// Get the configuration
    pub fn config(&self) -> &SerialConfig {
        &self.config
    }

    /// Encode a packet for transmission
    pub fn encode_packet(&mut self, packet: &Packet) -> Result<Vec<u8>, RnsError> {
        let mut buffer = [0u8; MAX_FRAME_SIZE];
        let mut output = OutputBuffer::new(&mut buffer);

        packet.serialize(&mut output)?;
        let data_len = output.offset();

        // Now encode with HDLC
        let mut hdlc_buffer = [0u8; MAX_FRAME_SIZE * 2 + 4];
        let mut hdlc_output = OutputBuffer::new(&mut hdlc_buffer);
        let len = Hdlc::encode(&buffer[..data_len], &mut hdlc_output)?;

        Ok(hdlc_buffer[..len].to_vec())
    }

    /// Decode received data into a packet
    pub fn decode_packet(&mut self, data: &[u8]) -> Result<Option<Packet>, RnsError> {
        let mut decoded = [0u8; MAX_FRAME_SIZE];
        let mut output = OutputBuffer::new(&mut decoded);

        match Hdlc::decode(data, &mut output) {
            Ok(len) => {
                if len > 0 {
                    let mut buffer = InputBuffer::new(&decoded[..len]);
                    let packet = Packet::deserialize(&mut buffer)?;
                    Ok(Some(packet))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                self.stats.rx_errors += 1;
                Err(e)
            }
        }
    }

    /// Record a successful transmission
    pub fn record_tx(&mut self, bytes: usize) {
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += bytes as u64;
    }

    /// Record a successful reception
    pub fn record_rx(&mut self, bytes: usize) {
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += bytes as u64;
    }

    /// Record a transmit error
    pub fn record_tx_error(&mut self) {
        self.stats.tx_errors += 1;
    }

    /// Record a receive error
    pub fn record_rx_error(&mut self) {
        self.stats.rx_errors += 1;
    }

    /// Record a CRC error
    pub fn record_crc_error(&mut self) {
        self.stats.crc_errors += 1;
    }
}

impl Interface for SerialInterface {
    fn mtu() -> usize {
        564 // Reticulum serial MTU (matches Python implementation)
    }
}

/// KISS interface constants
pub mod kiss {
    /// KISS frame start/end marker
    pub const FEND: u8 = 0xC0;
    /// KISS frame escape
    pub const FESC: u8 = 0xDB;
    /// Escaped FEND
    pub const TFEND: u8 = 0xDC;
    /// Escaped FESC
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
    /// Return (exit KISS mode) command
    pub const CMD_RETURN: u8 = 0xFF;
}

/// KISS interface for TNC communication
pub struct KissInterface {
    /// Base serial interface
    serial: SerialInterface,
    /// Port number (0-15 for multi-port TNCs)
    port: u8,
}

impl KissInterface {
    /// Create a new KISS interface
    pub fn new(config: SerialConfig, port: u8) -> Self {
        Self {
            serial: SerialInterface::new(config),
            port: port.min(15),
        }
    }

    /// Encode a packet in KISS format
    pub fn encode_kiss(&self, data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(data.len() * 2 + 3);

        // Start frame
        encoded.push(kiss::FEND);

        // Command byte (port << 4 | command)
        encoded.push((self.port << 4) | kiss::CMD_DATA);

        // Escape and add data
        for &byte in data {
            match byte {
                kiss::FEND => {
                    encoded.push(kiss::FESC);
                    encoded.push(kiss::TFEND);
                }
                kiss::FESC => {
                    encoded.push(kiss::FESC);
                    encoded.push(kiss::TFESC);
                }
                _ => {
                    encoded.push(byte);
                }
            }
        }

        // End frame
        encoded.push(kiss::FEND);

        encoded
    }

    /// Decode a KISS frame
    pub fn decode_kiss(&self, data: &[u8]) -> Result<Vec<u8>, RnsError> {
        let mut decoded = Vec::with_capacity(data.len());
        let mut escape = false;
        let mut in_frame = false;

        for &byte in data {
            if byte == kiss::FEND {
                if in_frame && !decoded.is_empty() {
                    // Remove command byte and return
                    if !decoded.is_empty() {
                        let _cmd = decoded.remove(0);
                        return Ok(decoded);
                    }
                }
                in_frame = true;
                decoded.clear();
                continue;
            }

            if !in_frame {
                continue;
            }

            if escape {
                match byte {
                    kiss::TFEND => decoded.push(kiss::FEND),
                    kiss::TFESC => decoded.push(kiss::FESC),
                    _ => decoded.push(byte),
                }
                escape = false;
            } else if byte == kiss::FESC {
                escape = true;
            } else {
                decoded.push(byte);
            }
        }

        Err(RnsError::InvalidArgument)
    }

    /// Get the underlying serial interface
    pub fn serial(&self) -> &SerialInterface {
        &self.serial
    }

    /// Get mutable reference to serial interface
    pub fn serial_mut(&mut self) -> &mut SerialInterface {
        &mut self.serial
    }
}

impl Interface for KissInterface {
    fn mtu() -> usize {
        564 // Reticulum serial MTU (matches Python implementation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_config() {
        let config = SerialConfig::new("/dev/ttyUSB0").with_baud_rate(9600);
        assert_eq!(config.port, "/dev/ttyUSB0");
        assert_eq!(config.baud_rate, 9600);
    }

    #[test]
    fn test_kiss_encode() {
        let config = SerialConfig::new("/dev/ttyUSB0");
        let kiss = KissInterface::new(config, 0);

        let data = vec![0x01, 0x02, 0x03];
        let encoded = kiss.encode_kiss(&data);

        assert_eq!(encoded[0], kiss::FEND);
        assert_eq!(encoded[1], kiss::CMD_DATA);
        assert_eq!(encoded[encoded.len() - 1], kiss::FEND);
    }

    #[test]
    fn test_kiss_encode_escape() {
        let config = SerialConfig::new("/dev/ttyUSB0");
        let kiss = KissInterface::new(config, 0);

        // Data containing FEND and FESC bytes
        let data = vec![kiss::FEND, kiss::FESC, 0x42];
        let encoded = kiss.encode_kiss(&data);

        // Should have escape sequences
        assert!(encoded.contains(&kiss::FESC));
        assert!(encoded.contains(&kiss::TFEND));
        assert!(encoded.contains(&kiss::TFESC));
    }

    #[test]
    fn test_kiss_decode() {
        let config = SerialConfig::new("/dev/ttyUSB0");
        let kiss = KissInterface::new(config, 0);

        // Valid KISS frame
        let frame = vec![kiss::FEND, kiss::CMD_DATA, 0x01, 0x02, 0x03, kiss::FEND];
        let decoded = kiss.decode_kiss(&frame).unwrap();

        assert_eq!(decoded, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_serial_stats() {
        let config = SerialConfig::new("/dev/ttyUSB0");
        let mut iface = SerialInterface::new(config);

        iface.record_tx(100);
        iface.record_rx(200);
        iface.record_tx_error();

        assert_eq!(iface.stats().tx_packets, 1);
        assert_eq!(iface.stats().rx_packets, 1);
        assert_eq!(iface.stats().tx_bytes, 100);
        assert_eq!(iface.stats().rx_bytes, 200);
        assert_eq!(iface.stats().tx_errors, 1);
    }

    #[test]
    fn test_serial_mtu_564() {
        // Verify serial MTU matches Python implementation (564 bytes)
        // Python: RNS/Interfaces/Interface.py AUTOCONFIGURE_MTU = 564
        assert_eq!(SerialInterface::mtu(), 564);
    }

    #[test]
    fn test_kiss_mtu_564() {
        // Verify KISS interface MTU also matches Python implementation
        assert_eq!(KissInterface::mtu(), 564);
    }
}
