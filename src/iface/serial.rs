//! Serial interface implementation for Reticulum.
//!
//! This module provides serial port communication with HDLC framing
//! for interfacing with hardware devices.

use std::time::{Duration, Instant};

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::config::InterfaceConfig;
use crate::error::RnsError;
use crate::hash::AddressHash;
use crate::iface::hdlc::Hdlc;
use crate::iface::kiss::{self, Kiss, FEND, FESC, TFEND, TFESC, CMD_DATA};
use crate::iface::Interface;
use crate::packet::Packet;
use crate::serde::Serialize;

/// Default baud rate for serial interfaces (9600 matches Python KISS TNC default)
pub const DEFAULT_BAUD_RATE: u32 = 9600;

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

// =============================================================================
// KISS TNC configuration and flow control
// =============================================================================

/// Default preamble in milliseconds (matches Python KISSInterface default)
pub const DEFAULT_PREAMBLE_MS: u32 = 350;
/// Default TX tail in milliseconds
pub const DEFAULT_TXTAIL_MS: u32 = 20;
/// Default persistence value (0-255)
pub const DEFAULT_PERSISTENCE: u8 = 64;
/// Default slot time in milliseconds
pub const DEFAULT_SLOTTIME_MS: u32 = 20;
/// Flow control timeout in seconds before auto-unlock
pub const DEFAULT_FLOW_CONTROL_TIMEOUT_SECS: u64 = 5;
/// Frame timeout in milliseconds — reset parser state after this much silence
pub const DEFAULT_FRAME_TIMEOUT_MS: u64 = 100;
/// Assumed bitrate for KISS TNCs (bps)
pub const KISS_BITRATE_GUESS: u64 = 1200;
/// Minimum beacon frame length in bytes (padded with 0x00)
pub const MIN_BEACON_LENGTH: usize = 15;

/// KISS TNC configuration parameters.
///
/// Sent as KISS command frames to the TNC hardware on startup.
#[derive(Debug, Clone)]
pub struct KissTncConfig {
    /// Preamble / TX delay in milliseconds
    pub preamble_ms: u32,
    /// TX tail in milliseconds
    pub txtail_ms: u32,
    /// CSMA persistence value (0-255)
    pub persistence: u8,
    /// CSMA slot time in milliseconds
    pub slottime_ms: u32,
    /// Enable hardware flow control (CMD_READY signaling)
    pub flow_control: bool,
}

impl Default for KissTncConfig {
    fn default() -> Self {
        Self {
            preamble_ms: DEFAULT_PREAMBLE_MS,
            txtail_ms: DEFAULT_TXTAIL_MS,
            persistence: DEFAULT_PERSISTENCE,
            slottime_ms: DEFAULT_SLOTTIME_MS,
            flow_control: false,
        }
    }
}

impl KissTncConfig {
    /// Generate the sequence of KISS command frames to configure the TNC.
    /// These should be written to the serial port on startup.
    pub fn command_frames(&self) -> Vec<[u8; 4]> {
        let mut frames = vec![
            Kiss::preamble_frame(self.preamble_ms),
            Kiss::txtail_frame(self.txtail_ms),
            Kiss::persistence_frame(self.persistence),
            Kiss::slottime_frame(self.slottime_ms),
        ];
        if self.flow_control {
            frames.push(Kiss::flow_control_frame());
        }
        frames
    }
}

/// KISS hardware flow control state.
///
/// When enabled, `interface_ready` is cleared after each TX. The TNC
/// signals readiness by sending CMD_READY, at which point queued packets
/// are drained. A timeout auto-unlocks after `DEFAULT_FLOW_CONTROL_TIMEOUT_SECS`.
pub struct KissFlowControl {
    /// Whether the interface is ready to transmit
    interface_ready: bool,
    /// Whether flow control is enabled
    enabled: bool,
    /// Timeout duration before auto-unlock
    timeout: Duration,
    /// When the interface was locked (for timeout tracking)
    locked_at: Option<Instant>,
    /// Packets queued while the interface is locked
    packet_queue: Vec<Vec<u8>>,
}

impl KissFlowControl {
    /// Create a new flow control instance.
    pub fn new(enabled: bool) -> Self {
        Self {
            interface_ready: true,
            enabled,
            timeout: Duration::from_secs(DEFAULT_FLOW_CONTROL_TIMEOUT_SECS),
            locked_at: None,
            packet_queue: Vec::new(),
        }
    }

    /// Returns true if the interface is ready to transmit.
    /// Always true when flow control is disabled.
    pub fn is_ready(&self) -> bool {
        !self.enabled || self.interface_ready
    }

    /// Lock the interface after a transmission (called when flow control is enabled).
    pub fn lock(&mut self) {
        if self.enabled {
            self.interface_ready = false;
            self.locked_at = Some(Instant::now());
        }
    }

    /// Signal that the TNC is ready (CMD_READY received).
    /// Unlocks the interface and returns any queued packets to be sent.
    pub fn signal_ready(&mut self) -> Vec<Vec<u8>> {
        self.interface_ready = true;
        self.locked_at = None;
        std::mem::take(&mut self.packet_queue)
    }

    /// Queue a packet while the interface is locked.
    pub fn queue(&mut self, data: Vec<u8>) {
        self.packet_queue.push(data);
    }

    /// Check if the flow control timeout has expired.
    /// Returns true if auto-unlocked (caller should log a warning).
    pub fn check_timeout(&mut self) -> bool {
        if !self.enabled || self.interface_ready {
            return false;
        }
        if let Some(locked_at) = self.locked_at {
            if locked_at.elapsed() >= self.timeout {
                log::warn!(
                    "Flow control timeout ({:?}) expired, auto-unlocking interface",
                    self.timeout
                );
                self.interface_ready = true;
                self.locked_at = None;
                return true;
            }
        }
        false
    }

    /// Returns true if flow control is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the number of queued packets.
    pub fn queue_len(&self) -> usize {
        self.packet_queue.len()
    }
}

/// Beacon / ID configuration for periodic station identification.
#[derive(Debug, Clone)]
pub struct BeaconConfig {
    /// Beacon interval in seconds (None = disabled)
    pub interval: Option<u64>,
    /// Beacon data (callsign/ID as UTF-8 bytes)
    pub data: Vec<u8>,
}

impl BeaconConfig {
    /// Build a beacon frame, padded to MIN_BEACON_LENGTH (15 bytes) with 0x00.
    pub fn make_frame(&self) -> Vec<u8> {
        let mut frame = self.data.clone();
        while frame.len() < MIN_BEACON_LENGTH {
            frame.push(0x00);
        }
        frame
    }
}

/// KISS interface for TNC communication.
///
/// Wraps a `SerialInterface` with KISS-specific TNC configuration,
/// flow control, and beacon support.
pub struct KissInterface {
    /// Base serial interface
    serial: SerialInterface,
    /// TNC port number (0-15 for multi-port TNCs)
    port: u8,
    /// TNC configuration parameters (preamble, persistence, etc.)
    tnc_config: KissTncConfig,
    /// Hardware flow control state
    flow_control: KissFlowControl,
    /// Optional beacon / station ID configuration
    beacon: Option<BeaconConfig>,
    /// Timestamp of first TX (for beacon interval tracking)
    first_tx: Option<Instant>,
}

impl KissInterface {
    /// Create a new KISS interface with default TNC settings.
    pub fn new(config: SerialConfig, port: u8) -> Self {
        Self {
            serial: SerialInterface::new(config),
            port: port.min(15),
            tnc_config: KissTncConfig::default(),
            flow_control: KissFlowControl::new(false),
            beacon: None,
            first_tx: None,
        }
    }

    /// Create a KISS interface with full TNC configuration.
    pub fn with_tnc_config(
        config: SerialConfig,
        port: u8,
        tnc_config: KissTncConfig,
        beacon: Option<BeaconConfig>,
    ) -> Self {
        let flow_control_enabled = tnc_config.flow_control;
        Self {
            serial: SerialInterface::new(config),
            port: port.min(15),
            tnc_config,
            flow_control: KissFlowControl::new(flow_control_enabled),
            beacon,
            first_tx: None,
        }
    }

    /// Encode a packet in KISS format
    pub fn encode_kiss(&self, data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(data.len() * 2 + 3);

        // Start frame
        encoded.push(FEND);

        // Command byte (port << 4 | command)
        encoded.push((self.port << 4) | CMD_DATA);

        // Escape and add data
        for &byte in data {
            match byte {
                FEND => {
                    encoded.push(FESC);
                    encoded.push(TFEND);
                }
                FESC => {
                    encoded.push(FESC);
                    encoded.push(TFESC);
                }
                _ => {
                    encoded.push(byte);
                }
            }
        }

        // End frame
        encoded.push(FEND);

        encoded
    }

    /// Decode a KISS frame
    pub fn decode_kiss(&self, data: &[u8]) -> Result<Vec<u8>, RnsError> {
        let mut decoded = Vec::with_capacity(data.len());
        let mut escape = false;
        let mut in_frame = false;

        for &byte in data {
            if byte == FEND {
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
                    TFEND => decoded.push(FEND),
                    TFESC => decoded.push(FESC),
                    _ => decoded.push(byte),
                }
                escape = false;
            } else if byte == FESC {
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

    /// Get the TNC configuration
    pub fn tnc_config(&self) -> &KissTncConfig {
        &self.tnc_config
    }

    /// Get mutable reference to flow control state
    pub fn flow_control_mut(&mut self) -> &mut KissFlowControl {
        &mut self.flow_control
    }

    /// Get the beacon configuration
    pub fn beacon(&self) -> Option<&BeaconConfig> {
        self.beacon.as_ref()
    }

    /// Get the TNC port number
    pub fn port(&self) -> u8 {
        self.port
    }

    /// Get/set the first TX timestamp (for beacon interval tracking)
    pub fn first_tx(&self) -> Option<Instant> {
        self.first_tx
    }

    /// Set the first TX timestamp
    pub fn set_first_tx(&mut self, instant: Option<Instant>) {
        self.first_tx = instant;
    }

    /// Create a KISS interface from an `InterfaceConfig`.
    ///
    /// Reads KISS-specific fields from the config's `extra` map:
    /// - `port` (required): serial port path
    /// - `speed`: baud rate (default 9600)
    /// - `databits`: data bits (default 8)
    /// - `parity`: "N", "E", or "O" (default "N")
    /// - `stopbits`: stop bits (default 1)
    /// - `preamble`: TX delay in ms (default 350)
    /// - `txtail`: TX tail in ms (default 20)
    /// - `persistence`: CSMA persistence 0-255 (default 64)
    /// - `slottime`: CSMA slot time in ms (default 20)
    /// - `flow_control`: enable hardware flow control (default false)
    /// - `id_interval`: beacon interval in seconds (optional)
    /// - `id_callsign`: beacon callsign string (optional)
    pub fn from_config(iface_config: &InterfaceConfig) -> Result<Self, RnsError> {
        let extra = &iface_config.extra;

        let port_path = extra.get("port")
            .ok_or(RnsError::InvalidArgument)?;

        let speed: u32 = extra.get("speed")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_BAUD_RATE);

        let databits: u8 = extra.get("databits")
            .and_then(|s| s.parse().ok())
            .unwrap_or(8);

        let parity = match extra.get("parity").map(|s| s.to_lowercase()).as_deref() {
            Some("e") | Some("even") => Parity::Even,
            Some("o") | Some("odd") => Parity::Odd,
            _ => Parity::None,
        };

        let stopbits: u8 = extra.get("stopbits")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let serial_config = SerialConfig {
            port: port_path.clone(),
            baud_rate: speed,
            data_bits: databits,
            stop_bits: stopbits,
            parity,
            ..Default::default()
        };

        let preamble_ms: u32 = extra.get("preamble")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_PREAMBLE_MS);

        let txtail_ms: u32 = extra.get("txtail")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TXTAIL_MS);

        let persistence: u8 = extra.get("persistence")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_PERSISTENCE);

        let slottime_ms: u32 = extra.get("slottime")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_SLOTTIME_MS);

        let flow_control: bool = extra.get("flow_control")
            .map(|s| s == "true" || s == "True" || s == "1" || s == "yes")
            .unwrap_or(false);

        let tnc_config = KissTncConfig {
            preamble_ms,
            txtail_ms,
            persistence,
            slottime_ms,
            flow_control,
        };

        let id_interval: Option<u64> = extra.get("id_interval")
            .and_then(|s| s.parse().ok());

        let id_callsign: Option<String> = extra.get("id_callsign").cloned();

        let beacon = match (id_interval, id_callsign) {
            (Some(interval), Some(callsign)) => Some(BeaconConfig {
                interval: Some(interval),
                data: callsign.into_bytes(),
            }),
            (Some(interval), None) => Some(BeaconConfig {
                interval: Some(interval),
                data: Vec::new(),
            }),
            _ => None,
        };

        Ok(Self::with_tnc_config(serial_config, 0, tnc_config, beacon))
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
        let config = SerialConfig::new("/dev/ttyUSB0").with_baud_rate(19200);
        assert_eq!(config.port, "/dev/ttyUSB0");
        assert_eq!(config.baud_rate, 19200);
    }

    #[test]
    fn test_default_baud_rate_9600() {
        let config = SerialConfig::default();
        assert_eq!(config.baud_rate, 9600);
    }

    #[test]
    fn test_kiss_encode() {
        let config = SerialConfig::new("/dev/ttyUSB0");
        let kiss_iface = KissInterface::new(config, 0);

        let data = vec![0x01, 0x02, 0x03];
        let encoded = kiss_iface.encode_kiss(&data);

        assert_eq!(encoded[0], FEND);
        assert_eq!(encoded[1], CMD_DATA);
        assert_eq!(encoded[encoded.len() - 1], FEND);
    }

    #[test]
    fn test_kiss_encode_escape() {
        let config = SerialConfig::new("/dev/ttyUSB0");
        let kiss_iface = KissInterface::new(config, 0);

        // Data containing FEND and FESC bytes
        let data = vec![FEND, FESC, 0x42];
        let encoded = kiss_iface.encode_kiss(&data);

        // Should have escape sequences
        assert!(encoded.contains(&FESC));
        assert!(encoded.contains(&TFEND));
        assert!(encoded.contains(&TFESC));
    }

    #[test]
    fn test_kiss_decode() {
        let config = SerialConfig::new("/dev/ttyUSB0");
        let kiss_iface = KissInterface::new(config, 0);

        // Valid KISS frame
        let frame = vec![FEND, CMD_DATA, 0x01, 0x02, 0x03, FEND];
        let decoded = kiss_iface.decode_kiss(&frame).unwrap();

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

    #[test]
    fn test_kiss_with_tnc_config() {
        let config = SerialConfig::new("/dev/ttyUSB0");
        let tnc = KissTncConfig {
            preamble_ms: 500,
            txtail_ms: 30,
            persistence: 128,
            slottime_ms: 40,
            flow_control: true,
        };
        let kiss_iface = KissInterface::with_tnc_config(config, 2, tnc, None);
        assert_eq!(kiss_iface.port(), 2);
        assert_eq!(kiss_iface.tnc_config().preamble_ms, 500);
        assert!(kiss_iface.beacon().is_none());
    }

    #[test]
    fn test_tnc_config_defaults() {
        let tnc = KissTncConfig::default();
        assert_eq!(tnc.preamble_ms, 350);
        assert_eq!(tnc.txtail_ms, 20);
        assert_eq!(tnc.persistence, 64);
        assert_eq!(tnc.slottime_ms, 20);
        assert!(!tnc.flow_control);
    }

    #[test]
    fn test_tnc_config_command_frames() {
        let tnc = KissTncConfig::default();
        let frames = tnc.command_frames();
        // preamble, txtail, persistence, slottime (no flow control)
        assert_eq!(frames.len(), 4);
        // Verify preamble frame: 350/10 = 35
        assert_eq!(frames[0], [FEND, kiss::CMD_TXDELAY, 35, FEND]);
    }

    #[test]
    fn test_tnc_config_command_frames_with_flow_control() {
        let tnc = KissTncConfig {
            flow_control: true,
            ..Default::default()
        };
        let frames = tnc.command_frames();
        // preamble, txtail, persistence, slottime, flow_control
        assert_eq!(frames.len(), 5);
        assert_eq!(frames[4], [FEND, kiss::CMD_READY, 0x01, FEND]);
    }

    #[test]
    fn test_flow_control_disabled() {
        let fc = KissFlowControl::new(false);
        assert!(fc.is_ready());
        assert!(!fc.is_enabled());
    }

    #[test]
    fn test_flow_control_lock_unlock() {
        let mut fc = KissFlowControl::new(true);
        assert!(fc.is_ready());

        fc.lock();
        assert!(!fc.is_ready());

        let queued = fc.signal_ready();
        assert!(fc.is_ready());
        assert!(queued.is_empty());
    }

    #[test]
    fn test_flow_control_queue() {
        let mut fc = KissFlowControl::new(true);
        fc.lock();

        fc.queue(vec![0x01, 0x02]);
        fc.queue(vec![0x03, 0x04]);
        assert_eq!(fc.queue_len(), 2);

        let queued = fc.signal_ready();
        assert_eq!(queued.len(), 2);
        assert_eq!(queued[0], vec![0x01, 0x02]);
        assert_eq!(queued[1], vec![0x03, 0x04]);
        assert_eq!(fc.queue_len(), 0);
    }

    #[test]
    fn test_beacon_config_make_frame() {
        let beacon = BeaconConfig {
            interval: Some(600),
            data: b"N0CALL".to_vec(),
        };
        let frame = beacon.make_frame();
        // "N0CALL" = 6 bytes, padded to 15
        assert_eq!(frame.len(), 15);
        assert_eq!(&frame[..6], b"N0CALL");
        assert!(frame[6..].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_beacon_config_no_padding_needed() {
        let beacon = BeaconConfig {
            interval: Some(300),
            data: vec![0x42; 20], // already > 15 bytes
        };
        let frame = beacon.make_frame();
        assert_eq!(frame.len(), 20);
    }

    mod from_config {
        use super::*;
        use std::collections::HashMap;

        fn make_iface_config(extra: HashMap<String, String>) -> InterfaceConfig {
            InterfaceConfig {
                name: "test_kiss".to_string(),
                interface_type: "KISSInterface".to_string(),
                enabled: true,
                mode: None,
                network_name: None,
                passphrase: None,
                target_host: None,
                target_port: None,
                listen_ip: None,
                listen_port: None,
                outgoing: false,
                bitrate: None,
                fixed_mtu: None,
                announce_rate_target: None,
                announce_rate_grace: None,
                announce_rate_penalty: None,
                kiss_framing: false,
                i2p_tunneled: false,
                connect_timeout: None,
                max_reconnect_tries: None,
                extra,
            }
        }

        #[test]
        fn test_from_config_defaults() {
            let mut extra = HashMap::new();
            extra.insert("port".to_string(), "/dev/ttyUSB0".to_string());
            let config = make_iface_config(extra);

            let kiss = KissInterface::from_config(&config).unwrap();
            assert_eq!(kiss.serial().config().port, "/dev/ttyUSB0");
            assert_eq!(kiss.serial().config().baud_rate, 9600);
            assert_eq!(kiss.tnc_config().preamble_ms, 350);
            assert_eq!(kiss.tnc_config().persistence, 64);
            assert!(!kiss.tnc_config().flow_control);
            assert!(kiss.beacon().is_none());
        }

        #[test]
        fn test_from_config_overrides() {
            let mut extra = HashMap::new();
            extra.insert("port".to_string(), "/dev/ttyS0".to_string());
            extra.insert("speed".to_string(), "19200".to_string());
            extra.insert("preamble".to_string(), "500".to_string());
            extra.insert("persistence".to_string(), "128".to_string());
            extra.insert("flow_control".to_string(), "true".to_string());
            extra.insert("id_interval".to_string(), "600".to_string());
            extra.insert("id_callsign".to_string(), "N0CALL".to_string());
            let config = make_iface_config(extra);

            let kiss = KissInterface::from_config(&config).unwrap();
            assert_eq!(kiss.serial().config().baud_rate, 19200);
            assert_eq!(kiss.tnc_config().preamble_ms, 500);
            assert_eq!(kiss.tnc_config().persistence, 128);
            assert!(kiss.tnc_config().flow_control);

            let beacon = kiss.beacon().unwrap();
            assert_eq!(beacon.interval, Some(600));
            assert_eq!(beacon.data, b"N0CALL");
        }

        #[test]
        fn test_from_config_missing_port() {
            let extra = HashMap::new();
            let config = make_iface_config(extra);
            assert!(KissInterface::from_config(&config).is_err());
        }

        #[test]
        fn test_from_config_parity() {
            let mut extra = HashMap::new();
            extra.insert("port".to_string(), "/dev/ttyUSB0".to_string());
            extra.insert("parity".to_string(), "E".to_string());
            let config = make_iface_config(extra);

            let kiss = KissInterface::from_config(&config).unwrap();
            assert_eq!(kiss.serial().config().parity, Parity::Even);
        }
    }
}
