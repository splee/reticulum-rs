//! Serial interface implementation for Reticulum.
//!
//! This module provides serial port communication for two interface types:
//! - `SerialInterface`: HDLC-framed serial I/O (Python: `SerialInterface.py`)
//! - `KissInterface`: KISS-framed serial I/O for TNC hardware (Python: `KISSInterface.py`)
//!
//! Both follow the `TcpClient::spawn()` pattern: register with the interface
//! registry, run RX/TX tasks, and reconnect on failure.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::config::InterfaceConfig;
use crate::error::RnsError;
use crate::hash::AddressHash;
use crate::iface::hdlc::{Hdlc, HdlcParseResult, HdlcStreamParser, MIN_FRAME_PAYLOAD};
use crate::iface::kiss::{self, Kiss, KissParseResult, KissStreamParser, FEND};
use crate::iface::stats::{InterfaceMetadata, InterfaceMode};
use crate::iface::{Interface, InterfaceContext, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

/// Default baud rate for serial interfaces (9600 matches Python default)
pub const DEFAULT_BAUD_RATE: u32 = 9600;

/// Default read timeout in milliseconds
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 100;

/// Maximum frame size for stack-allocated encode/decode buffers
pub const MAX_FRAME_SIZE: usize = 2048;

/// Reconnect delay after serial port error/disconnect (Python: 5 seconds)
const RECONNECT_DELAY_SECS: u64 = 5;

/// Device initialization delay after opening port (Python: 0.5 seconds)
const CONFIGURE_DEVICE_DELAY_MS: u64 = 500;

/// TNC initialization delay after opening port (Python: 2 seconds)
const KISS_CONFIGURE_DELAY_MS: u64 = 2000;

// =============================================================================
// Serial port configuration types
// =============================================================================

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

// =============================================================================
// SerialInterface — HDLC-framed serial I/O
// =============================================================================

/// Serial interface for hardware communication using HDLC framing.
///
/// Python reference: `RNS/Interfaces/SerialInterface.py`
pub struct SerialInterface {
    /// Configuration
    config: SerialConfig,
    /// Current state
    state: SerialState,
    /// Statistics
    stats: SerialStats,
    /// Interface operating mode from config
    mode: Option<InterfaceMode>,
    /// Whether interface can transmit packets
    dir_out: Option<bool>,
    /// Interface bitrate from config (overrides baud_rate for metadata)
    bitrate: Option<u64>,
    /// Per-interface announce rate target in seconds
    announce_rate_target: Option<u64>,
    /// Per-interface announce rate grace violations
    announce_rate_grace: Option<u32>,
    /// Per-interface announce rate penalty in seconds
    announce_rate_penalty: Option<u64>,
}

impl SerialInterface {
    /// Create a new serial interface
    pub fn new(config: SerialConfig) -> Self {
        Self {
            config,
            state: SerialState::Disconnected,
            stats: SerialStats::default(),
            mode: None,
            dir_out: None,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
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

    /// Create a SerialInterface from an `InterfaceConfig`.
    ///
    /// Reads serial-specific fields from the config's `extra` map:
    /// - `port` (required): serial port path
    /// - `speed`: baud rate (default 9600)
    /// - `databits`: data bits (default 8)
    /// - `parity`: "N", "E", or "O" (default "N")
    /// - `stopbits`: stop bits (default 1)
    pub fn from_config(iface_config: &InterfaceConfig) -> Result<Self, RnsError> {
        let serial_config = parse_serial_config(&iface_config.extra)?;
        Ok(Self::new(serial_config))
    }

    /// Apply common interface config (mode, bitrate, announce rates, etc.).
    /// Follows the same builder pattern as `TcpClient::with_config()`.
    pub fn with_config(mut self, config: &InterfaceConfig) -> Self {
        self.mode = config.mode;
        self.bitrate = config.bitrate;
        self.dir_out = Some(config.outgoing);
        self.announce_rate_target = config.announce_rate_target;
        self.announce_rate_grace = config.announce_rate_grace;
        self.announce_rate_penalty = config.announce_rate_penalty;
        self
    }

    /// Spawn the serial interface I/O loop.
    ///
    /// Follows `TcpClient::spawn()` pattern:
    /// 1. Create and register InterfaceMetadata
    /// 2. Run reconnect loop: open port → spawn RX/TX tasks → await disconnect
    /// 3. On exit, unregister from registry
    pub async fn spawn(context: InterfaceContext<SerialInterface>) {
        let iface_stop = context.channel.stop.clone();
        let (port_path, serial_config, mode, bitrate, dir_out,
             announce_rate_target, announce_rate_grace, announce_rate_penalty) = {
            let inner = context.inner.lock().await;
            (inner.config.port.clone(),
             inner.config.clone(), inner.mode, inner.bitrate, inner.dir_out,
             inner.announce_rate_target, inner.announce_rate_grace,
             inner.announce_rate_penalty)
        };
        let iface_address = context.channel.address;

        // Build InterfaceMetadata (matches Python SerialInterface.__str__ format)
        let effective_bitrate = bitrate.unwrap_or(serial_config.baud_rate as u64);
        let mut meta = InterfaceMetadata::new(
            format!("SerialInterface[{}]", port_path),
            "Serial",
            "SerialInterface",
            port_path.clone(),
        )
        .with_bitrate(effective_bitrate)
        .with_direction(true, dir_out.unwrap_or(true))
        .with_hw_mtu(564)
        .with_ingress_control_disabled(); // Python: should_ingress_limit() returns False

        if let Some(m) = mode {
            meta = meta.with_mode(m);
        }
        if let Some(target) = announce_rate_target {
            meta = meta.with_announce_rate(
                target,
                announce_rate_grace.unwrap_or(0),
                announce_rate_penalty.unwrap_or(0),
            );
        }

        let metadata = Arc::new(meta);

        // Register with interface registry
        let registry = context.interface_registry.clone();
        if let Some(ref reg) = registry {
            reg.register(iface_address, metadata.clone()).await;
        }

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        // Reconnection loop (matches Python reconnect_port())
        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            match build_serial_port(&serial_config) {
                Ok(stream) => {
                    // Device initialization delay (Python: configure_device sleeps 0.5s)
                    tokio::time::sleep(Duration::from_millis(CONFIGURE_DEVICE_DELAY_MS)).await;

                    let (reader, writer) = tokio::io::split(stream);
                    metadata.set_online(true);
                    log::info!("serial: connected to {}", port_path);

                    let stop = CancellationToken::new();

                    // Spawn RX task
                    let rx_task = {
                        let cancel = context.cancel.clone();
                        let stop = stop.clone();
                        let rx_channel = rx_channel.clone();
                        let metadata = metadata.clone();
                        let port_path = port_path.clone();

                        tokio::spawn(serial_hdlc_rx_task(
                            reader, cancel, stop, rx_channel, metadata, iface_address, port_path,
                        ))
                    };

                    // Spawn TX task
                    let tx_task = {
                        let cancel = context.cancel.clone();
                        let stop = stop.clone();
                        let tx_channel = tx_channel.clone();
                        let metadata = metadata.clone();
                        let port_path = port_path.clone();

                        tokio::spawn(serial_hdlc_tx_task(
                            writer, cancel, stop, tx_channel, metadata, iface_address, port_path,
                        ))
                    };

                    // Wait for tasks to finish (port error or shutdown)
                    let _ = rx_task.await;
                    let _ = tx_task.await;

                    metadata.set_online(false);
                    log::info!("serial: disconnected from {}", port_path);
                }
                Err(e) => {
                    log::info!("serial: couldn't open {}: {}", port_path, e);
                    metadata.set_online(false);
                }
            }

            // Check for shutdown before sleeping
            if context.cancel.is_cancelled() {
                break;
            }

            // Reconnect delay (Python: sleep(5))
            tokio::select! {
                _ = context.cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)) => {},
            }
        }

        // Unregister from interface registry on exit
        if let Some(ref reg) = registry {
            reg.unregister(&iface_address).await;
        }

        iface_stop.cancel();
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

// =============================================================================
// KissInterface — KISS-framed serial I/O for TNC hardware
// =============================================================================

/// KISS interface for TNC communication.
///
/// Wraps a `SerialInterface` with KISS-specific TNC configuration,
/// flow control, and beacon support.
///
/// Python reference: `RNS/Interfaces/KISSInterface.py`
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

        let serial_config = parse_serial_config(extra)?;

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

    /// Apply common interface config (mode, bitrate, announce rates, etc.).
    pub fn with_config(mut self, config: &InterfaceConfig) -> Self {
        self.serial.mode = config.mode;
        self.serial.bitrate = config.bitrate;
        self.serial.dir_out = Some(config.outgoing);
        self.serial.announce_rate_target = config.announce_rate_target;
        self.serial.announce_rate_grace = config.announce_rate_grace;
        self.serial.announce_rate_penalty = config.announce_rate_penalty;
        self
    }

    /// Spawn the KISS interface I/O loop.
    ///
    /// Similar to `SerialInterface::spawn()` but uses KISS framing,
    /// sends TNC configuration on connect, and supports flow control + beacons.
    pub async fn spawn(context: InterfaceContext<KissInterface>) {
        let iface_stop = context.channel.stop.clone();
        let (port_path, baud_rate, serial_config, tnc_config, tnc_port,
             flow_control_enabled, beacon, mode, bitrate, dir_out,
             announce_rate_target, announce_rate_grace, announce_rate_penalty) = {
            let inner = context.inner.lock().await;
            (inner.serial.config.port.clone(), inner.serial.config.baud_rate,
             inner.serial.config.clone(), inner.tnc_config.clone(), inner.port,
             inner.tnc_config.flow_control, inner.beacon.clone(),
             inner.serial.mode, inner.serial.bitrate, inner.serial.dir_out,
             inner.serial.announce_rate_target, inner.serial.announce_rate_grace,
             inner.serial.announce_rate_penalty)
        };
        let iface_address = context.channel.address;

        // Build InterfaceMetadata
        let effective_bitrate = bitrate.unwrap_or(KISS_BITRATE_GUESS);
        let mut meta = InterfaceMetadata::new(
            format!("KISSInterface[{}]", port_path),
            "KISS",
            "KISSInterface",
            port_path.clone(),
        )
        .with_bitrate(effective_bitrate)
        .with_direction(true, dir_out.unwrap_or(true))
        .with_hw_mtu(564)
        .with_ingress_control_disabled(); // Python: should_ingress_limit() returns False

        if let Some(m) = mode {
            meta = meta.with_mode(m);
        }
        if let Some(target) = announce_rate_target {
            meta = meta.with_announce_rate(
                target,
                announce_rate_grace.unwrap_or(0),
                announce_rate_penalty.unwrap_or(0),
            );
        }

        let metadata = Arc::new(meta);

        // Register with interface registry
        let registry = context.interface_registry.clone();
        if let Some(ref reg) = registry {
            reg.register(iface_address, metadata.clone()).await;
        }

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        // Reconnection loop
        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            match build_serial_port(&serial_config) {
                Ok(mut stream) => {
                    // Send TNC configuration frames
                    let config_frames = tnc_config.command_frames();
                    let mut tnc_init_ok = true;
                    for frame in &config_frames {
                        if let Err(e) = stream.write_all(frame).await {
                            log::warn!("kiss: failed to send TNC config to {}: {}", port_path, e);
                            tnc_init_ok = false;
                            break;
                        }
                    }
                    if tnc_init_ok {
                        let _ = stream.flush().await;
                    }

                    // TNC initialization delay (Python: 2 seconds)
                    tokio::time::sleep(Duration::from_millis(KISS_CONFIGURE_DELAY_MS)).await;

                    if !tnc_init_ok {
                        metadata.set_online(false);
                        // Fall through to reconnect
                    } else {
                        let (reader, writer) = tokio::io::split(stream);
                        // Shared writer behind Arc<Mutex> for flow control (RX task
                        // needs to drain queued packets on CMD_READY)
                        let writer = Arc::new(tokio::sync::Mutex::new(writer));
                        let flow_control = Arc::new(std::sync::Mutex::new(
                            KissFlowControl::new(flow_control_enabled),
                        ));

                        metadata.set_online(true);
                        log::info!("kiss: connected to {}", port_path);

                        let stop = CancellationToken::new();

                        // Spawn RX task
                        let rx_task = {
                            let cancel = context.cancel.clone();
                            let stop = stop.clone();
                            let rx_channel = rx_channel.clone();
                            let metadata = metadata.clone();
                            let port_path = port_path.clone();
                            let writer = writer.clone();
                            let flow_control = flow_control.clone();

                            tokio::spawn(kiss_rx_task(
                                reader, cancel, stop, rx_channel, metadata,
                                iface_address, port_path, writer, flow_control,
                            ))
                        };

                        // Spawn TX task
                        let tx_task = {
                            let cancel = context.cancel.clone();
                            let stop = stop.clone();
                            let tx_channel = tx_channel.clone();
                            let metadata = metadata.clone();
                            let port_path = port_path.clone();
                            let writer = writer.clone();
                            let flow_control = flow_control.clone();
                            let beacon = beacon.clone();

                            tokio::spawn(kiss_tx_task(
                                cancel, stop, tx_channel, metadata,
                                iface_address, port_path, writer, flow_control,
                                tnc_port, beacon,
                            ))
                        };

                        let _ = rx_task.await;
                        let _ = tx_task.await;

                        metadata.set_online(false);
                        log::info!("kiss: disconnected from {}", port_path);
                    }
                }
                Err(e) => {
                    log::info!("kiss: couldn't open {}: {}", port_path, e);
                    metadata.set_online(false);
                }
            }

            if context.cancel.is_cancelled() {
                break;
            }

            tokio::select! {
                _ = context.cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)) => {},
            }
        }

        if let Some(ref reg) = registry {
            reg.unregister(&iface_address).await;
        }

        iface_stop.cancel();
    }
}

impl Interface for KissInterface {
    fn mtu() -> usize {
        564 // Reticulum serial MTU (matches Python implementation)
    }
}

// =============================================================================
// Shared helpers
// =============================================================================

/// Parse serial port configuration from a config extra map.
///
/// Shared between `SerialInterface::from_config()` and `KissInterface::from_config()`.
fn parse_serial_config(extra: &std::collections::HashMap<String, String>) -> Result<SerialConfig, RnsError> {
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

    Ok(SerialConfig {
        port: port_path.clone(),
        baud_rate: speed,
        data_bits: databits,
        stop_bits: stopbits,
        parity,
        ..Default::default()
    })
}

/// Map our `Parity` enum to `tokio_serial::Parity`.
fn map_parity(parity: Parity) -> tokio_serial::Parity {
    match parity {
        Parity::None => tokio_serial::Parity::None,
        Parity::Odd => tokio_serial::Parity::Odd,
        Parity::Even => tokio_serial::Parity::Even,
    }
}

/// Map our data bits value to `tokio_serial::DataBits`.
fn map_data_bits(bits: u8) -> tokio_serial::DataBits {
    match bits {
        5 => tokio_serial::DataBits::Five,
        6 => tokio_serial::DataBits::Six,
        7 => tokio_serial::DataBits::Seven,
        _ => tokio_serial::DataBits::Eight,
    }
}

/// Map our stop bits value to `tokio_serial::StopBits`.
fn map_stop_bits(bits: u8) -> tokio_serial::StopBits {
    match bits {
        2 => tokio_serial::StopBits::Two,
        _ => tokio_serial::StopBits::One,
    }
}

/// Open a serial port using tokio-serial.
///
/// Configures all serial port parameters and sets flow control to None
/// (matching Python: xonxoff=False, rtscts=False, dsrdtr=False).
fn build_serial_port(config: &SerialConfig) -> Result<tokio_serial::SerialStream, RnsError> {
    let builder = tokio_serial::new(&config.port, config.baud_rate)
        .data_bits(map_data_bits(config.data_bits))
        .stop_bits(map_stop_bits(config.stop_bits))
        .parity(map_parity(config.parity))
        .flow_control(tokio_serial::FlowControl::None)
        .timeout(Duration::from_millis(0)); // Non-blocking

    tokio_serial::SerialStream::open(&builder).map_err(|e| {
        log::error!("Failed to open serial port {}: {}", config.port, e);
        RnsError::ConnectionError
    })
}

// =============================================================================
// HDLC RX/TX tasks for SerialInterface
// =============================================================================

/// HDLC receive task: reads bytes from serial port, parses HDLC frames,
/// deserializes packets, and sends them to the transport layer.
///
/// Matches Python `SerialInterface.readLoop()` behavior.
async fn serial_hdlc_rx_task(
    mut reader: tokio::io::ReadHalf<tokio_serial::SerialStream>,
    cancel: CancellationToken,
    stop: CancellationToken,
    rx_channel: crate::iface::InterfaceRxSender,
    metadata: Arc<InterfaceMetadata>,
    iface_address: AddressHash,
    port_path: String,
) {
    let mut parser = HdlcStreamParser::new();
    let mut read_buf = [0u8; 256];
    let mut last_read = Instant::now();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            result = reader.read(&mut read_buf) => {
                match result {
                    Ok(0) => {
                        log::warn!("serial[{}]: read returned 0 bytes (EOF)", port_path);
                        stop.cancel();
                        break;
                    }
                    Ok(n) => {
                        last_read = Instant::now();
                        metadata.add_rx_bytes(n as u64);

                        for &byte in &read_buf[..n] {
                            if let HdlcParseResult::DataFrame = parser.feed(byte) {
                                let data = parser.take_frame();
                                if data.len() >= MIN_FRAME_PAYLOAD {
                                    match Packet::deserialize(&mut InputBuffer::new(&data)) {
                                        Ok(packet) => {
                                            let _ = rx_channel.send(RxMessage {
                                                address: iface_address,
                                                packet,
                                            }).await;
                                        }
                                        Err(e) => {
                                            log::warn!(
                                                "serial[{}]: packet decode error: {}",
                                                port_path, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("serial[{}]: read error: {}", port_path, e);
                        stop.cancel();
                        break;
                    }
                }
            }
            // Timeout: reset parser if partial data and no bytes for 100ms
            _ = tokio::time::sleep(Duration::from_millis(DEFAULT_READ_TIMEOUT_MS)) => {
                if parser.has_data() && last_read.elapsed() >= Duration::from_millis(DEFAULT_READ_TIMEOUT_MS) {
                    parser.reset();
                }
            }
        }
    }
}

/// HDLC transmit task: receives packets from transport, serializes them,
/// wraps in HDLC framing, and writes to serial port.
///
/// Matches Python `SerialInterface.processOutgoing()`.
async fn serial_hdlc_tx_task(
    mut writer: tokio::io::WriteHalf<tokio_serial::SerialStream>,
    cancel: CancellationToken,
    stop: CancellationToken,
    tx_channel: Arc<tokio::sync::Mutex<crate::iface::InterfaceTxReceiver>>,
    metadata: Arc<InterfaceMetadata>,
    _iface_address: AddressHash,
    port_path: String,
) {
    let mut tx_buffer = [0u8; MAX_FRAME_SIZE];
    let mut hdlc_buffer = [0u8; MAX_FRAME_SIZE * 2 + 4];

    loop {
        let mut tx_channel = tx_channel.lock().await;

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            Some(message) = tx_channel.recv() => {
                let packet = message.packet;
                let mut output = OutputBuffer::new(&mut tx_buffer);

                if packet.serialize(&mut output).is_ok() {
                    let mut hdlc_output = OutputBuffer::new(&mut hdlc_buffer);
                    if Hdlc::encode(output.as_slice(), &mut hdlc_output).is_ok() {
                        let data = hdlc_output.as_slice();
                        metadata.add_tx_bytes(data.len() as u64);

                        if let Err(e) = writer.write_all(data).await {
                            log::warn!("serial[{}]: write error: {}", port_path, e);
                            stop.cancel();
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                }
            }
        }
    }
}

// =============================================================================
// KISS RX/TX tasks for KissInterface
// =============================================================================

/// KISS receive task: reads bytes from serial port, parses KISS frames,
/// handles flow control CMD_READY signals, deserializes packets.
async fn kiss_rx_task(
    mut reader: tokio::io::ReadHalf<tokio_serial::SerialStream>,
    cancel: CancellationToken,
    stop: CancellationToken,
    rx_channel: crate::iface::InterfaceRxSender,
    metadata: Arc<InterfaceMetadata>,
    iface_address: AddressHash,
    port_path: String,
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio_serial::SerialStream>>>,
    flow_control: Arc<std::sync::Mutex<KissFlowControl>>,
) {
    let mut parser = KissStreamParser::new();
    let mut read_buf = [0u8; 256];
    let mut last_read = Instant::now();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            result = reader.read(&mut read_buf) => {
                match result {
                    Ok(0) => {
                        log::warn!("kiss[{}]: read returned 0 bytes (EOF)", port_path);
                        stop.cancel();
                        break;
                    }
                    Ok(n) => {
                        last_read = Instant::now();
                        metadata.add_rx_bytes(n as u64);

                        for &byte in &read_buf[..n] {
                            match parser.feed(byte) {
                                KissParseResult::DataFrame => {
                                    let data = parser.take_frame();
                                    if data.len() >= MIN_FRAME_PAYLOAD {
                                        match Packet::deserialize(&mut InputBuffer::new(&data)) {
                                            Ok(packet) => {
                                                let _ = rx_channel.send(RxMessage {
                                                    address: iface_address,
                                                    packet,
                                                }).await;
                                            }
                                            Err(e) => {
                                                log::warn!(
                                                    "kiss[{}]: packet decode error: {}",
                                                    port_path, e
                                                );
                                            }
                                        }
                                    }
                                }
                                KissParseResult::ReadySignal => {
                                    // TNC is ready — drain queued packets
                                    let queued = {
                                        flow_control.lock().expect("flow_control lock").signal_ready()
                                    };
                                    if !queued.is_empty() {
                                        let mut w = writer.lock().await;
                                        for data in queued {
                                            metadata.add_tx_bytes(data.len() as u64);
                                            if let Err(e) = w.write_all(&data).await {
                                                log::warn!("kiss[{}]: write error draining queue: {}", port_path, e);
                                                stop.cancel();
                                                break;
                                            }
                                        }
                                        let _ = w.flush().await;
                                    }
                                }
                                KissParseResult::CommandFrame(cmd) => {
                                    log::debug!("kiss[{}]: received command frame 0x{:02x}", port_path, cmd);
                                }
                                KissParseResult::Pending => {}
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("kiss[{}]: read error: {}", port_path, e);
                        stop.cancel();
                        break;
                    }
                }
            }
            // Timeout: reset parser if partial data and no bytes for 100ms
            _ = tokio::time::sleep(Duration::from_millis(DEFAULT_READ_TIMEOUT_MS)) => {
                if parser.has_data() && last_read.elapsed() >= Duration::from_millis(DEFAULT_READ_TIMEOUT_MS) {
                    parser.reset();
                }
                // Check flow control timeout
                flow_control.lock().expect("flow_control lock").check_timeout();
            }
        }
    }
}

/// KISS transmit task: receives packets from transport, serializes them,
/// wraps in KISS framing, and writes to serial port (with flow control).
///
/// Also handles periodic beacon transmission when configured.
async fn kiss_tx_task(
    cancel: CancellationToken,
    stop: CancellationToken,
    tx_channel: Arc<tokio::sync::Mutex<crate::iface::InterfaceTxReceiver>>,
    metadata: Arc<InterfaceMetadata>,
    _iface_address: AddressHash,
    port_path: String,
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio_serial::SerialStream>>>,
    flow_control: Arc<std::sync::Mutex<KissFlowControl>>,
    tnc_port: u8,
    beacon: Option<BeaconConfig>,
) {
    let mut tx_buffer = [0u8; MAX_FRAME_SIZE];
    let mut kiss_buffer = [0u8; MAX_FRAME_SIZE * 2 + 4];
    let mut first_tx: Option<Instant> = None;

    loop {
        let mut tx_channel = tx_channel.lock().await;

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            Some(message) = tx_channel.recv() => {
                let packet = message.packet;
                let mut output = OutputBuffer::new(&mut tx_buffer);

                if packet.serialize(&mut output).is_ok() {
                    let mut kiss_output = OutputBuffer::new(&mut kiss_buffer);
                    let encode_result = if tnc_port == 0 {
                        Kiss::encode(output.as_slice(), &mut kiss_output)
                    } else {
                        Kiss::encode_with_port(output.as_slice(), tnc_port, &mut kiss_output)
                    };

                    if encode_result.is_ok() {
                        let encoded = kiss_output.as_slice().to_vec();

                        // Track first TX for beacon timing
                        if first_tx.is_none() {
                            first_tx = Some(Instant::now());
                        }

                        // Check flow control
                        let ready = flow_control.lock().expect("flow_control lock").is_ready();
                        if !ready {
                            flow_control.lock().expect("flow_control lock").queue(encoded);
                            continue;
                        }

                        metadata.add_tx_bytes(encoded.len() as u64);

                        let mut w = writer.lock().await;
                        if let Err(e) = w.write_all(&encoded).await {
                            log::warn!("kiss[{}]: write error: {}", port_path, e);
                            stop.cancel();
                            break;
                        }
                        let _ = w.flush().await;
                        drop(w);

                        // Lock after TX if flow control is enabled
                        flow_control.lock().expect("flow_control lock").lock();
                    }
                }
            }
            // Beacon check: send periodic identification if configured
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if let Some(ref beacon_config) = beacon {
                    if let (Some(interval), Some(first)) = (beacon_config.interval, first_tx) {
                        if first.elapsed() >= Duration::from_secs(interval) {
                            let beacon_data = beacon_config.make_frame();
                            let mut kiss_output = OutputBuffer::new(&mut kiss_buffer);
                            let encode_result = if tnc_port == 0 {
                                Kiss::encode(&beacon_data, &mut kiss_output)
                            } else {
                                Kiss::encode_with_port(&beacon_data, tnc_port, &mut kiss_output)
                            };

                            if encode_result.is_ok() {
                                let mut w = writer.lock().await;
                                let data = kiss_output.as_slice();
                                metadata.add_tx_bytes(data.len() as u64);
                                if let Err(e) = w.write_all(data).await {
                                    log::warn!("kiss[{}]: beacon write error: {}", port_path, e);
                                }
                                let _ = w.flush().await;
                            }
                            // Reset first_tx for next beacon interval
                            first_tx = Some(Instant::now());
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

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
        assert_eq!(SerialInterface::mtu(), 564);
    }

    #[test]
    fn test_kiss_mtu_564() {
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
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0], [FEND, kiss::CMD_TXDELAY, 35, FEND]);
    }

    #[test]
    fn test_tnc_config_command_frames_with_flow_control() {
        let tnc = KissTncConfig {
            flow_control: true,
            ..Default::default()
        };
        let frames = tnc.command_frames();
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
        assert_eq!(frame.len(), 15);
        assert_eq!(&frame[..6], b"N0CALL");
        assert!(frame[6..].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_beacon_config_no_padding_needed() {
        let beacon = BeaconConfig {
            interval: Some(300),
            data: vec![0x42; 20],
        };
        let frame = beacon.make_frame();
        assert_eq!(frame.len(), 20);
    }

    #[test]
    fn test_map_parity() {
        assert_eq!(map_parity(Parity::None), tokio_serial::Parity::None);
        assert_eq!(map_parity(Parity::Odd), tokio_serial::Parity::Odd);
        assert_eq!(map_parity(Parity::Even), tokio_serial::Parity::Even);
    }

    #[test]
    fn test_map_data_bits() {
        assert_eq!(map_data_bits(5), tokio_serial::DataBits::Five);
        assert_eq!(map_data_bits(6), tokio_serial::DataBits::Six);
        assert_eq!(map_data_bits(7), tokio_serial::DataBits::Seven);
        assert_eq!(map_data_bits(8), tokio_serial::DataBits::Eight);
        // Invalid values default to Eight
        assert_eq!(map_data_bits(9), tokio_serial::DataBits::Eight);
    }

    #[test]
    fn test_map_stop_bits() {
        assert_eq!(map_stop_bits(1), tokio_serial::StopBits::One);
        assert_eq!(map_stop_bits(2), tokio_serial::StopBits::Two);
        // Invalid values default to One
        assert_eq!(map_stop_bits(3), tokio_serial::StopBits::One);
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
        fn test_kiss_from_config_defaults() {
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
        fn test_kiss_from_config_overrides() {
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
        fn test_kiss_from_config_missing_port() {
            let extra = HashMap::new();
            let config = make_iface_config(extra);
            assert!(KissInterface::from_config(&config).is_err());
        }

        #[test]
        fn test_kiss_from_config_parity() {
            let mut extra = HashMap::new();
            extra.insert("port".to_string(), "/dev/ttyUSB0".to_string());
            extra.insert("parity".to_string(), "E".to_string());
            let config = make_iface_config(extra);

            let kiss = KissInterface::from_config(&config).unwrap();
            assert_eq!(kiss.serial().config().parity, Parity::Even);
        }

        #[test]
        fn test_serial_from_config_defaults() {
            let mut extra = HashMap::new();
            extra.insert("port".to_string(), "/dev/ttyUSB0".to_string());
            let config = make_iface_config(extra);

            let serial = SerialInterface::from_config(&config).unwrap();
            assert_eq!(serial.config().port, "/dev/ttyUSB0");
            assert_eq!(serial.config().baud_rate, 9600);
            assert_eq!(serial.config().data_bits, 8);
            assert_eq!(serial.config().stop_bits, 1);
            assert_eq!(serial.config().parity, Parity::None);
        }

        #[test]
        fn test_serial_from_config_overrides() {
            let mut extra = HashMap::new();
            extra.insert("port".to_string(), "/dev/ttyS0".to_string());
            extra.insert("speed".to_string(), "115200".to_string());
            extra.insert("databits".to_string(), "7".to_string());
            extra.insert("stopbits".to_string(), "2".to_string());
            extra.insert("parity".to_string(), "O".to_string());
            let config = make_iface_config(extra);

            let serial = SerialInterface::from_config(&config).unwrap();
            assert_eq!(serial.config().port, "/dev/ttyS0");
            assert_eq!(serial.config().baud_rate, 115200);
            assert_eq!(serial.config().data_bits, 7);
            assert_eq!(serial.config().stop_bits, 2);
            assert_eq!(serial.config().parity, Parity::Odd);
        }

        #[test]
        fn test_serial_from_config_missing_port() {
            let extra = HashMap::new();
            let config = make_iface_config(extra);
            assert!(SerialInterface::from_config(&config).is_err());
        }

        #[test]
        fn test_serial_with_config() {
            let mut extra = HashMap::new();
            extra.insert("port".to_string(), "/dev/ttyUSB0".to_string());
            let mut iface_config = make_iface_config(extra);
            iface_config.outgoing = true;
            iface_config.bitrate = Some(19200);
            iface_config.mode = Some(InterfaceMode::Full);

            let serial = SerialInterface::from_config(&iface_config)
                .unwrap()
                .with_config(&iface_config);

            assert_eq!(serial.dir_out, Some(true));
            assert_eq!(serial.bitrate, Some(19200));
            assert_eq!(serial.mode, Some(InterfaceMode::Full));
        }
    }
}
