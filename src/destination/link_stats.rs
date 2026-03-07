//! Link statistics tracking
//!
//! This module provides statistics tracking for links including
//! throughput, latency, packet counts, and physical layer metrics.

use std::time::{Duration, Instant};

use crate::packet::{MAX_SUPPORTED_LINK_MTU, RETICULUM_MTU};

/// Statistics for a link
#[derive(Debug, Clone)]
pub struct LinkStats {
    /// Number of packets transmitted
    pub tx_packets: u64,
    /// Number of packets received
    pub rx_packets: u64,
    /// Number of bytes transmitted
    pub tx_bytes: u64,
    /// Number of bytes received
    pub rx_bytes: u64,
    /// Round-trip time
    pub rtt: Option<Duration>,
    /// Last measured RSSI (dBm)
    pub rssi: Option<i16>,
    /// Last measured SNR (dB)
    pub snr: Option<f32>,
    /// Link quality (0.0 - 1.0)
    pub q: Option<f32>,
    /// Time when link was established
    pub established_at: Option<Instant>,
    /// Time of last inbound activity
    pub last_inbound: Option<Instant>,
    /// Time of last outbound activity
    pub last_outbound: Option<Instant>,
    /// Time of last keepalive
    pub last_keepalive: Option<Instant>,
    /// Time of last proof
    pub last_proof: Option<Instant>,
    /// Number of keepalives sent
    pub keepalives_sent: u64,
    /// Number of keepalives received
    pub keepalives_received: u64,
    /// Number of retransmissions
    pub retransmissions: u64,
}

impl Default for LinkStats {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkStats {
    /// Create new empty statistics
    pub fn new() -> Self {
        Self {
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            rtt: None,
            rssi: None,
            snr: None,
            q: None,
            established_at: None,
            last_inbound: None,
            last_outbound: None,
            last_keepalive: None,
            last_proof: None,
            keepalives_sent: 0,
            keepalives_received: 0,
            retransmissions: 0,
        }
    }

    /// Mark the link as established
    pub fn mark_established(&mut self) {
        self.established_at = Some(Instant::now());
    }

    /// Record a transmitted packet
    pub fn record_tx(&mut self, bytes: usize) {
        self.tx_packets += 1;
        self.tx_bytes += bytes as u64;
        self.last_outbound = Some(Instant::now());
    }

    /// Record a received packet
    pub fn record_rx(&mut self, bytes: usize) {
        self.rx_packets += 1;
        self.rx_bytes += bytes as u64;
        self.last_inbound = Some(Instant::now());
    }

    /// Record a keepalive sent
    pub fn record_keepalive_sent(&mut self) {
        self.keepalives_sent += 1;
        self.last_keepalive = Some(Instant::now());
    }

    /// Record a keepalive received
    pub fn record_keepalive_received(&mut self) {
        self.keepalives_received += 1;
    }

    /// Record a proof
    pub fn record_proof(&mut self) {
        self.last_proof = Some(Instant::now());
    }

    /// Record a retransmission
    pub fn record_retransmission(&mut self) {
        self.retransmissions += 1;
    }

    /// Update RTT measurement
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
    }

    /// Update physical layer metrics
    pub fn update_physical_metrics(&mut self, rssi: Option<i16>, snr: Option<f32>, q: Option<f32>) {
        if rssi.is_some() {
            self.rssi = rssi;
        }
        if snr.is_some() {
            self.snr = snr;
        }
        if q.is_some() {
            self.q = q;
        }
    }

    /// Get the time since the link was established
    pub fn age(&self) -> Option<Duration> {
        self.established_at.map(|t| t.elapsed())
    }

    /// Get the time since last activity (either direction)
    pub fn idle_time(&self) -> Option<Duration> {
        let last_activity = match (self.last_inbound, self.last_outbound) {
            (Some(i), Some(o)) => Some(i.max(o)),
            (Some(i), None) => Some(i),
            (None, Some(o)) => Some(o),
            (None, None) => None,
        };
        last_activity.map(|t| t.elapsed())
    }

    /// Get the time since last inbound activity
    pub fn time_since_inbound(&self) -> Option<Duration> {
        self.last_inbound.map(|t| t.elapsed())
    }

    /// Get the time since last outbound activity
    pub fn time_since_outbound(&self) -> Option<Duration> {
        self.last_outbound.map(|t| t.elapsed())
    }

    /// Calculate average throughput (bytes per second) for transmit
    pub fn tx_throughput(&self) -> Option<f64> {
        let age = self.age()?.as_secs_f64();
        if age > 0.0 {
            Some(self.tx_bytes as f64 / age)
        } else {
            None
        }
    }

    /// Calculate average throughput (bytes per second) for receive
    pub fn rx_throughput(&self) -> Option<f64> {
        let age = self.age()?.as_secs_f64();
        if age > 0.0 {
            Some(self.rx_bytes as f64 / age)
        } else {
            None
        }
    }

    /// Get total packets (tx + rx)
    pub fn total_packets(&self) -> u64 {
        self.tx_packets + self.rx_packets
    }

    /// Get total bytes (tx + rx)
    pub fn total_bytes(&self) -> u64 {
        self.tx_bytes + self.rx_bytes
    }

    /// Reset all statistics
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Keepalive configuration
#[derive(Debug, Clone)]
pub struct KeepaliveConfig {
    /// Interval between keepalive packets
    pub interval: Duration,
    /// Timeout factor (multiplied by interval for timeout)
    pub timeout_factor: f32,
    /// Maximum RTT allowed for keepalive response
    pub max_rtt: Duration,
    /// Whether keepalive is enabled
    pub enabled: bool,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(360), // 6 minutes
            timeout_factor: 4.0,
            max_rtt: Duration::from_millis(1750), // 1.75 seconds
            enabled: true,
        }
    }
}

impl KeepaliveConfig {
    /// Get the timeout duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs_f32(self.interval.as_secs_f32() * self.timeout_factor)
    }

    /// Get the stale time (when link is considered stale)
    pub fn stale_time(&self) -> Duration {
        self.timeout() // Same as timeout by default
    }
}

/// Link MTU configuration and discovery
#[derive(Debug, Clone)]
pub struct LinkMtuConfig {
    /// Current MTU
    pub mtu: usize,
    /// Minimum MTU
    pub min_mtu: usize,
    /// Maximum MTU
    pub max_mtu: usize,
    /// Whether MTU discovery is enabled
    pub discovery_enabled: bool,
    /// Whether MTU has been discovered
    pub discovered: bool,
}

impl Default for LinkMtuConfig {
    fn default() -> Self {
        Self {
            mtu: RETICULUM_MTU,
            min_mtu: 219, // Absolute minimum
            max_mtu: MAX_SUPPORTED_LINK_MTU,
            discovery_enabled: true,
            discovered: false,
        }
    }
}

impl LinkMtuConfig {
    /// Create with a specific MTU
    pub fn with_mtu(mtu: usize) -> Self {
        Self {
            mtu: mtu.clamp(219, MAX_SUPPORTED_LINK_MTU),
            discovered: true,
            ..Default::default()
        }
    }

    /// Update MTU from discovery
    pub fn update_mtu(&mut self, new_mtu: usize) {
        self.mtu = new_mtu.clamp(self.min_mtu, self.max_mtu);
        self.discovered = true;
    }

    /// Encode MTU for signalling in link packets
    pub fn encode_signalling(&self) -> [u8; 3] {
        let mut bytes = [0u8; 3];
        // Simple encoding: just store MTU as 16-bit + flags
        bytes[0] = (self.mtu >> 8) as u8;
        bytes[1] = (self.mtu & 0xFF) as u8;
        bytes[2] = if self.discovery_enabled { 0x01 } else { 0x00 };
        bytes
    }

    /// Decode MTU from signalling bytes
    pub fn decode_signalling(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }
        let mtu = ((bytes[0] as usize) << 8) | (bytes[1] as usize);
        let discovery_enabled = bytes[2] & 0x01 != 0;

        Some(Self {
            mtu: mtu.clamp(219, MAX_SUPPORTED_LINK_MTU),
            discovery_enabled,
            discovered: true,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_link_stats_creation() {
        let stats = LinkStats::new();
        assert_eq!(stats.tx_packets, 0);
        assert_eq!(stats.rx_packets, 0);
    }

    #[test]
    fn test_link_stats_recording() {
        let mut stats = LinkStats::new();

        stats.record_tx(100);
        stats.record_rx(200);

        assert_eq!(stats.tx_packets, 1);
        assert_eq!(stats.rx_packets, 1);
        assert_eq!(stats.tx_bytes, 100);
        assert_eq!(stats.rx_bytes, 200);
        assert_eq!(stats.total_packets(), 2);
        assert_eq!(stats.total_bytes(), 300);
    }

    #[test]
    fn test_link_stats_age() {
        let mut stats = LinkStats::new();
        stats.mark_established();

        sleep(Duration::from_millis(10));

        let age = stats.age().unwrap();
        assert!(age >= Duration::from_millis(10));
    }

    #[test]
    fn test_keepalive_config() {
        let config = KeepaliveConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval, Duration::from_secs(360));
        assert_eq!(config.timeout(), Duration::from_secs(1440)); // 360 * 4
    }

    #[test]
    fn test_link_mtu_config() {
        let mut config = LinkMtuConfig::default();
        assert_eq!(config.mtu, 500);

        config.update_mtu(450);
        assert_eq!(config.mtu, 450);
        assert!(config.discovered);
    }

    #[test]
    fn test_mtu_signalling() {
        let config = LinkMtuConfig::with_mtu(450);
        let encoded = config.encode_signalling();
        let decoded = LinkMtuConfig::decode_signalling(&encoded).unwrap();

        assert_eq!(config.mtu, decoded.mtu);
    }
}
