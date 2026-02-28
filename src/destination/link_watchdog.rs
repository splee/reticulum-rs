//! Link watchdog for monitoring link health and handling keepalives.
//!
//! This module provides a watchdog task that monitors link status,
//! sends keepalives when needed, and tears down stale links.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;

use super::link::{Link, LinkStatus, KEEPALIVE_TIMEOUT_FACTOR, STALE_GRACE};
use crate::hash::AddressHash;
use crate::packet::{Header, Packet, PacketContext, PacketDataBuffer, PacketType};

/// Messages sent from the watchdog to the transport layer.
#[derive(Debug, Clone)]
pub enum WatchdogMessage {
    /// Send a keepalive packet for this link.
    SendKeepalive {
        link_id: AddressHash,
        packet: Box<Packet>,
    },
    /// Tear down this link due to staleness or timeout.
    TeardownLink {
        link_id: AddressHash,
        reason: TeardownReason,
    },
}

/// Reason for link teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownReason {
    /// Link establishment timed out.
    EstablishmentTimeout,
    /// Link became stale (no activity).
    Stale,
    /// Keepalive timeout (no response to keepalives).
    KeepaliveTimeout,
    /// Explicit close requested.
    Closed,
}

/// Configuration for the link watchdog.
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// How often to check link status.
    pub check_interval: Duration,
    /// Timeout for link establishment.
    pub establishment_timeout: Duration,
}

/// Timeout per hop for link establishment (matching Python Link.py)
pub const ESTABLISHMENT_TIMEOUT_PER_HOP: f64 = 6.0;

/// Default keepalive duration used in establishment timeout calculation
pub const DEFAULT_KEEPALIVE_SECS: f64 = 360.0;

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(1),
            establishment_timeout: Duration::from_secs(15),
        }
    }
}

impl WatchdogConfig {
    /// Create config for incoming link with hop-aware establishment timeout.
    pub fn for_incoming_link(hops: u8) -> Self {
        let effective_hops = (hops as f64).max(1.0);
        let timeout = ESTABLISHMENT_TIMEOUT_PER_HOP * effective_hops + DEFAULT_KEEPALIVE_SECS;
        Self {
            check_interval: Duration::from_secs(1),
            establishment_timeout: Duration::from_secs_f64(timeout),
        }
    }
}

/// Spawn a watchdog task for a link.
///
/// The watchdog monitors the link and sends messages through the provided
/// broadcast channel when actions are needed.
///
/// # Arguments
///
/// * `link` - The link to monitor (shared reference)
/// * `cancel` - Cancellation token to stop the watchdog
/// * `msg_tx` - Channel to send watchdog messages
/// * `config` - Watchdog configuration
///
/// # Returns
///
/// A JoinHandle for the spawned task.
pub fn spawn_link_watchdog(
    link: Arc<RwLock<Link>>,
    cancel: CancellationToken,
    msg_tx: broadcast::Sender<WatchdogMessage>,
    config: WatchdogConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        link_watchdog_loop(link, cancel, msg_tx, config).await;
    })
}

/// Main watchdog loop.
async fn link_watchdog_loop(
    link: Arc<RwLock<Link>>,
    cancel: CancellationToken,
    msg_tx: broadcast::Sender<WatchdogMessage>,
    config: WatchdogConfig,
) {
    loop {
        // Check for cancellation
        if cancel.is_cancelled() {
            break;
        }

        // Read current link status
        let (status, link_id, should_keepalive, should_teardown, teardown_reason) = {
            let link = link.read().await;
            let status = link.status();
            let link_id = *link.id();

            let (should_keepalive, should_teardown, reason) = match status {
                LinkStatus::Pending | LinkStatus::Handshake => {
                    // Check establishment timeout
                    let timed_out = link
                        .activated_at()
                        .is_none()
                        && link
                            .last_outbound()
                            .map(|t| t.elapsed() > config.establishment_timeout)
                            .unwrap_or(false);

                    (false, timed_out, Some(TeardownReason::EstablishmentTimeout))
                }
                LinkStatus::Active => {
                    // Check if we need to send keepalive
                    let keepalive_interval = link.keepalive_interval();
                    let should_keepalive = link
                        .last_outbound()
                        .map(|t| t.elapsed() > keepalive_interval)
                        .unwrap_or(false);

                    // Check if link is stale
                    let is_stale = link.is_stale();

                    // Check keepalive timeout
                    let keepalive_timeout = link
                        .last_inbound()
                        .map(|t| t.elapsed() > keepalive_interval * KEEPALIVE_TIMEOUT_FACTOR)
                        .unwrap_or(false);

                    if keepalive_timeout {
                        (false, true, Some(TeardownReason::KeepaliveTimeout))
                    } else if is_stale {
                        (false, true, Some(TeardownReason::Stale))
                    } else {
                        (should_keepalive, false, None)
                    }
                }
                LinkStatus::Stale => {
                    // Wait for stale grace period before teardown
                    let should_teardown = link
                        .last_data()
                        .map(|t| t.elapsed() > link.stale_time() + STALE_GRACE)
                        .unwrap_or(true);

                    (false, should_teardown, Some(TeardownReason::Stale))
                }
                LinkStatus::Closed => {
                    // Link is already closed, exit watchdog
                    break;
                }
            };

            (status, link_id, should_keepalive, should_teardown, reason)
        };

        // Handle actions
        if should_teardown {
            if let Some(reason) = teardown_reason {
                log::debug!(
                    "link_watchdog({}): tearing down link, reason={:?}",
                    link_id,
                    reason
                );
                let _ = msg_tx.send(WatchdogMessage::TeardownLink {
                    link_id,
                    reason,
                });
            }
            break;
        }

        if should_keepalive && status == LinkStatus::Active {
            // Create keepalive packet
            if let Some(packet) = create_keepalive_packet(&link).await {
                log::trace!("link_watchdog({}): sending keepalive", link_id);
                let _ = msg_tx.send(WatchdogMessage::SendKeepalive {
                    link_id,
                    packet: Box::new(packet),
                });
            }
        }

        // Sleep before next check
        tokio::select! {
            _ = tokio::time::sleep(config.check_interval) => {}
            _ = cancel.cancelled() => break,
        }
    }

    log::debug!("link_watchdog: exiting");
}

/// Create a keepalive packet for a link.
async fn create_keepalive_packet(link: &Arc<RwLock<Link>>) -> Option<Packet> {
    let link = link.read().await;

    if link.status() != LinkStatus::Active {
        return None;
    }

    // Keepalive is an empty data packet with context flag set
    let packet = Packet {
        header: Header {
            packet_type: PacketType::Data,
            context_flag: true, // Indicates keepalive
            ..Default::default()
        },
        ifac: None,
        destination: *link.id(),
        transport: None,
        context: PacketContext::KeepAlive,
        data: PacketDataBuffer::new(),
        ratchet_id: None,
    };

    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchdog_config_default() {
        let config = WatchdogConfig::default();
        assert_eq!(config.check_interval, Duration::from_secs(1));
        assert_eq!(config.establishment_timeout, Duration::from_secs(15));
    }

    #[test]
    fn test_watchdog_message_variants() {
        let link_id = AddressHash::new_from_slice(&[1u8; 32]);

        // Test SendKeepalive variant
        let keepalive_msg = WatchdogMessage::SendKeepalive {
            link_id,
            packet: Box::new(Packet::default()),
        };
        match keepalive_msg {
            WatchdogMessage::SendKeepalive { link_id: id, .. } => {
                assert_eq!(id, link_id);
            }
            _ => panic!("Expected SendKeepalive"),
        }

        // Test TeardownLink variant
        let teardown_msg = WatchdogMessage::TeardownLink {
            link_id,
            reason: TeardownReason::Stale,
        };
        match teardown_msg {
            WatchdogMessage::TeardownLink { reason, .. } => {
                assert_eq!(reason, TeardownReason::Stale);
            }
            _ => panic!("Expected TeardownLink"),
        }
    }

    #[test]
    fn test_teardown_reasons() {
        assert_eq!(TeardownReason::EstablishmentTimeout, TeardownReason::EstablishmentTimeout);
        assert_eq!(TeardownReason::Stale, TeardownReason::Stale);
        assert_eq!(TeardownReason::KeepaliveTimeout, TeardownReason::KeepaliveTimeout);
        assert_eq!(TeardownReason::Closed, TeardownReason::Closed);

        // Different reasons should not be equal
        assert_ne!(TeardownReason::Stale, TeardownReason::Closed);
    }

    #[test]
    fn test_watchdog_config_custom() {
        let config = WatchdogConfig {
            check_interval: Duration::from_millis(500),
            establishment_timeout: Duration::from_secs(30),
        };

        assert_eq!(config.check_interval, Duration::from_millis(500));
        assert_eq!(config.establishment_timeout, Duration::from_secs(30));
    }
}
