//! Shared protocol helpers for rncp modes.
//!
//! This module provides common protocol operations used by send and fetch modes:
//! - Transport interface setup
//! - Announce discovery
//! - Link establishment and activation

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reticulum::cli::format::format_hash;
use reticulum::destination::link::{LinkEvent, LinkEventData, LinkStatus};
use reticulum::destination::DestinationDesc;
use reticulum::hash::AddressHash;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::link_handle::LinkHandle;
use reticulum::transport::Transport;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;

/// Error type for protocol operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// Operation timed out before completing.
    Timeout,
    /// Operation was cancelled via the running flag.
    Cancelled,
    /// Link was closed unexpectedly.
    LinkClosed,
    /// Path to destination not found.
    PathNotFound,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::Timeout => write!(f, "operation timed out"),
            ProtocolError::Cancelled => write!(f, "operation cancelled"),
            ProtocolError::LinkClosed => write!(f, "link closed unexpectedly"),
            ProtocolError::PathNotFound => write!(f, "path not found"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Set up TCP interfaces on a transport.
///
/// Adds TCP server and/or client interfaces based on the provided addresses.
///
/// # Arguments
/// * `transport` - The transport to configure
/// * `tcp_server` - Optional address to listen on (e.g., "127.0.0.1:4242")
/// * `tcp_client` - Optional address to connect to
pub async fn setup_transport_interfaces(
    transport: &Transport,
    tcp_server: Option<&str>,
    tcp_client: Option<&str>,
) {
    if let Some(server_addr) = tcp_server {
        log::info!("Starting TCP server on {}", server_addr);
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(
                TcpServer::new(server_addr, transport.iface_manager()),
                TcpServer::spawn,
            );
    }

    if let Some(client_addr) = tcp_client {
        log::info!("Connecting TCP client to {}", client_addr);
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(client_addr), TcpClient::spawn);
    }
}

/// Wait for an announce from a specific destination.
///
/// Listens for announce events and returns when an announce from the target
/// destination is received, or returns an error on timeout/cancellation.
///
/// # Arguments
/// * `announce_rx` - Broadcast receiver for announce events
/// * `dest_hash` - The destination hash to wait for
/// * `timeout` - Maximum time to wait
/// * `running` - Atomic flag that signals cancellation when set to false
/// * `silent` - If true, suppress status output
///
/// # Returns
/// The destination descriptor on success, or an error
pub async fn wait_for_announce(
    announce_rx: &mut BroadcastReceiver<reticulum::transport::AnnounceEvent>,
    dest_hash: &AddressHash,
    timeout: Duration,
    running: &Arc<AtomicBool>,
    silent: bool,
) -> Result<DestinationDesc, ProtocolError> {
    if !silent {
        println!("Path to {} requested", format_hash(dest_hash.as_slice()));
    }

    let deadline = tokio::time::Instant::now() + timeout;

    while tokio::time::Instant::now() < deadline && running.load(Ordering::SeqCst) {
        tokio::select! {
            Ok(event) = announce_rx.recv() => {
                let announced_hash = event.destination.lock().await.desc.address_hash;
                if announced_hash == *dest_hash {
                    log::info!("Received announce from target destination");
                    return Ok(event.destination.lock().await.desc);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Continue waiting
            }
        }
    }

    if !running.load(Ordering::SeqCst) {
        Err(ProtocolError::Cancelled)
    } else {
        Err(ProtocolError::PathNotFound)
    }
}

/// Wait for a link to become active.
///
/// Listens for link events and returns when the link activates, or returns
/// an error on timeout, cancellation, or if the link closes.
///
/// # Arguments
/// * `link` - The link to wait for
/// * `link_id` - The link ID to match events against
/// * `link_events` - Receiver for link events
/// * `timeout` - Maximum time to wait
/// * `running` - Atomic flag that signals cancellation when set to false
/// * `silent` - If true, suppress status output
///
/// # Returns
/// Ok(()) on success, or an error
pub async fn wait_for_link_activation(
    link: &LinkHandle,
    link_id: &reticulum::destination::link::LinkId,
    link_events: &mut BroadcastReceiver<LinkEventData>,
    timeout: Duration,
    running: &Arc<AtomicBool>,
    silent: bool,
) -> Result<(), ProtocolError> {
    let link_id_hex = hex::encode(&link_id.as_slice()[..8]);
    let deadline = tokio::time::Instant::now() + timeout;

    if !silent {
        let dest_hash = link.destination().address_hash;
        println!(
            "Establishing link with {}",
            format_hash(dest_hash.as_slice())
        );
    }

    while tokio::time::Instant::now() < deadline && running.load(Ordering::SeqCst) {
        tokio::select! {
            Ok(event) = link_events.recv() => {
                if event.id == *link_id {
                    match event.event {
                        LinkEvent::Activated => {
                            log::info!("Link {} activated", link_id_hex);
                            return Ok(());
                        }
                        LinkEvent::Closed => {
                            return Err(ProtocolError::LinkClosed);
                        }
                        _ => {}
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Also check link status directly
                if link.status().await == LinkStatus::Active {
                    log::info!("Link {} activated", link_id_hex);
                    return Ok(());
                }
            }
        }
    }

    if !running.load(Ordering::SeqCst) {
        Err(ProtocolError::Cancelled)
    } else {
        Err(ProtocolError::Timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_error_display() {
        assert_eq!(ProtocolError::Timeout.to_string(), "operation timed out");
        assert_eq!(ProtocolError::Cancelled.to_string(), "operation cancelled");
        assert_eq!(
            ProtocolError::LinkClosed.to_string(),
            "link closed unexpectedly"
        );
        assert_eq!(ProtocolError::PathNotFound.to_string(), "path not found");
    }

    #[test]
    fn test_protocol_error_equality() {
        assert_eq!(ProtocolError::Timeout, ProtocolError::Timeout);
        assert_ne!(ProtocolError::Timeout, ProtocolError::Cancelled);
    }

    #[tokio::test]
    async fn test_wait_for_announce_cancelled() {
        // Create a running flag and set it to false (cancelled)
        let running = Arc::new(AtomicBool::new(false));
        let (tx, _rx) = tokio::sync::broadcast::channel(1);
        let mut announce_rx = tx.subscribe();

        let dest_hash = AddressHash::new([0u8; 16]);
        let timeout = Duration::from_millis(100);

        let result =
            wait_for_announce(&mut announce_rx, &dest_hash, timeout, &running, true).await;

        assert!(result.is_err());
        match result {
            Err(ProtocolError::Cancelled) => {}
            _ => panic!("Expected Cancelled error"),
        }
    }

    #[tokio::test]
    async fn test_wait_for_announce_timeout() {
        // Create a running flag that stays true
        let running = Arc::new(AtomicBool::new(true));
        let (tx, _rx) = tokio::sync::broadcast::channel(1);
        let mut announce_rx = tx.subscribe();

        let dest_hash = AddressHash::new([0u8; 16]);
        let timeout = Duration::from_millis(50); // Very short timeout

        let result =
            wait_for_announce(&mut announce_rx, &dest_hash, timeout, &running, true).await;

        assert!(result.is_err());
        match result {
            Err(ProtocolError::PathNotFound) => {}
            _ => panic!("Expected PathNotFound error"),
        }
    }

    #[test]
    fn test_running_flag_cancellation() {
        // Test that the running flag works correctly for cancellation
        let running = Arc::new(AtomicBool::new(true));
        assert!(running.load(Ordering::SeqCst));

        running.store(false, Ordering::SeqCst);
        assert!(!running.load(Ordering::SeqCst));
    }
}
