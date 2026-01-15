//! Local interface implementations for daemon mode IPC.
//!
//! This module provides `LocalServerInterface` and `LocalClientInterface` which handle
//! bidirectional packet relay between the daemon and local client processes using
//! HDLC framing over Unix sockets (or TCP on Windows).
//!
//! The protocol matches the Python implementation's LocalInterface for compatibility.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::iface::hdlc::Hdlc;
use crate::iface::{Interface, InterfaceContext, InterfaceManager, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

use super::addr::{connect, IpcListener, IpcStream, ListenerAddr};

/// Packet tracing for debugging (disabled by default).
const PACKET_TRACE: bool = false;

/// Reconnection delay for client interface.
const RECONNECT_DELAY: Duration = Duration::from_secs(8);

/// Buffer size for packet handling.
const BUFFER_SIZE: usize = core::mem::size_of::<Packet>() * 2;

/// Local server interface for daemon mode.
///
/// Listens for connections from local client processes and relays packets
/// between them and the daemon's network interfaces. Each connected client
/// spawns a new `LocalClientInterface` to handle the bidirectional communication.
pub struct LocalServerInterface {
    addr: ListenerAddr,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl LocalServerInterface {
    /// Create a new local server interface.
    ///
    /// # Arguments
    /// * `addr` - The address to listen on (Unix socket or TCP)
    /// * `iface_manager` - Shared interface manager for spawning client interfaces
    pub fn new(addr: ListenerAddr, iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>) -> Self {
        Self { addr, iface_manager }
    }

    /// Spawn the server interface and start accepting connections.
    ///
    /// This function runs until cancelled, accepting new client connections
    /// and spawning a `LocalClientInterface` for each one.
    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().await.addr.clone() };
        let iface_manager = { context.inner.lock().await.iface_manager.clone() };

        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let listener = match IpcListener::bind(&addr).await {
                Ok(listener) => listener,
                Err(e) => {
                    log::warn!("local_server: couldn't bind to {}: {}", addr.display(), e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            log::info!("local_server: listening on {}", addr.display());

            // Task to drain TX messages (server doesn't transmit directly)
            let tx_task = {
                let cancel = context.cancel.clone();
                let tx_channel = tx_channel.clone();

                tokio::spawn(async move {
                    loop {
                        if cancel.is_cancelled() {
                            break;
                        }

                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                break;
                            }
                            // Drain TX messages - server broadcasts through connected clients
                            _ = tx_channel.recv() => {}
                        }
                    }
                })
            };

            let cancel = context.cancel.clone();

            // Accept connections loop
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    }

                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                log::info!(
                                    "local_server: new client <{}> connected to {}",
                                    peer_addr,
                                    addr.display()
                                );

                                let mut iface_manager = iface_manager.lock().await;

                                // Spawn a local client interface to handle this connection.
                                // Local client interfaces always receive packets regardless
                                // of the transport's broadcast setting.
                                iface_manager.spawn_local_client(
                                    LocalClientInterface::new_from_stream(peer_addr, stream),
                                    LocalClientInterface::spawn,
                                );
                            }
                            Err(e) => {
                                log::warn!("local_server: accept error: {}", e);
                            }
                        }
                    }
                }
            }

            let _ = tokio::join!(tx_task);
        }
    }
}

impl Interface for LocalServerInterface {
    fn mtu() -> usize {
        2048
    }
}

/// Local client interface for daemon mode.
///
/// Handles bidirectional packet relay between a local client process and
/// the daemon. Can be created either as a server-side handler for incoming
/// connections or as a client connecting to an existing daemon.
pub struct LocalClientInterface {
    /// Peer address for logging.
    peer_addr: String,
    /// Address to connect to (if connecting as client).
    connect_addr: Option<ListenerAddr>,
    /// Pre-established stream (if accepting from server).
    stream: Option<IpcStream>,
}

impl LocalClientInterface {
    /// Create a new client interface that will connect to a daemon.
    ///
    /// # Arguments
    /// * `addr` - The daemon address to connect to
    pub fn new(addr: ListenerAddr) -> Self {
        Self {
            peer_addr: addr.display(),
            connect_addr: Some(addr),
            stream: None,
        }
    }

    /// Create a client interface from an already-established stream.
    ///
    /// Used by `LocalServerInterface` when accepting connections.
    pub fn new_from_stream(peer_addr: String, stream: IpcStream) -> Self {
        Self {
            peer_addr,
            connect_addr: None,
            stream: Some(stream),
        }
    }

    /// Spawn the client interface and handle bidirectional packet relay.
    ///
    /// For server-side clients (pre-established stream), this runs until
    /// the connection closes or is cancelled.
    ///
    /// For client-side connections, this includes reconnection logic.
    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let peer_addr = { context.inner.lock().await.peer_addr.clone() };
        let connect_addr = { context.inner.lock().await.connect_addr.clone() };
        let iface_address = context.channel.address;
        let mut stream = { context.inner.lock().await.stream.take() };

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        // If we have a pre-established stream, run once (server-side client)
        // Otherwise, loop with reconnection (client-side)
        let mut running = stream.is_some();

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            // Get or establish stream
            let current_stream = match stream.take() {
                Some(s) => {
                    running = false; // Server-side: don't reconnect
                    Ok(s)
                }
                None => {
                    if let Some(ref addr) = connect_addr {
                        connect(addr).await
                    } else {
                        // Server-side connection closed, exit
                        break;
                    }
                }
            };

            let current_stream = match current_stream {
                Ok(s) => s,
                Err(e) => {
                    if !running {
                        // Server-side: connection lost, exit
                        log::info!("local_client: connection to <{}> lost: {}", peer_addr, e);
                        break;
                    }
                    log::debug!(
                        "local_client: couldn't connect to <{}>: {}. Retrying in {:?}",
                        peer_addr,
                        e,
                        RECONNECT_DELAY
                    );
                    tokio::time::sleep(RECONNECT_DELAY).await;
                    continue;
                }
            };

            log::info!("local_client: connected to <{}>", peer_addr);

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            // Split the stream for bidirectional I/O
            let (read_half, write_half) = tokio::io::split(current_stream);

            // Receive task: read HDLC frames and forward packets to transport
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let mut reader = read_half;
                let rx_channel = rx_channel.clone();
                let peer_addr = peer_addr.clone();

                tokio::spawn(async move {
                    let mut hdlc_rx_buffer = [0u8; BUFFER_SIZE];
                    let mut rx_buffer = [0u8; BUFFER_SIZE + (BUFFER_SIZE / 2)];
                    let mut read_buffer = [0u8; BUFFER_SIZE * 16];

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                break;
                            }
                            _ = stop.cancelled() => {
                                break;
                            }
                            result = reader.read(&mut read_buffer[..]) => {
                                match result {
                                    Ok(0) => {
                                        log::info!("local_client: connection to <{}> closed", peer_addr);
                                        stop.cancel();
                                        break;
                                    }
                                    Ok(n) => {
                                        // Process bytes, looking for HDLC frames
                                        for &byte in read_buffer.iter().take(n) {
                                            // Push byte to end of buffer
                                            rx_buffer[BUFFER_SIZE - 1] = byte;

                                            // Check for complete HDLC frame
                                            if let Some(frame) = Hdlc::find(&rx_buffer[..]) {
                                                let frame_buffer = &mut rx_buffer[frame.0..frame.1 + 1];
                                                let mut output = OutputBuffer::new(&mut hdlc_rx_buffer[..]);

                                                if Hdlc::decode(frame_buffer, &mut output).is_ok() {
                                                    if let Ok(packet) = Packet::deserialize(
                                                        &mut InputBuffer::new(output.as_slice())
                                                    ) {
                                                        if PACKET_TRACE {
                                                            log::debug!(
                                                                "local_client: rx << ({}) {}",
                                                                iface_address,
                                                                packet
                                                            );
                                                        }
                                                        let _ = rx_channel.send(RxMessage {
                                                            address: iface_address,
                                                            packet
                                                        }).await;
                                                    } else {
                                                        log::warn!("local_client: couldn't decode packet");
                                                    }
                                                } else {
                                                    log::warn!("local_client: couldn't decode hdlc frame");
                                                }

                                                // Clear processed frame
                                                frame_buffer.fill(0);
                                            } else {
                                                // Shift buffer left
                                                rx_buffer.copy_within(1.., 0);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("local_client: read error from <{}>: {}", peer_addr, e);
                                        stop.cancel();
                                        break;
                                    }
                                }
                            }
                        }
                    }
                })
            };

            // Transmit task: receive packets from transport and send as HDLC frames
            let tx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let tx_channel = tx_channel.clone();
                let mut writer = write_half;
                let peer_addr = peer_addr.clone();

                tokio::spawn(async move {
                    let mut hdlc_tx_buffer = [0u8; BUFFER_SIZE];
                    let mut tx_buffer = [0u8; BUFFER_SIZE];

                    loop {
                        if stop.is_cancelled() {
                            break;
                        }

                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                break;
                            }
                            _ = stop.cancelled() => {
                                break;
                            }
                            Some(message) = tx_channel.recv() => {
                                let packet = message.packet;
                                if PACKET_TRACE {
                                    log::debug!("local_client: tx >> ({}) {}", iface_address, packet);
                                }

                                let mut output = OutputBuffer::new(&mut tx_buffer);
                                if packet.serialize(&mut output).is_ok() {
                                    let mut hdlc_output = OutputBuffer::new(&mut hdlc_tx_buffer[..]);

                                    if Hdlc::encode(output.as_slice(), &mut hdlc_output).is_ok() {
                                        if let Err(e) = writer.write_all(hdlc_output.as_slice()).await {
                                            log::warn!("local_client: write error to <{}>: {}", peer_addr, e);
                                            stop.cancel();
                                            break;
                                        }
                                        if let Err(e) = writer.flush().await {
                                            log::warn!("local_client: flush error to <{}>: {}", peer_addr, e);
                                            stop.cancel();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                })
            };

            // Wait for both tasks to complete
            let _ = tokio::join!(tx_task, rx_task);

            log::info!("local_client: disconnected from <{}>", peer_addr);

            // If not reconnecting, exit the loop
            if !running && connect_addr.is_none() {
                break;
            }
        }

        iface_stop.cancel();
    }
}

impl Interface for LocalClientInterface {
    fn mtu() -> usize {
        2048
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_client_interface_creation() {
        let addr = ListenerAddr::localhost(37428);
        let client = LocalClientInterface::new(addr);
        assert!(client.connect_addr.is_some());
        assert!(client.stream.is_none());
    }
}
