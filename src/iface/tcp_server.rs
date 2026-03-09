use alloc::string::String;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::config::InterfaceConfig;
use crate::error::RnsError;
use crate::iface::stats::{InterfaceMetadata, InterfaceMode};

use super::tcp_client::TcpClient;
use super::tcp_options::configure_tcp_socket;
use super::{Interface, InterfaceContext, InterfaceManager};

/// TCP server interface supporting both HDLC and KISS framing.
///
/// Accepted client connections inherit the server's framing mode.
pub struct TcpServer {
    addr: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    /// When true, use KISS framing instead of HDLC for all clients
    kiss_framing: bool,
    /// Interface operating mode from config
    mode: Option<InterfaceMode>,
    /// Interface bitrate from config
    bitrate: Option<u64>,
    /// Whether interface can transmit packets
    dir_out: Option<bool>,
    /// Per-interface announce rate target in seconds
    announce_rate_target: Option<u64>,
    /// Per-interface announce rate grace violations
    announce_rate_grace: Option<u32>,
    /// Per-interface announce rate penalty in seconds
    announce_rate_penalty: Option<u64>,
}

impl TcpServer {
    /// Create a new TCP server with HDLC framing (default).
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
            kiss_framing: false,
            mode: None,
            bitrate: None,
            dir_out: None,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
        }
    }

    /// Create a new TCP server with the specified framing mode.
    pub fn new_with_framing<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
        kiss_framing: bool,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
            kiss_framing,
            mode: None,
            bitrate: None,
            dir_out: None,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
        }
    }

    /// Enable KISS framing (builder pattern).
    pub fn with_kiss_framing(mut self) -> Self {
        self.kiss_framing = true;
        self
    }

    /// Apply configuration from an InterfaceConfig.
    pub fn with_config(mut self, config: &InterfaceConfig) -> Self {
        self.mode = config.mode;
        self.bitrate = config.bitrate;
        self.dir_out = Some(config.outgoing);
        self.announce_rate_target = config.announce_rate_target;
        self.announce_rate_grace = config.announce_rate_grace;
        self.announce_rate_penalty = config.announce_rate_penalty;
        self
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let (addr, kiss_framing, mode, bitrate, dir_out,
             announce_rate_target, announce_rate_grace, announce_rate_penalty) = {
            let inner = context.inner.lock().await;
            (inner.addr.clone(), inner.kiss_framing, inner.mode, inner.bitrate,
             inner.dir_out, inner.announce_rate_target, inner.announce_rate_grace,
             inner.announce_rate_penalty)
        };
        let iface_address = context.channel.address;

        let iface_manager = { context.inner.lock().await.iface_manager.clone() };

        // Create interface metadata for stats tracking.
        // Name matches Python's TCPServerInterface.__str__() format (no framing suffix).
        let framing_type = if kiss_framing { "KISS" } else { "HDLC" };
        let effective_bitrate = bitrate.unwrap_or(10_000_000); // BITRATE_GUESS = 10 Mbps
        let mut meta = InterfaceMetadata::new(
            format!("TCPServerInterface[{}]", addr),
            "TCPServer",
            "TCPServerInterface",
            addr.clone(),
        )
        .with_bitrate(effective_bitrate)
        .with_direction(true, dir_out.unwrap_or(true))
        .with_autoconfigure_mtu()
        .with_hw_mtu(262144);

        // Apply interface mode from config
        if let Some(m) = mode {
            meta = meta.with_mode(m);
        }

        // Apply announce rate limiting from config
        if let Some(target) = announce_rate_target {
            meta = meta.with_announce_rate(
                target,
                announce_rate_grace.unwrap_or(0),
                announce_rate_penalty.unwrap_or(0),
            );
        }

        meta.optimise_mtu();
        let metadata = Arc::new(meta);

        // Register with interface registry if available
        let registry = context.interface_registry.clone();
        if let Some(ref reg) = registry {
            reg.register(iface_address, metadata.clone()).await;
        }

        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let listener = TcpListener::bind(addr.clone())
                .await
                .map_err(|_| RnsError::ConnectionError);

            if listener.is_err() {
                log::warn!("tcp_server: couldn't bind to <{}>", addr);
                metadata.set_online(false);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            // Mark interface as online when listening
            metadata.set_online(true);
            log::info!("tcp_server: listen on <{}>", addr);

            let listener = listener.unwrap();

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
                            // Skip all tx messages
                            _ = tx_channel.recv() => {}
                        }
                    }
                })
            };

            let cancel = context.cancel.clone();

            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    }

                    client = listener.accept() => {
                        if let Ok((stream, peer_addr)) = client {
                            log::info!(
                                "tcp_server: new client <{}> connected to <{}> ({})",
                                peer_addr,
                                addr,
                                framing_type
                            );

                            // Configure TCP socket options (keepalive, nodelay, etc.)
                            if let Err(e) = configure_tcp_socket(&stream) {
                                log::warn!("tcp_server: failed to configure socket options for {}: {}", peer_addr, e);
                            }

                            let mut iface_manager = iface_manager.lock().await;

                            // Spawn client with the same framing mode as the server.
                            // Propagate config from server to spawned client
                            // (Python: TCPInterface.py:576-619).
                            let client_name = format!("TCPInterface[{}]", peer_addr);
                            let mut client = TcpClient::new_from_stream_with_framing(
                                peer_addr.to_string(), stream, kiss_framing,
                            );
                            // Propagate server config to spawned client
                            client.mode = mode;
                            client.bitrate = bitrate;
                            client.dir_out = dir_out;
                            client.announce_rate_target = announce_rate_target;
                            client.announce_rate_grace = announce_rate_grace;
                            client.announce_rate_penalty = announce_rate_penalty;

                            iface_manager.spawn(
                                client,
                                TcpClient::spawn,
                                &client_name,
                            );
                        }
                    }
                }
            }

            let _ = tokio::join!(tx_task);
        }

        // Unregister from interface registry on exit
        if let Some(ref reg) = registry {
            reg.unregister(&iface_address).await;
        }
    }
}

impl Interface for TcpServer {
    /// TCP interface hardware MTU (matching Python's TCPInterface.HW_MTU = 262144 = 256KB).
    fn mtu() -> usize {
        262144
    }
}
