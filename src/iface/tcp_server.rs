use alloc::string::String;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::error::RnsError;
use crate::iface::stats::InterfaceMetadata;

use super::tcp_client::TcpClient;
use super::tcp_options::configure_tcp_socket;
use super::{Interface, InterfaceContext, InterfaceManager};

pub struct TcpServer {
    addr: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl TcpServer {
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().await.addr.clone() };
        let iface_address = context.channel.address;

        let iface_manager = { context.inner.lock().await.iface_manager.clone() };

        // Create interface metadata for stats tracking
        let metadata = Arc::new(InterfaceMetadata::new(
            format!("TCPServerInterface[{}]", addr),
            "TCPServer",
            "TCPServerInterface",
            addr.clone(),
        ));

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
                                "tcp_server: new client <{}> connected to <{}>",
                                peer_addr,
                                addr
                            );

                            // Configure TCP socket options (keepalive, nodelay, etc.)
                            if let Err(e) = configure_tcp_socket(&stream) {
                                log::warn!("tcp_server: failed to configure socket options for {}: {}", peer_addr, e);
                            }

                            let mut iface_manager = iface_manager.lock().await;

                            iface_manager.spawn(
                                TcpClient::new_from_stream(peer_addr.to_string(), stream),
                                TcpClient::spawn,
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
