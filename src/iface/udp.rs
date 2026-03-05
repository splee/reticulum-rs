use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::RxMessage;
use crate::iface::stats::InterfaceMetadata;
use crate::packet::Packet;
use crate::serde::Serialize;

use super::{Interface, InterfaceContext};

// TODO: Configure via features
const PACKET_TRACE: bool = false;

pub struct UdpInterface {
    bind_addr: String,
    forward_addr: Option<String>
}

impl UdpInterface {
    pub fn new<T: Into<String>>(
        bind_addr: T,
        forward_addr: Option<T>
    ) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            forward_addr: forward_addr.map(Into::into),
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let bind_addr = { context.inner.lock().await.bind_addr.clone() };
        let forward_addr = { context.inner.lock().await.forward_addr.clone() };
        let iface_address = context.channel.address;

        // Create interface metadata for stats tracking
        let metadata = Arc::new(InterfaceMetadata::new(
            format!("UDPInterface[{}]", bind_addr),
            "UDP",
            "UDPInterface",
            bind_addr.clone(),
        ));

        // Register with interface registry if available
        let registry = context.interface_registry.clone();
        if let Some(ref reg) = registry {
            reg.register(iface_address, metadata.clone()).await;
        }

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let socket = UdpSocket::bind(bind_addr.clone())
                .await
                .map_err(|_| RnsError::ConnectionError);

            if socket.is_err() {
                log::info!("udp_interface: couldn't bind to <{}>", bind_addr);
                metadata.set_online(false);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            let socket = socket.unwrap();
            let read_socket = Arc::new(socket);
            let write_socket = read_socket.clone();

            // Mark interface as online
            metadata.set_online(true);
            log::info!("udp_interface bound to <{}>", bind_addr);

            const BUFFER_SIZE: usize = core::mem::size_of::<Packet>() * 3;

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let socket = read_socket;
                let rx_channel = rx_channel.clone();
                let metadata = metadata.clone();

                tokio::spawn(async move {
                    loop {
                        let mut rx_buffer = [0u8; BUFFER_SIZE];

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            _ = stop.cancelled() => {
                                    break;
                            }
                            result = socket.recv_from(&mut rx_buffer) => {
                                match result {
                                    Ok((0, _)) => {
                                        log::warn!("udp_interface: connection closed");
                                        stop.cancel();
                                        break;
                                    }
                                    Ok((n, _in_addr)) => {
                                        // Track received bytes for stats
                                        metadata.add_rx_bytes(n as u64);

                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&rx_buffer[..n])) {
                                            if PACKET_TRACE {
                                                log::trace!("udp_interface: rx << ({}) {}", iface_address, packet);
                                            }
                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                        } else {
                                            log::warn!("udp_interface: couldn't decode packet");
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("udp_interface: connection error {}", e);
                                        break;
                                    }
                                }
                            },
                        };
                    }
                })
            };

            if let Some(forward_addr) = forward_addr.clone() {
                // Start transmit task
                let tx_task = {
                    let cancel = cancel.clone();
                    let tx_channel = tx_channel.clone();
                    let socket = write_socket;
                    let metadata = metadata.clone();

                    tokio::spawn(async move {
                        loop {
                            if stop.is_cancelled() {
                                break;
                            }

                            let mut tx_buffer = [0u8; BUFFER_SIZE];

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
                                        log::trace!("udp_interface: tx >> ({}) {}", iface_address, packet);
                                    }
                                    let mut output = OutputBuffer::new(&mut tx_buffer);
                                    if packet.serialize(&mut output).is_ok() {
                                        let output_slice = output.as_slice();

                                        // Track transmitted bytes for stats
                                        metadata.add_tx_bytes(output_slice.len() as u64);

                                        let _ = socket.send_to(output_slice, &forward_addr).await;
                                    }
                                }
                            };
                        }
                    })
                };
                if let Err(e) = tx_task.await {
                    log::error!("udp_interface: tx task panicked: {:?}", e);
                }
            }

            if let Err(e) = rx_task.await {
                log::error!("udp_interface: rx task panicked: {:?}", e);
            }

            // Mark interface as offline when closed
            metadata.set_online(false);
            log::info!("udp_interface <{}>: closed", bind_addr);
        }

        // Unregister from interface registry on exit
        if let Some(ref reg) = registry {
            reg.unregister(&iface_address).await;
        }
    }
}

impl Interface for UdpInterface {
    fn mtu() -> usize {
        1064 // Reticulum UDP MTU (matches Python implementation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_mtu_1064() {
        // Verify UDP MTU matches Python implementation (1064 bytes)
        // Python: RNS/Interfaces/UDPInterface.py UDP_MTU = 1064
        assert_eq!(UdpInterface::mtu(), 1064);
    }
}
