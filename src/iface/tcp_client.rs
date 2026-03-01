use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::RxMessage;
use crate::iface::stats::InterfaceMetadata;
use crate::packet::Packet;
use crate::serde::Serialize;

use tokio::io::AsyncReadExt;

use alloc::string::String;

use super::hdlc::Hdlc;
use super::kiss::Kiss;
use super::tcp_options::configure_tcp_socket;
use super::{Interface, InterfaceContext};

// TODO: Configure via features
const PACKET_TRACE: bool = false;

/// TCP client interface supporting both HDLC and KISS framing.
///
/// The framing mode determines how packets are encoded on the wire:
/// - HDLC (default): Uses 0x7e delimiters with byte stuffing (0x7d escape)
/// - KISS: Uses 0xC0 delimiters with 0xDB escape sequences
///
/// Python reference: RNS/Interfaces/TCPInterface.py supports kiss_framing config option.
pub struct TcpClient {
    addr: String,
    stream: Option<TcpStream>,
    /// When true, use KISS framing instead of HDLC
    kiss_framing: bool,
}

impl TcpClient {
    /// Create a new TCP client with HDLC framing (default).
    pub fn new<T: Into<String>>(addr: T) -> Self {
        Self {
            addr: addr.into(),
            stream: None,
            kiss_framing: false,
        }
    }

    /// Create a new TCP client from an existing stream with HDLC framing.
    pub fn new_from_stream<T: Into<String>>(addr: T, stream: TcpStream) -> Self {
        Self {
            addr: addr.into(),
            stream: Some(stream),
            kiss_framing: false,
        }
    }

    /// Create a new TCP client with the specified framing mode.
    ///
    /// # Arguments
    /// * `addr` - Address to connect to (host:port)
    /// * `kiss_framing` - When true, use KISS framing instead of HDLC
    pub fn new_with_framing<T: Into<String>>(addr: T, kiss_framing: bool) -> Self {
        Self {
            addr: addr.into(),
            stream: None,
            kiss_framing,
        }
    }

    /// Create a new TCP client from an existing stream with the specified framing mode.
    pub fn new_from_stream_with_framing<T: Into<String>>(addr: T, stream: TcpStream, kiss_framing: bool) -> Self {
        Self {
            addr: addr.into(),
            stream: Some(stream),
            kiss_framing,
        }
    }

    /// Enable KISS framing (builder pattern).
    pub fn with_kiss_framing(mut self) -> Self {
        self.kiss_framing = true;
        self
    }

    /// Check if KISS framing is enabled.
    pub fn is_kiss_framing(&self) -> bool {
        self.kiss_framing
    }

    pub async fn spawn(context: InterfaceContext<TcpClient>) {
        let iface_stop = context.channel.stop.clone();
        let (addr, kiss_framing) = {
            let inner = context.inner.lock().await;
            (inner.addr.clone(), inner.kiss_framing)
        };
        let iface_address = context.channel.address;
        let mut stream = { context.inner.lock().await.stream.take() };

        // Create interface metadata for stats tracking
        let framing_type = if kiss_framing { "KISS" } else { "HDLC" };
        let metadata = Arc::new(InterfaceMetadata::new(
            format!("TCPInterface[{}]({})", addr, framing_type),
            "TCPClient",
            "TCPClientInterface",
            addr.clone(),
        ));

        // Register with interface registry if available
        let registry = context.interface_registry.clone();
        if let Some(ref reg) = registry {
            reg.register(iface_address, metadata.clone()).await;
        }

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        let mut running = true;
        loop {
            if !running || context.cancel.is_cancelled() {
                break;
            }

            let stream = {
                match stream.take() {
                    Some(stream) => {
                        running = false;
                        Ok(stream)
                    }
                    None => TcpStream::connect(addr.clone())
                        .await
                        .map_err(|_| RnsError::ConnectionError),
                }
            };

            if stream.is_err() {
                log::info!("tcp_client: couldn't connect to <{}>", addr);
                metadata.set_online(false);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            let stream = stream.unwrap();

            // Configure TCP socket options (keepalive, nodelay, etc.)
            if let Err(e) = configure_tcp_socket(&stream) {
                log::warn!("tcp_client: failed to configure socket options: {}", e);
            }

            let (read_stream, write_stream) = stream.into_split();

            // Mark interface as online
            metadata.set_online(true);
            log::info!("tcp_client connected to <{}>", addr);

            const BUFFER_SIZE: usize = core::mem::size_of::<Packet>() * 2;

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let mut stream = read_stream;
                let rx_channel = rx_channel.clone();
                let metadata = metadata.clone();

                tokio::spawn(async move {
                    let mut decode_rx_buffer = [0u8; BUFFER_SIZE];
                    let mut rx_buffer = [0u8; BUFFER_SIZE + (BUFFER_SIZE / 2)];
                    let mut tcp_buffer = [0u8; (BUFFER_SIZE * 16)];

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            _ = stop.cancelled() => {
                                    break;
                            }
                            result = stream.read(&mut tcp_buffer[..]) => {
                                    match result {
                                        Ok(0) => {
                                            log::warn!("tcp_client: connection closed");
                                            stop.cancel();
                                            break;
                                        }
                                        Ok(n) => {
                                            // Track received bytes for stats
                                            metadata.add_rx_bytes(n as u64);

                                            // TCP stream may contain several or partial frames
                                            for &byte in tcp_buffer.iter().take(n) {
                                                // Push new byte from the end of buffer
                                                rx_buffer[BUFFER_SIZE-1] = byte;

                                                // Find frame using appropriate framing mode
                                                let frame = if kiss_framing {
                                                    Kiss::find(&rx_buffer[..])
                                                } else {
                                                    Hdlc::find(&rx_buffer[..])
                                                };

                                                if let Some(frame) = frame {
                                                    // Decode frame and deserialize packet
                                                    let frame_buffer = &mut rx_buffer[frame.0..frame.1+1];
                                                    let mut output = OutputBuffer::new(&mut decode_rx_buffer[..]);

                                                    let decode_result = if kiss_framing {
                                                        Kiss::decode(frame_buffer, &mut output)
                                                    } else {
                                                        Hdlc::decode(frame_buffer, &mut output)
                                                    };

                                                    if decode_result.is_ok() {
                                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(output.as_slice())) {
                                                            if PACKET_TRACE {
                                                                log::trace!("tcp_client: rx << ({}) {}", iface_address, packet);
                                                            }
                                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                                        } else {
                                                            log::warn!("tcp_client: couldn't decode packet");
                                                        }
                                                    } else {
                                                        let framing = if kiss_framing { "kiss" } else { "hdlc" };
                                                        log::warn!("tcp_client: couldn't decode {} frame", framing);
                                                    }

                                                    // Remove current frame data
                                                    frame_buffer.fill(0);
                                                } else {
                                                    // Move data left
                                                    rx_buffer.copy_within(1.., 0);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log::warn!("tcp_client: connection error {}", e);
                                            break;
                                        }
                                    }
                                },
                        };
                    }
                })
            };

            // Start transmit task
            let tx_task = {
                let cancel = cancel.clone();
                let tx_channel = tx_channel.clone();
                let mut stream = write_stream;
                let metadata = metadata.clone();

                tokio::spawn(async move {
                    loop {
                        if stop.is_cancelled() {
                            break;
                        }

                        let mut encoded_tx_buffer = [0u8; BUFFER_SIZE];
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
                                    log::trace!("tcp_client: tx >> ({}) {}", iface_address, packet);
                                }
                                let mut output = OutputBuffer::new(&mut tx_buffer);
                                if packet.serialize(&mut output).is_ok() {
                                    // Debug: log hex dump of announce packets for wire format debugging
                                    if packet.header.packet_type == crate::packet::PacketType::Announce {
                                        let raw = output.as_slice();
                                        log::debug!(
                                            "tcp_client: TX announce to {} ({} bytes): {:02x?}",
                                            iface_address,
                                            raw.len(),
                                            &raw[..raw.len().min(60)]
                                        );
                                    }

                                    let mut encoded_output = OutputBuffer::new(&mut encoded_tx_buffer[..]);

                                    // Encode using appropriate framing mode
                                    let encode_result = if kiss_framing {
                                        Kiss::encode(output.as_slice(), &mut encoded_output)
                                    } else {
                                        Hdlc::encode(output.as_slice(), &mut encoded_output)
                                    };

                                    if encode_result.is_ok() {
                                        let encoded_slice = encoded_output.as_slice();

                                        // Track transmitted bytes for stats
                                        metadata.add_tx_bytes(encoded_slice.len() as u64);

                                        let _ = stream.write_all(encoded_slice).await;
                                        let _ = stream.flush().await;
                                    }
                                }
                            }
                        };
                    }
                })
            };

            if let Err(e) = tx_task.await {
                log::error!("tcp_client: tx task panicked: {:?}", e);
            }
            if let Err(e) = rx_task.await {
                log::error!("tcp_client: rx task panicked: {:?}", e);
            }

            // Mark interface as offline when disconnected
            metadata.set_online(false);
            log::info!("tcp_client: disconnected from <{}>", addr);
        }

        // Unregister from interface registry on exit
        if let Some(ref reg) = registry {
            reg.unregister(&iface_address).await;
        }

        iface_stop.cancel();
    }
}

impl Interface for TcpClient {
    /// TCP interface hardware MTU (matching Python's TCPInterface.HW_MTU = 262144 = 256KB).
    fn mtu() -> usize {
        262144
    }
}
