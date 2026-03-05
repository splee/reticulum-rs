pub mod auto_interface;
pub mod hdlc;
pub mod kiss;
pub mod serial;
pub mod tcp_options;

pub mod kaonic;
pub mod tcp_client;
pub mod tcp_server;
pub mod udp;

pub mod registry;
pub mod stats;

pub use registry::{InterfaceRegistry, InterfaceStatsSnapshot};
pub use stats::{InterfaceMetadata, InterfaceMode};

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::task;
use tokio_util::sync::CancellationToken;

use crate::hash::AddressHash;
use crate::hash::Hash;
use crate::packet::Packet;

pub type InterfaceTxSender = mpsc::Sender<TxMessage>;
pub type InterfaceTxReceiver = mpsc::Receiver<TxMessage>;

pub type InterfaceRxSender = mpsc::Sender<RxMessage>;
pub type InterfaceRxReceiver = mpsc::Receiver<RxMessage>;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TxMessageType {
    Broadcast(Option<AddressHash>),
    Direct(AddressHash),
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct TxMessage {
    pub tx_type: TxMessageType,
    pub packet: Packet,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct RxMessage {
    pub address: AddressHash, // Address of source interface
    pub packet: Packet,       // Received packet
}

pub struct InterfaceChannel {
    pub address: AddressHash,
    pub rx_channel: InterfaceRxSender,
    pub tx_channel: InterfaceTxReceiver,
    pub stop: CancellationToken,
}

impl InterfaceChannel {
    pub fn make_rx_channel(cap: usize) -> (InterfaceRxSender, InterfaceRxReceiver) {
        mpsc::channel(cap)
    }

    pub fn make_tx_channel(cap: usize) -> (InterfaceTxSender, InterfaceTxReceiver) {
        mpsc::channel(cap)
    }

    pub fn new(
        rx_channel: InterfaceRxSender,
        tx_channel: InterfaceTxReceiver,
        address: AddressHash,
        stop: CancellationToken,
    ) -> Self {
        Self {
            address,
            rx_channel,
            tx_channel,
            stop,
        }
    }

    pub fn address(&self) -> &AddressHash {
        &self.address
    }

    pub fn split(self) -> (InterfaceRxSender, InterfaceTxReceiver) {
        (self.rx_channel, self.tx_channel)
    }
}

pub trait Interface {
    fn mtu() -> usize;
}

struct LocalInterface {
    address: AddressHash,
    tx_send: InterfaceTxSender,
    stop: CancellationToken,
    /// True if this is a local IPC client interface (should always receive packets)
    is_local_client: bool,
}

pub struct InterfaceContext<T: Interface> {
    pub inner: Arc<Mutex<T>>,
    pub channel: InterfaceChannel,
    pub cancel: CancellationToken,
    /// Optional interface registry for stats tracking.
    /// When set, interfaces should register themselves and track rx/tx bytes.
    pub interface_registry: Option<Arc<InterfaceRegistry>>,
}

pub struct InterfaceManager {
    counter: usize,
    rx_recv: Arc<tokio::sync::Mutex<InterfaceRxReceiver>>,
    rx_send: InterfaceRxSender,
    cancel: CancellationToken,
    ifaces: Vec<LocalInterface>,
    /// Optional interface registry for stats tracking
    interface_registry: Option<Arc<InterfaceRegistry>>,
}

impl InterfaceManager {
    pub fn new(rx_cap: usize) -> Self {
        let (rx_send, rx_recv) = InterfaceChannel::make_rx_channel(rx_cap);
        let rx_recv = Arc::new(tokio::sync::Mutex::new(rx_recv));

        Self {
            counter: 0,
            rx_recv,
            rx_send,
            cancel: CancellationToken::new(),
            ifaces: Vec::new(),
            interface_registry: None,
        }
    }

    /// Set the interface registry for stats tracking.
    pub fn set_interface_registry(&mut self, registry: Arc<InterfaceRegistry>) {
        self.interface_registry = Some(registry);
    }

    /// Get the interface registry if set.
    pub fn interface_registry(&self) -> Option<Arc<InterfaceRegistry>> {
        self.interface_registry.clone()
    }

    pub fn new_channel(&mut self, tx_cap: usize) -> InterfaceChannel {
        self.new_channel_impl(tx_cap, false)
    }

    /// Create a channel for a local IPC client interface.
    /// Local client interfaces always receive packets regardless of broadcast settings.
    pub fn new_channel_local_client(&mut self, tx_cap: usize) -> InterfaceChannel {
        self.new_channel_impl(tx_cap, true)
    }

    fn new_channel_impl(&mut self, tx_cap: usize, is_local_client: bool) -> InterfaceChannel {
        self.counter += 1;

        let counter_bytes = self.counter.to_le_bytes();
        let address = AddressHash::new_from_hash(&Hash::new_from_slice(&counter_bytes[..]));

        let (tx_send, tx_recv) = InterfaceChannel::make_tx_channel(tx_cap);

        log::debug!("iface: create channel {} (local_client={})", address, is_local_client);

        let stop = CancellationToken::new();

        self.ifaces.push(LocalInterface {
            address,
            tx_send,
            stop: stop.clone(),
            is_local_client,
        });

        InterfaceChannel {
            rx_channel: self.rx_send.clone(),
            tx_channel: tx_recv,
            address,
            stop,
        }
    }

    pub fn new_context<T: Interface>(&mut self, inner: T) -> InterfaceContext<T> {
        self.new_context_impl(inner, false)
    }

    /// Create a context for a local IPC client interface.
    pub fn new_context_local_client<T: Interface>(&mut self, inner: T) -> InterfaceContext<T> {
        self.new_context_impl(inner, true)
    }

    fn new_context_impl<T: Interface>(&mut self, inner: T, is_local_client: bool) -> InterfaceContext<T> {
        let channel = if is_local_client {
            self.new_channel_local_client(1)
        } else {
            self.new_channel(1)
        };

        let inner = Arc::new(Mutex::new(inner));

        InterfaceContext::<T> {
            inner: inner.clone(),
            channel,
            cancel: self.cancel.clone(),
            interface_registry: self.interface_registry.clone(),
        }
    }

    pub fn spawn<T: Interface, F, R>(&mut self, inner: T, worker: F) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.new_context(inner);
        let address = *context.channel.address();

        task::spawn(worker(context));

        address
    }

    /// Spawn a local IPC client interface.
    /// Local client interfaces always receive packets regardless of broadcast settings.
    pub fn spawn_local_client<T: Interface, F, R>(&mut self, inner: T, worker: F) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.new_context_local_client(inner);
        let address = *context.channel.address();

        task::spawn(worker(context));

        address
    }

    pub fn receiver(&self) -> Arc<tokio::sync::Mutex<InterfaceRxReceiver>> {
        self.rx_recv.clone()
    }

    pub fn cleanup(&mut self) {
        self.ifaces.retain(|iface| !iface.stop.is_cancelled());
    }

    pub async fn send(&self, message: TxMessage) {
        log::debug!(
            "iface_manager: send {:?} pkt_type={:?} to {} interfaces (local_clients: {})",
            message.tx_type,
            message.packet.header.packet_type,
            self.ifaces.len(),
            self.ifaces.iter().filter(|i| i.is_local_client).count()
        );
        let mut sent = false;
        for iface in &self.ifaces {
            let should_send = match &message.tx_type {
                TxMessageType::Broadcast(address) => {
                    let mut should_send = true;
                    if let Some(address) = address {
                        should_send = *address != iface.address;
                    }

                    should_send
                },
                TxMessageType::Direct(address) => *address == iface.address,
            };

            let stopped = iface.stop.is_cancelled();
            log::debug!(
                "iface_manager: considering iface {} (local_client={}, should_send={}, stopped={})",
                iface.address,
                iface.is_local_client,
                should_send,
                stopped
            );

            if should_send && !stopped {
                match iface.tx_send.send(message).await {
                    Ok(()) => {
                        log::debug!("iface_manager: sent to iface {}", iface.address);
                        sent = true;
                    }
                    Err(e) => {
                        log::warn!("iface_manager: failed to send to iface {}: {}", iface.address, e);
                    }
                }
            }
        }

        // Log warning if no interface matched for direct send (but not for every packet)
        if !sent {
            if let TxMessageType::Direct(target_addr) = &message.tx_type {
                log::debug!(
                    "iface_manager: no interface matched for direct send to {}",
                    target_addr
                );
            }
        }
    }

    /// Send a packet to all local client interfaces.
    /// This is used to forward packets from network interfaces to local IPC clients,
    /// regardless of the transport's broadcast setting.
    /// The `exclude_address` is typically the interface that received the packet.
    pub async fn send_to_local_clients(&self, packet: Packet, exclude_address: Option<AddressHash>) {
        for iface in &self.ifaces {
            if !iface.is_local_client {
                continue;
            }

            // Don't send back to the interface that received this packet
            if let Some(exclude) = &exclude_address {
                if *exclude == iface.address {
                    continue;
                }
            }

            if !iface.stop.is_cancelled() {
                let _ = iface.tx_send.send(TxMessage {
                    tx_type: TxMessageType::Broadcast(exclude_address),
                    packet,
                }).await;
            }
        }
    }

    /// Check if there are any local client interfaces connected.
    pub fn has_local_clients(&self) -> bool {
        self.ifaces.iter().any(|iface| iface.is_local_client && !iface.stop.is_cancelled())
    }

    /// Check if an interface address belongs to a local client interface.
    pub fn is_local_client(&self, address: &AddressHash) -> bool {
        self.ifaces.iter().any(|iface| &iface.address == address && iface.is_local_client)
    }

    /// Get the list of active network interface addresses (excludes local clients).
    ///
    /// Used for per-interface announce queue management (ANNOUNCE_CAP).
    pub fn network_interface_addresses(&self) -> Vec<AddressHash> {
        self.ifaces
            .iter()
            .filter(|iface| !iface.is_local_client && !iface.stop.is_cancelled())
            .map(|iface| iface.address)
            .collect()
    }

    /// Send a packet from a local client to all network interfaces.
    /// This forwards packets from IPC clients to the actual network,
    /// regardless of the transport's broadcast setting.
    /// The `from_address` is the local client interface that sent the packet.
    pub async fn send_from_local_client(&self, packet: Packet, from_address: AddressHash) {
        for iface in &self.ifaces {
            // Skip local client interfaces (don't send to other local clients from this path)
            // and skip the source interface
            if iface.is_local_client || iface.address == from_address {
                continue;
            }

            if !iface.stop.is_cancelled() {
                let _ = iface.tx_send.send(TxMessage {
                    tx_type: TxMessageType::Broadcast(Some(from_address)),
                    packet,
                }).await;
            }
        }
    }
}

impl Drop for InterfaceManager {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
