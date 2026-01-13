use alloc::sync::Arc;
use sha2::Digest;
use announce_limits::AnnounceLimits;
use announce_table::AnnounceTable;
use link_table::LinkTable;
use packet_cache::PacketCache;
use path_table::PathTable;
use rand_core::OsRng;
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::time;
use tokio_util::sync::CancellationToken;

use tokio::sync::broadcast;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;

use crate::destination::link::Link;
use crate::destination::link::LinkEventData;
use crate::destination::link::LinkHandleResult;
use crate::destination::link::LinkId;
use crate::destination::link::LinkStatus;
use crate::destination::plain::PlainDestination;
use crate::destination::DestinationAnnounce;
use crate::destination::DestinationDesc;
use crate::destination::DestinationHandleStatus;
use crate::destination::DestinationName;
use crate::destination::SingleInputDestination;
use crate::destination::SingleOutputDestination;

use crate::error::RnsError;
use crate::hash::{AddressHash, Hash};
use crate::identity::{Identity, PrivateIdentity};

use crate::iface::InterfaceManager;
use crate::iface::InterfaceRxReceiver;
use crate::iface::RxMessage;
use crate::iface::TxMessage;
use crate::iface::TxMessageType;

use crate::packet::DestinationType;
use crate::packet::Header;
use crate::packet::Packet;
use crate::packet::PacketContext;
use crate::packet::PacketDataBuffer;
use crate::packet::PacketType;
use crate::receipt::{PacketReceipt, ReceiptManager};
use crate::discovery::{InterfaceDiscoveryStorage, PythonDiscoveryHandler, DEFAULT_DISCOVERY_STAMP_VALUE};

mod announce_limits;
mod announce_table;
mod link_table;
mod packet_cache;
pub mod path_table;

// Phase 5: Transport enhancements
pub mod blackhole;
pub mod blackhole_info;
pub mod path_request;
pub mod remote_management;
pub mod reverse_table;
pub mod tunnel;

use path_request::{PathRequestManager, PathRequestTagCache};

// TODO: Configure via features
const PACKET_TRACE: bool = false;
pub const PATHFINDER_M: usize = 128; // Max hops

const INTERVAL_LINKS_CHECK: Duration = Duration::from_secs(1);
const INTERVAL_INPUT_LINK_CLEANUP: Duration = Duration::from_secs(20);
const INTERVAL_OUTPUT_LINK_RESTART: Duration = Duration::from_secs(60);
const INTERVAL_OUTPUT_LINK_REPEAT: Duration = Duration::from_secs(6);
const INTERVAL_OUTPUT_LINK_KEEP: Duration = Duration::from_secs(5);
const INTERVAL_IFACE_CLEANUP: Duration = Duration::from_secs(10);
const INTERVAL_ANNOUNCES_RETRANSMIT: Duration = Duration::from_secs(1);
const INTERVAL_KEEP_PACKET_CACHED: Duration = Duration::from_secs(180);
const INTERVAL_PACKET_CACHE_CLEANUP: Duration = Duration::from_secs(90);

// Other constants
const KEEP_ALIVE_REQUEST: u8 = 0xFF;
const KEEP_ALIVE_RESPONSE: u8 = 0xFE;

#[derive(Clone)]
pub struct ReceivedData {
    pub destination: AddressHash,
    pub data: PacketDataBuffer,
}

pub struct TransportConfig {
    name: String,
    identity: PrivateIdentity,
    broadcast: bool,
    retransmit: bool,
}

#[derive(Clone)]
pub struct AnnounceEvent {
    pub destination: Arc<Mutex<SingleOutputDestination>>,
    pub app_data: PacketDataBuffer,
}

struct TransportHandler {
    config: TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    announce_tx: broadcast::Sender<AnnounceEvent>,

    path_table: PathTable,
    announce_table: AnnounceTable,
    link_table: LinkTable,
    single_in_destinations: HashMap<AddressHash, Arc<Mutex<SingleInputDestination>>>,
    single_out_destinations: HashMap<AddressHash, Arc<Mutex<SingleOutputDestination>>>,

    announce_limits: AnnounceLimits,

    out_links: HashMap<AddressHash, Arc<Mutex<Link>>>,
    in_links: HashMap<AddressHash, Arc<Mutex<Link>>>,

    packet_cache: Mutex<PacketCache>,

    /// Path request tag deduplication cache
    path_request_tags: PathRequestTagCache,

    /// Receipt manager for tracking packet proofs
    receipt_manager: ReceiptManager,

    link_in_event_tx: broadcast::Sender<LinkEventData>,
    received_data_tx: broadcast::Sender<ReceivedData>,

    cancel: CancellationToken,
}

pub struct Transport {
    name: String,
    link_in_event_tx: broadcast::Sender<LinkEventData>,
    link_out_event_tx: broadcast::Sender<LinkEventData>,
    received_data_tx: broadcast::Sender<ReceivedData>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
    handler: Arc<Mutex<TransportHandler>>,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
}

impl TransportConfig {
    pub fn new<T: Into<String>>(name: T, identity: &PrivateIdentity, enable_transport: bool) -> Self {
        Self {
            name: name.into(),
            identity: identity.clone(),
            broadcast: enable_transport,
            retransmit: enable_transport,
        }
    }

    pub fn set_retransmit(&mut self, retransmit: bool) {
        self.retransmit = retransmit;
    }
    pub fn set_broadcast(&mut self, broadcast: bool) {
        self.broadcast = broadcast;
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            name: "tp".into(),
            identity: PrivateIdentity::new_from_rand(OsRng),
            broadcast: false,
            retransmit: false,
        }
    }
}

impl Transport {
    pub fn new(config: TransportConfig) -> Self {
        let (announce_tx, _) = tokio::sync::broadcast::channel(16);
        let (link_in_event_tx, _) = tokio::sync::broadcast::channel(16);
        let (link_out_event_tx, _) = tokio::sync::broadcast::channel(16);
        let (received_data_tx, _) = tokio::sync::broadcast::channel(16);
        let (iface_messages_tx, _) = tokio::sync::broadcast::channel(16);

        let iface_manager = InterfaceManager::new(16);

        let rx_receiver = iface_manager.receiver();

        let iface_manager = Arc::new(Mutex::new(iface_manager));

        let cancel = CancellationToken::new();
        let name = config.name.clone();
        let handler = Arc::new(Mutex::new(TransportHandler {
            config,
            iface_manager: iface_manager.clone(),
            announce_table: AnnounceTable::new(),
            link_table: LinkTable::new(),
            path_table: PathTable::new(),
            single_in_destinations: HashMap::new(),
            single_out_destinations: HashMap::new(),
            announce_limits: AnnounceLimits::new(),
            out_links: HashMap::new(),
            in_links: HashMap::new(),
            packet_cache: Mutex::new(PacketCache::new()),
            path_request_tags: PathRequestTagCache::new(),
            receipt_manager: ReceiptManager::new(1024),
            announce_tx,
            link_in_event_tx: link_in_event_tx.clone(),
            received_data_tx: received_data_tx.clone(),
            cancel: cancel.clone(),
        }));

        {
            let handler = handler.clone();
            tokio::spawn(manage_transport(
                handler,
                rx_receiver,
                iface_messages_tx.clone(),
            ))
        };

        Self {
            name,
            iface_manager,
            link_in_event_tx,
            link_out_event_tx,
            received_data_tx,
            iface_messages_tx,
            handler,
            cancel,
        }
    }

    pub async fn outbound(&self, packet: &Packet) {
        let (packet, maybe_iface) = self
            .handler
            .lock()
            .await
            .path_table
            .handle_packet(packet);

        if let Some(iface) = maybe_iface {
            self.send_direct(iface, packet).await;
            log::trace!("Sent outbound packet to {}", iface);
        }

        // TODO handle other cases
    }

    pub fn iface_manager(&self) -> Arc<Mutex<InterfaceManager>> {
        self.iface_manager.clone()
    }

    pub fn iface_rx(&self) -> broadcast::Receiver<RxMessage> {
        self.iface_messages_tx.subscribe()
    }

    pub async fn recv_announces(&self) -> broadcast::Receiver<AnnounceEvent> {
        self.handler.lock().await.announce_tx.subscribe()
    }

    /// Start a discovery handler to process interface announcements.
    ///
    /// This spawns a background task that listens for announcements and
    /// stores discovered interface information.
    ///
    /// # Arguments
    /// * `storage_path` - Base path for storing discovered interfaces
    /// * `required_value` - Optional required stamp value (default: 14)
    /// * `cancel` - Cancellation token for graceful shutdown
    pub async fn start_discovery_handler(
        &self,
        storage_path: std::path::PathBuf,
        required_value: Option<u8>,
        cancel: CancellationToken,
    ) {
        let required_value = required_value.unwrap_or(DEFAULT_DISCOVERY_STAMP_VALUE);

        // Create storage
        let storage = match InterfaceDiscoveryStorage::new(&storage_path) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("Failed to create discovery storage: {}", e);
                return;
            }
        };

        // Create handler with storage
        let handler = PythonDiscoveryHandler::new(required_value)
            .with_storage(storage);

        // Pre-compute the discovery aspect name hash for filtering
        // Only announces for "rnstransport.discovery.interface" should be processed
        let discovery_name = DestinationName::new("rnstransport", "discovery.interface");

        // Subscribe to announces
        let mut announce_rx = self.handler.lock().await.announce_tx.subscribe();

        // Spawn background task
        tokio::spawn(async move {
            log::info!("Discovery handler started (required stamp value: {})", required_value);

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        log::info!("Discovery handler shutting down");
                        break;
                    }

                    result = announce_rx.recv() => {
                        match result {
                            Ok(event) => {
                                // Get destination info
                                let dest = event.destination.lock().await;

                                // Filter by aspect: only process announces for the discovery aspect
                                // Compute expected destination hash for this identity + discovery aspect
                                let identity_hash = dest.identity.address_hash.as_slice();
                                let expected_dest_hash = AddressHash::new_from_hash(&Hash::new(
                                    Hash::generator()
                                        .chain_update(discovery_name.as_name_hash_slice())
                                        .chain_update(identity_hash)
                                        .finalize()
                                        .into(),
                                ));

                                // Compare with actual destination hash from the announce
                                let actual_dest_hash = dest.desc.address_hash;
                                if expected_dest_hash.as_slice() != actual_dest_hash.as_slice() {
                                    // Not a discovery announce, skip it
                                    continue;
                                }

                                // This is a discovery announce - process it
                                let dest_hash = actual_dest_hash.as_slice();
                                let app_data = event.app_data.as_slice();
                                let hops = 0u8; // TODO: Get actual hop count from announce

                                if let Some(info) = handler.handle_announce(
                                    dest_hash,
                                    identity_hash,
                                    app_data,
                                    hops,
                                ) {
                                    log::debug!(
                                        "Discovered interface: {} ({}) from {}",
                                        info.name,
                                        info.interface_type,
                                        info.network_id
                                    );
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                log::warn!("Discovery handler lagged {} announces", n);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                log::info!("Announce channel closed, discovery handler exiting");
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    /// Start the remote management service for this transport.
    ///
    /// This creates a destination that allows authorized clients to query
    /// transport status over links. The destination aspect is
    /// `rnstransport.remote.management`.
    ///
    /// # Arguments
    /// * `identity` - The transport's identity for the management destination
    /// * `config` - Configuration for access control
    /// * `cancel` - Cancellation token for graceful shutdown
    ///
    /// # Returns
    /// The destination hash for the management service, so clients can connect.
    pub async fn start_remote_management(
        &self,
        identity: &PrivateIdentity,
        config: remote_management::RemoteManagementConfig,
        cancel: CancellationToken,
    ) -> AddressHash {
        use crate::destination::link::{LinkEvent, LinkStatus};

        let service = remote_management::RemoteManagementService::new(identity, config);
        let dest_hash = service.destination_hash().await;

        // Register the destination with transport
        {
            let mut handler = self.handler.lock().await;
            handler.single_in_destinations.insert(
                dest_hash,
                service.destination.clone(),
            );
        }

        log::info!(
            "Remote management service started at {}",
            dest_hash
        );

        // Subscribe to link events for the management destination
        let mut link_events = self.in_link_events();
        let transport = self.handler.clone();

        // Spawn handler task
        tokio::spawn(async move {
            log::debug!("Remote management event handler started");

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        log::info!("Remote management service shutting down");
                        break;
                    }

                    result = link_events.recv() => {
                        match result {
                            Ok(event) => {
                                // Only handle events for our destination
                                if event.address_hash != dest_hash {
                                    continue;
                                }

                                match &event.event {
                                    LinkEvent::Activated => {
                                        log::debug!("remote_management: link {} activated", event.id);
                                    }
                                    LinkEvent::Identified(identity) => {
                                        log::info!(
                                            "remote_management: client {} identified on link {}",
                                            identity.address_hash,
                                            event.id
                                        );
                                    }
                                    LinkEvent::Request(payload) => {
                                        // Get the remote identity from the link
                                        let remote_identity_hash = {
                                            let handler = transport.lock().await;
                                            if let Some(link) = handler.in_links.get(&event.id) {
                                                let link = link.lock().await;
                                                link.remote_identity_hash()
                                            } else {
                                                None
                                            }
                                        };

                                        // Build context with transport data
                                        let context = {
                                            let handler = transport.lock().await;
                                            remote_management::RemoteManagementContext {
                                                path_table: Some(handler.path_table.get_paths(None)),
                                                rate_table: Some(handler.announce_limits.get_rate_table()),
                                                interface_stats: vec![], // TODO: gather interface stats
                                                link_count: Some(handler.in_links.len() as u64),
                                            }
                                        };

                                        // Process the request
                                        if let Some(response) = service.process_request(
                                            payload.as_slice(),
                                            event.id.as_slice(),
                                            remote_identity_hash.as_ref(),
                                            &context,
                                        ) {
                                            // Send the response back on the link
                                            let handler = transport.lock().await;
                                            if let Some(link) = handler.in_links.get(&event.id) {
                                                let link = link.lock().await;
                                                if link.status() == LinkStatus::Active {
                                                    if let Ok(packet) = link.response_packet(&response) {
                                                        handler.send_packet(packet).await;
                                                        log::debug!(
                                                            "remote_management: sent response on link {}",
                                                            event.id
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    LinkEvent::Closed => {
                                        log::debug!("remote_management: link {} closed", event.id);
                                    }
                                    _ => {}
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                log::warn!("remote_management: lagged {} events", n);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                log::info!("remote_management: event channel closed");
                                break;
                            }
                        }
                    }
                }
            }
        });

        dest_hash
    }

    /// Start the blackhole info service.
    ///
    /// This creates a public destination (ALLOW_ALL) that clients can query
    /// to get the list of blackholed identities. This matches Python's
    /// `--publish-blackhole` functionality.
    ///
    /// # Arguments
    /// * `identity` - The transport's identity (used for the info destination)
    /// * `cancel` - Cancellation token for graceful shutdown
    ///
    /// # Returns
    /// The destination hash for the blackhole info service.
    pub async fn start_blackhole_info_service(
        &self,
        identity: &PrivateIdentity,
        cancel: CancellationToken,
    ) -> AddressHash {
        use crate::destination::link::{LinkEvent, LinkStatus};

        let service = blackhole_info::BlackholeInfoService::new(identity);
        let dest_hash = service.destination_hash().await;

        // Register the destination with transport
        {
            let mut handler = self.handler.lock().await;
            handler.single_in_destinations.insert(
                dest_hash,
                service.destination.clone(),
            );
        }

        log::info!(
            "Blackhole info service started at {}",
            dest_hash
        );

        // Subscribe to link events for the info destination
        let mut link_events = self.in_link_events();
        let transport = self.handler.clone();

        // Spawn handler task
        tokio::spawn(async move {
            log::debug!("Blackhole info event handler started");

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        log::info!("Blackhole info service shutting down");
                        break;
                    }

                    result = link_events.recv() => {
                        match result {
                            Ok(event) => {
                                // Only handle events for our destination
                                if event.address_hash != dest_hash {
                                    continue;
                                }

                                match &event.event {
                                    LinkEvent::Activated => {
                                        log::debug!("blackhole_info: link {} activated", event.id);
                                    }
                                    LinkEvent::Request(payload) => {
                                        // Get the remote identity from the link
                                        let remote_identity_hash = {
                                            let handler = transport.lock().await;
                                            if let Some(link) = handler.in_links.get(&event.id) {
                                                let link = link.lock().await;
                                                link.remote_identity_hash()
                                            } else {
                                                None
                                            }
                                        };

                                        // Build context with blackhole entries
                                        // TODO: Integrate with BlackholeManager when fully implemented
                                        let context = blackhole_info::BlackholeInfoContext {
                                            entries: vec![],
                                        };

                                        // Process the request
                                        if let Some(response) = service.process_request(
                                            payload.as_slice(),
                                            event.id.as_slice(),
                                            remote_identity_hash.as_ref(),
                                            &context,
                                        ) {
                                            // Send the response back on the link
                                            let handler = transport.lock().await;
                                            if let Some(link) = handler.in_links.get(&event.id) {
                                                let link = link.lock().await;
                                                if link.status() == LinkStatus::Active {
                                                    if let Ok(packet) = link.response_packet(&response) {
                                                        handler.send_packet(packet).await;
                                                        log::debug!(
                                                            "blackhole_info: sent response on link {}",
                                                            event.id
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    LinkEvent::Closed => {
                                        log::debug!("blackhole_info: link {} closed", event.id);
                                    }
                                    _ => {}
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                log::warn!("blackhole_info: lagged {} events", n);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                log::info!("blackhole_info: event channel closed");
                                break;
                            }
                        }
                    }
                }
            }
        });

        dest_hash
    }

    pub async fn send_packet(&self, packet: Packet) {
        self.handler.lock().await.send_packet(packet).await;
    }

    /// Send a packet and track it for proof receipt.
    ///
    /// Returns a receipt that can be polled for delivery status.
    /// The destination_hash is used to look up the destination's identity
    /// when validating the proof.
    pub async fn send_packet_with_receipt(
        &self,
        packet: Packet,
        destination_hash: AddressHash,
        hops: u8,
    ) -> Arc<StdMutex<PacketReceipt>> {
        let hash = packet.hash().to_bytes();
        let dest_truncated: [u8; 16] = {
            let slice = destination_hash.as_slice();
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&slice[..16]);
            arr
        };

        let receipt = PacketReceipt::new_with_destination(hash, dest_truncated, hops, None);
        let receipt = self.handler.lock().await.receipt_manager.add(receipt);

        self.send_packet(packet).await;
        receipt
    }

    pub async fn send_announce(
        &self,
        destination: &Arc<Mutex<SingleInputDestination>>,
        app_data: Option<&[u8]>,
    ) {
        self.handler
            .lock()
            .await
            .send_packet(
                destination
                    .lock()
                    .await
                    .announce(OsRng, app_data)
                    .expect("valid announce packet"),
            )
            .await;
    }

    pub async fn send_broadcast(&self, packet: Packet, from_iface: Option<AddressHash>) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(from_iface),
                packet,
            })
            .await;
    }

    pub async fn send_direct(&self, addr: AddressHash, packet: Packet) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Direct(addr),
                packet,
            })
            .await;
    }

    pub async fn send_to_all_out_links(&self, payload: &[u8]) {
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let link = link.lock().await;
            if link.status() == LinkStatus::Active {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                }
            }
        }
    }

    pub async fn send_to_out_links(&self, destination: &AddressHash, payload: &[u8]) {
        let mut count = 0usize;
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let link = link.lock().await;
            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                    count += 1;
                }
            }
        }

        if count == 0 {
            log::trace!(
                "tp({}): no output links for {} destination",
                self.name,
                destination
            );
        }
    }

    pub async fn send_to_in_links(&self, destination: &AddressHash, payload: &[u8]) {
        let handler = self.handler.lock().await;
        let mut count = 0usize;
        for link in handler.in_links.values() {
            let link = link.lock().await;

            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                    count += 1;
                }
            }
        }

        if count == 0 {
            log::trace!(
                "tp({}): no input links for {} destination",
                self.name,
                destination
            );
        }
    }

    /// Send a resource request packet on an incoming link by link ID.
    pub async fn send_resource_request(&self, link_id: &AddressHash, request_data: &[u8]) -> bool {
        let handler = self.handler.lock().await;
        if let Some(link) = handler.in_links.get(link_id) {
            let link = link.lock().await;
            if link.status() == LinkStatus::Active {
                if let Ok(packet) = link.resource_request_packet(request_data) {
                    handler.send_packet(packet).await;
                    return true;
                }
            }
        }
        false
    }

    /// Send a resource proof packet on an incoming link by link ID.
    pub async fn send_resource_proof(&self, link_id: &AddressHash, proof_data: &[u8]) -> bool {
        let handler = self.handler.lock().await;
        if let Some(link) = handler.in_links.get(link_id) {
            let link = link.lock().await;
            if link.status() == LinkStatus::Active {
                if let Ok(packet) = link.resource_proof_packet(proof_data) {
                    handler.send_packet(packet).await;
                    return true;
                }
            }
        }
        false
    }

    /// Send a resource data packet on an outgoing link by link ID (for sender side).
    pub async fn send_resource_data(&self, link_id: &AddressHash, data: &[u8]) -> bool {
        let handler = self.handler.lock().await;
        if let Some(link) = handler.out_links.get(link_id) {
            let link = link.lock().await;
            if link.status() == LinkStatus::Active {
                if let Ok(packet) = link.resource_data_packet(data) {
                    handler.send_packet(packet).await;
                    return true;
                }
            }
        }
        false
    }

    /// Send a resource hashmap update packet on an outgoing link by link ID (for sender side).
    pub async fn send_resource_hashmap_update(&self, link_id: &AddressHash, hashmap_data: &[u8]) -> bool {
        let handler = self.handler.lock().await;
        if let Some(link) = handler.out_links.get(link_id) {
            let link = link.lock().await;
            if link.status() == LinkStatus::Active {
                if let Ok(packet) = link.resource_hashmap_update_packet(hashmap_data) {
                    handler.send_packet(packet).await;
                    return true;
                }
            }
        }
        false
    }

    pub async fn find_out_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.out_links.get(link_id).cloned()
    }

    pub async fn find_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.in_links.get(link_id).cloned()
    }

    /// Decrypt data using an incoming link's key.
    /// This is used for decrypting resource data that was encrypted at the resource level.
    pub async fn decrypt_with_in_link(&self, link_id: &AddressHash, data: &[u8]) -> Result<Vec<u8>, RnsError> {
        if let Some(link) = self.find_in_link(link_id).await {
            let link = link.lock().await;
            let mut buffer = vec![0u8; data.len() + 64]; // Add padding for decryption overhead
            let decrypted = link.decrypt(data, &mut buffer)?;
            Ok(decrypted.to_vec())
        } else {
            Err(RnsError::InvalidArgument)
        }
    }

    pub async fn link(&self, destination: DestinationDesc) -> Arc<Mutex<Link>> {
        let link = self
            .handler
            .lock()
            .await
            .out_links
            .get(&destination.address_hash)
            .cloned();

        if let Some(link) = link {
            if link.lock().await.status() != LinkStatus::Closed {
                return link;
            } else {
                log::warn!("tp({}): link was closed", self.name);
            }
        }

        let mut link = Link::new(destination, self.link_out_event_tx.clone());

        let packet = link.request();

        log::debug!(
            "tp({}): create new link {} for destination {}",
            self.name,
            link.id(),
            destination
        );

        let link = Arc::new(Mutex::new(link));

        self.send_packet(packet).await;

        self.handler
            .lock()
            .await
            .out_links
            .insert(destination.address_hash, link.clone());

        link
    }

    pub fn out_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_out_event_tx.subscribe()
    }

    pub fn in_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_in_event_tx.subscribe()
    }

    pub fn received_data_events(&self) -> broadcast::Receiver<ReceivedData> {
        self.received_data_tx.subscribe()
    }

    pub async fn add_destination(
        &mut self,
        identity: PrivateIdentity,
        name: DestinationName,
    ) -> Arc<Mutex<SingleInputDestination>> {
        let destination = SingleInputDestination::new(identity, name);
        let address_hash = destination.desc.address_hash;

        log::debug!("tp({}): add destination {}", self.name, address_hash);

        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .single_in_destinations
            .insert(address_hash, destination.clone());

        destination
    }

    pub async fn has_destination(&self, address: &AddressHash) -> bool {
        self.handler.lock().await.has_destination(address)
    }

    #[allow(private_interfaces)]
    pub fn get_handler(&self) -> Arc<Mutex<TransportHandler>> {
        // direct access to handler for testing purposes
        self.handler.clone()
    }

    // =========================================================================
    // Path Table Query Methods (for rnpath CLI)
    // =========================================================================

    /// Check if a path to destination exists
    pub async fn has_path(&self, destination: &AddressHash) -> bool {
        self.handler.lock().await.path_table.has_path(destination)
    }

    /// Get the number of hops to a destination
    pub async fn hops_to(&self, destination: &AddressHash) -> Option<u8> {
        self.handler.lock().await.path_table.hops_to(destination)
    }

    /// Get the next hop for a destination
    pub async fn get_next_hop(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.handler.lock().await.path_table.next_hop(destination)
    }

    /// Get the interface hash for the next hop
    pub async fn get_next_hop_iface(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.handler.lock().await.path_table.next_hop_iface(destination)
    }

    /// Recall a destination's identity from the announce cache.
    ///
    /// Returns the Identity if an announce from this destination has been received
    /// and cached. This is used to create packets for the destination and to validate
    /// proofs.
    pub async fn recall_identity(&self, destination: &AddressHash) -> Option<Identity> {
        let handler = self.handler.lock().await;
        if let Some(dest) = handler.single_out_destinations.get(destination) {
            Some(dest.lock().await.identity)
        } else {
            None
        }
    }

    /// Get all paths in the path table, optionally filtered by max hops
    pub async fn get_path_table(&self, max_hops: Option<u8>) -> Vec<path_table::PathInfo> {
        self.handler.lock().await.path_table.get_paths(max_hops)
    }

    /// Drop a specific path from the path table
    /// Returns true if the path existed and was removed
    pub async fn drop_path(&self, destination: &AddressHash) -> bool {
        self.handler.lock().await.path_table.drop_path(destination)
    }

    /// Drop all paths that route through a specific transport instance
    /// Returns the number of paths dropped
    pub async fn drop_via(&self, transport_hash: &AddressHash) -> usize {
        self.handler.lock().await.path_table.drop_via(transport_hash)
    }

    /// Get the number of entries in the path table
    pub async fn path_table_size(&self) -> usize {
        self.handler.lock().await.path_table.len()
    }

    // =========================================================================
    // Announce Rate Query Methods (for rnpath CLI)
    // =========================================================================

    /// Get announce rate information for all tracked destinations
    pub async fn get_rate_table(&self) -> Vec<announce_limits::RateInfo> {
        self.handler.lock().await.announce_limits.get_rate_table()
    }

    /// Get announce rate information for a specific destination
    pub async fn get_rate_info(&self, destination: &AddressHash) -> Option<announce_limits::RateInfo> {
        self.handler.lock().await.announce_limits.get_rate_info(destination)
    }

    // =========================================================================
    // Announce Queue Methods (for rnpath CLI)
    // =========================================================================

    /// Drop all queued announces from the announce table
    pub async fn drop_announce_queues(&self) {
        self.handler.lock().await.announce_table.clear();
    }

    // =========================================================================
    // Path Request Methods
    // =========================================================================

    /// Send a path request for a destination.
    ///
    /// This broadcasts a path request packet to the network. Other nodes that
    /// know the path (or host the destination locally) will respond with an
    /// announce packet.
    ///
    /// If `on_interface` is Some, the request is sent only on that interface.
    /// Otherwise, it's broadcast on all interfaces.
    ///
    /// Returns true if the request was sent, false if rate-limited.
    pub async fn request_path(
        &self,
        destination: &AddressHash,
        on_interface: Option<AddressHash>,
    ) -> bool {
        let handler = self.handler.lock().await;

        // Check if we already have a path
        if handler.path_table.has_path(destination) {
            return true;
        }

        // Build the path request packet
        let transport_id = if handler.config.retransmit {
            Some(*handler.config.identity.address_hash())
        } else {
            None
        };

        let (packet, _tag) =
            PathRequestManager::create_request_packet(destination, transport_id.as_ref());

        log::debug!(
            "tp({}): sending path request for {}",
            handler.config.name,
            destination
        );

        // Send the packet
        match on_interface {
            Some(iface) => {
                handler
                    .send(TxMessage {
                        tx_type: TxMessageType::Direct(iface),
                        packet,
                    })
                    .await;
            }
            None => {
                handler
                    .send(TxMessage {
                        tx_type: TxMessageType::Broadcast(None),
                        packet,
                    })
                    .await;
            }
        }

        true
    }

    /// Request a path and wait until found or timeout.
    ///
    /// This sends a path request and then polls until the path appears in the
    /// path table, or the timeout expires.
    ///
    /// Returns true if the path was found, false if timed out.
    pub async fn wait_for_path(
        &self,
        destination: &AddressHash,
        timeout: std::time::Duration,
    ) -> bool {
        use tokio::time::{sleep, Instant};

        // Check if we already have a path
        if self.has_path(destination).await {
            return true;
        }

        // Send the path request
        self.request_path(destination, None).await;

        let start = Instant::now();
        let poll_interval = std::time::Duration::from_millis(50);

        while start.elapsed() < timeout {
            if self.has_path(destination).await {
                return true;
            }
            sleep(poll_interval).await;
        }

        false
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl TransportHandler {
    async fn send_packet(&self, packet: Packet) {
        // Check if destination needs routing through path_table
        // This adds HEADER_2 routing for remote destinations (hops > 1)
        // and keeps HEADER_1 for directly reachable destinations (hops == 1)
        let (routed_packet, maybe_iface) = self.path_table.handle_packet(&packet);

        let message = if let Some(iface) = maybe_iface {
            // Destination found in path_table - send to specific interface
            TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: routed_packet,
            }
        } else {
            // No path found or local destination - broadcast
            TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: routed_packet,
            }
        };

        self.send(message).await;
    }

    async fn send(&self, message: TxMessage) {
        self.packet_cache.lock().await.update(&message.packet);
        self.iface_manager.lock().await.send(message).await;
    }

    fn has_destination(&self, address: &AddressHash) -> bool {
        self.single_in_destinations.contains_key(address)
    }

    async fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
        let mut allow_duplicate = false;

        // Certain packet contexts are exempt from duplicate filtering.
        // These packets may be legitimately repeated (e.g., keepalives are identical,
        // resource packets need retransmission, channels may resend data).
        match packet.context {
            PacketContext::KeepAlive
            | PacketContext::ResourceRequest
            | PacketContext::ResourceProof
            | PacketContext::Resource
            | PacketContext::CacheRequest
            | PacketContext::Channel => {
                return true;
            }
            _ => {}
        }

        match packet.header.packet_type {
            PacketType::Announce => {
                return true;
            },
            PacketType::LinkRequest => {
                allow_duplicate = true;
            },
            PacketType::Data => {
                allow_duplicate = packet.context == PacketContext::KeepAlive;
            },
            PacketType::Proof => {
                if packet.context == PacketContext::LinkRequestProof {
                    if let Some(link) = self.in_links.get(&packet.destination) {
                        if link.lock().await.status().not_yet_active() {
                            allow_duplicate = true;
                        }
                    }
                }
            }
        }

        let is_new = self.packet_cache.lock().await.update(packet);

        is_new || allow_duplicate
    }
}

async fn handle_proof<'a>(packet: &Packet, mut handler: MutexGuard<'a, TransportHandler>) {
    log::trace!(
        "tp({}): handle proof for {}",
        handler.config.name,
        packet.destination
    );

    // Handle link proofs
    for link in handler.out_links.values() {
        let mut link = link.lock().await;
        if let LinkHandleResult::Activated = link.handle_packet(packet) {
            let rtt_packet = link.create_rtt();
            handler.send_packet(rtt_packet).await;
        }
    }

    // Handle packet proofs (for receipts)
    // The proof packet's destination is the truncated hash of the proved packet
    if packet.context != PacketContext::LinkRequestProof {
        let truncated_hash: [u8; 16] = {
            let slice = packet.destination.as_slice();
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&slice[..16]);
            arr
        };

        if let Some(receipt) = handler.receipt_manager.get(&truncated_hash) {
            // Get the destination identity for proof validation
            if let Ok(mut receipt_guard) = receipt.lock() {
                if let Some(dest_hash) = receipt_guard.destination_hash() {
                    // Look up the destination's identity
                    let dest_hash_arr = AddressHash::new_from_slice(dest_hash);
                    if let Some(dest) = handler.single_out_destinations.get(&dest_hash_arr) {
                        let dest_lock = dest.blocking_lock();
                        let identity = &dest_lock.identity;
                        let proof_data = packet.data.as_slice();

                        if receipt_guard.validate_proof(proof_data, identity) {
                            log::debug!(
                                "tp({}): validated proof for packet {}",
                                handler.config.name,
                                packet.destination
                            );
                        }
                    }
                }
            }
        }
    }

    let maybe_packet = handler.link_table.handle_proof(packet);

    if let Some((packet, iface)) = maybe_packet {
        handler.send(TxMessage {
            tx_type: TxMessageType::Direct(iface),
            packet
        })
        .await;
    }
}

async fn send_to_next_hop<'a>(
    packet: &Packet,
    handler: &MutexGuard<'a, TransportHandler>,
    lookup: Option<AddressHash>
) -> bool {
    let (packet, maybe_iface) = handler.path_table.handle_inbound_packet(
        packet,
        lookup
    );

    if let Some(iface) = maybe_iface {
        handler.send(TxMessage {
            tx_type: TxMessageType::Direct(iface),
            packet,
        })
        .await;
    }

    maybe_iface.is_some()
}

async fn handle_keepalive_response<'a>(
    packet: &Packet,
    handler: &MutexGuard<'a, TransportHandler>
) -> bool {
    if packet.context == PacketContext::KeepAlive
        && packet.data.as_slice()[0] == KEEP_ALIVE_RESPONSE {
            let lookup = handler.link_table.handle_keepalive(packet);

            if let Some((propagated, iface)) = lookup {
                handler.send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet: propagated,
                })
                .await;
            }

            return true;
        }

    false
}

/// Handle an incoming path request packet.
///
/// Path requests are broadcast DATA packets addressed to the PLAIN destination
/// "rnstransport.path.request". When received, we check if we can answer
/// (local destination or known path) and send a response if so.
async fn handle_path_request<'a>(
    packet: &Packet,
    iface: AddressHash,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    let data = packet.data.as_slice();

    // Parse the path request data
    let parsed = PathRequestManager::parse_request_data(data);
    if parsed.is_none() {
        log::debug!(
            "tp({}): ignoring path request with invalid data (len={})",
            handler.config.name,
            data.len()
        );
        return;
    }

    let (destination_hash, requesting_transport_id, tag_bytes) = parsed.unwrap();

    // Path requests must have a tag for deduplication
    let tag = match tag_bytes {
        Some(t) => t,
        None => {
            log::debug!(
                "tp({}): ignoring tagless path request for {}",
                handler.config.name,
                destination_hash
            );
            return;
        }
    };

    // Check for duplicates using unique_tag = destination_hash + tag
    let mut unique_tag = [0u8; 32];
    unique_tag[..16].copy_from_slice(&destination_hash.as_slice()[..16]);
    unique_tag[16..].copy_from_slice(&tag);

    if handler.path_request_tags.contains(&unique_tag) {
        log::debug!(
            "tp({}): ignoring duplicate path request for {}",
            handler.config.name,
            destination_hash
        );
        return;
    }

    // Add to tag cache
    handler.path_request_tags.insert(unique_tag);

    // Process the path request
    process_path_request(
        destination_hash,
        requesting_transport_id,
        Some(&tag),
        iface,
        handler,
    )
    .await;
}

/// Process a validated path request and send a response if possible.
///
/// This implements the path response logic from Python Transport.path_request():
/// 1. If destination is local, send an immediate announce with PathResponse context
/// 2. If path is known in path_table, queue announce retransmission with grace period
/// 3. If transport enabled and path unknown, forward request on other interfaces
async fn process_path_request<'a>(
    destination_hash: AddressHash,
    requestor_transport_id: Option<AddressHash>,
    _tag: Option<&[u8]>,
    attached_interface: AddressHash,
    handler: MutexGuard<'a, TransportHandler>,
) {
    let is_transport_enabled = handler.config.retransmit;

    // Case 1: Local destination - send announce immediately with PathResponse context
    if let Some(destination) = handler.single_in_destinations.get(&destination_hash).cloned() {
        log::debug!(
            "tp({}): answering path request for {}, destination is local",
            handler.config.name,
            destination_hash
        );

        // Create announce with PathResponse context
        let dest = destination.lock().await;
        if let Ok(mut announce_packet) = dest.announce(OsRng, None) {
            announce_packet.context = PacketContext::PathResponse;
            drop(dest);
            handler.send_packet(announce_packet).await;
        }
        return;
    }

    // Case 2: Path known in path_table - queue retransmission with grace period
    if (is_transport_enabled || !handler.single_in_destinations.is_empty())
        && handler.path_table.has_path(&destination_hash)
    {
        if let Some(next_hop) = handler.path_table.next_hop(&destination_hash) {
            // Don't answer if next hop is the requestor (avoid loop)
            if let Some(ref requestor_id) = requestor_transport_id {
                if &next_hop == requestor_id {
                    log::debug!(
                        "tp({}): not answering path request for {}, next hop is requestor",
                        handler.config.name,
                        destination_hash
                    );
                    return;
                }
            }

            // Schedule announce retransmission with grace period
            // For now, we'll trigger an immediate retransmit if we have the announce cached
            if let Some(announce_packet) = handler.announce_table.get_announce_packet(&destination_hash) {
                let hops = handler.path_table.hops_to(&destination_hash).unwrap_or(0);
                log::debug!(
                    "tp({}): answering path request for {}, path known ({} hops)",
                    handler.config.name,
                    destination_hash,
                    hops
                );

                // Set PathResponse context and send
                let mut response_packet = *announce_packet;
                response_packet.context = PacketContext::PathResponse;

                // Send excluding the interface that sent the request
                handler
                    .send(TxMessage {
                        tx_type: TxMessageType::Broadcast(Some(attached_interface)),
                        packet: response_packet,
                    })
                    .await;
            }
        }
        return;
    }

    // Case 3: Unknown path + transport enabled - forward request on other interfaces
    if is_transport_enabled {
        log::debug!(
            "tp({}): forwarding path request for {} to other interfaces",
            handler.config.name,
            destination_hash
        );

        // Create a new path request packet to forward
        let transport_id = Some(*handler.config.identity.address_hash());
        let (forward_packet, _) =
            PathRequestManager::create_request_packet(&destination_hash, transport_id.as_ref());

        // Send on all interfaces except the one that sent us the request
        handler
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(Some(attached_interface)),
                packet: forward_packet,
            })
            .await;
    } else {
        log::debug!(
            "tp({}): ignoring path request for {}, no path known and transport disabled",
            handler.config.name,
            destination_hash
        );
    }
}

async fn handle_data<'a>(packet: &Packet, iface: AddressHash, handler: MutexGuard<'a, TransportHandler>) {
    let mut data_handled = false;

    // Check for path request control packets (PLAIN destination type)
    if packet.header.destination_type == DestinationType::Plain {
        let path_request_hash = *PlainDestination::new("rnstransport", "path.request")
            .address_hash();

        if packet.destination == path_request_hash {
            handle_path_request(packet, iface, handler).await;
            return;
        }
    }

    if packet.header.destination_type == DestinationType::Link {
        if let Some(link) = handler.in_links.get(&packet.destination).cloned() {
            let mut link = link.lock().await;
            let result = link.handle_packet(packet);
            if let LinkHandleResult::KeepAlive = result {
                let packet = link.keep_alive_packet(KEEP_ALIVE_RESPONSE);
                handler.send_packet(packet).await;
            }
        }

        for link in handler.out_links.values() {
            let mut link = link.lock().await;
            let _ = link.handle_packet(packet);
            data_handled = true;
        }

        if handle_keepalive_response(packet, &handler).await {
            return;
        }

        let lookup = handler.link_table.original_destination(&packet.destination);
        if lookup.is_some() {
            let sent = send_to_next_hop(packet, &handler, lookup).await;

            log::trace!(
                "tp({}): {} packet to remote link {}",
                handler.config.name,
                if sent { "forwarded" } else { "could not forward" },
                packet.destination
            );
        }
    }

    if packet.header.destination_type == DestinationType::Single {
        if let Some(_destination) = handler
            .single_in_destinations
            .get(&packet.destination)
            .cloned()
        {
            data_handled = true;

            handler.received_data_tx.send(ReceivedData {
                destination: packet.destination,
                data: packet.data,
            }).ok();
        } else {
            data_handled = send_to_next_hop(packet, &handler, None).await;
        }
    }

    if data_handled {
        log::trace!(
            "tp({}): handle data request for {} dst={:2x} ctx={:2x}",
            handler.config.name,
            packet.destination,
            packet.header.destination_type as u8,
            packet.context as u8,
        );
    }
}

async fn handle_announce<'a>(
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
    from_local_client: bool,
) {
    if let Some(blocked_until) = handler.announce_limits.check(&packet.destination) {
        log::info!(
            "tp({}): too many announces from {}, blocked for {} seconds",
            handler.config.name,
            &packet.destination,
            blocked_until.as_secs(),
        );
        return;
    }

    let destination_known = handler.has_destination(&packet.destination);

    if let Ok(result) = DestinationAnnounce::validate(packet) {
        let destination = result.0;
        let app_data = result.1;
        let dest_hash = destination.identity.address_hash;
        let destination = Arc::new(Mutex::new(destination));

        if !destination_known {
            if !handler
                .single_out_destinations
                .contains_key(&packet.destination)
            {
                log::trace!(
                    "tp({}): new announce for {}",
                    handler.config.name,
                    packet.destination
                );

                handler
                    .single_out_destinations
                    .insert(packet.destination, destination.clone());
            }

            handler.announce_table.add(
                packet,
                dest_hash,
                iface,
            );

            handler.path_table.handle_announce(
                packet,
                packet.transport,
                iface,
            );
        }

        // Retransmit announces if transport is enabled OR if from local client.
        // This matches Python behavior where local client announces are always
        // forwarded to network interfaces even when transport is disabled.
        let should_retransmit = handler.config.retransmit || from_local_client;
        if should_retransmit {
            let transport_id = *handler.config.identity.address_hash();
            if let Some((recv_from, packet)) = handler.announce_table.new_packet(
                &dest_hash,
                &transport_id,
            ) {
                handler.send(TxMessage {
                    tx_type: TxMessageType::Broadcast(Some(recv_from)),
                    packet
                }).await;
            }
        }

        let _ = handler.announce_tx.send(AnnounceEvent {
            destination,
            app_data: PacketDataBuffer::new_from_slice(app_data),
        });
    }
}

async fn handle_link_request_as_destination<'a>(
    destination: Arc<Mutex<SingleInputDestination>>,
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>
) {
    let mut destination = destination.lock().await;
    match destination.handle_packet(packet) {
        DestinationHandleStatus::LinkProof => {
            let link_id = LinkId::from(packet);
            if !handler.in_links.contains_key(&link_id) {
                log::trace!(
                    "tp({}): send proof to {}",
                    handler.config.name,
                    packet.destination
                );

                let link = Link::new_from_request(
                    packet,
                    destination.sign_key().clone(),
                    destination.desc,
                    handler.link_in_event_tx.clone(),
                );

                if let Ok(mut link) = link {
                    handler.send_packet(link.prove()).await;

                    log::debug!(
                        "tp({}): save input link {} for destination {}",
                        handler.config.name,
                        link.id(),
                        link.destination().address_hash
                    );

                    handler
                        .in_links
                        .insert(*link.id(), Arc::new(Mutex::new(link)));
                }
            }
        }
        DestinationHandleStatus::None => {}
    }
}

async fn handle_link_request_as_intermediate<'a>(
    received_from: AddressHash,
    next_hop: AddressHash,
    next_hop_iface: AddressHash,
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>
) {
    handler.link_table.add(
        packet,
        packet.destination,
        received_from,
        next_hop,
        next_hop_iface
    );

    send_to_next_hop(packet, &handler, None).await;
}

async fn handle_link_request<'a>(
    packet: &Packet,
    iface: AddressHash,
    handler: MutexGuard<'a, TransportHandler>
) {
    if let Some(destination) = handler
        .single_in_destinations
        .get(&packet.destination)
        .cloned()
    {
        log::trace!(
            "tp({}): handle link request for {}",
            handler.config.name,
            packet.destination
        );

        handle_link_request_as_destination(destination, packet, handler).await;
    } else if let Some(entry) = handler.path_table.next_hop_full(&packet.destination) {
        log::trace!(
            "tp({}): handle link request for remote destination {}",
            handler.config.name,
            packet.destination
        );

        let (next_hop, next_iface) = entry;
        handle_link_request_as_intermediate(
            iface,
            next_hop,
            next_iface,
            packet,
            handler
        ).await;
    } else {
        log::trace!(
            "tp({}): dropping link request to unknown destination {}",
            handler.config.name,
            packet.destination
        );
    }
}

async fn handle_check_links<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    let mut links_to_remove: Vec<AddressHash> = Vec::new();

    // Clean up input links
    for link_entry in &handler.in_links {
        let mut link = link_entry.1.lock().await;
        if link.elapsed() > INTERVAL_INPUT_LINK_CLEANUP {
            link.close();
            links_to_remove.push(*link_entry.0);
        }
    }

    for addr in &links_to_remove {
        handler.in_links.remove(addr);
    }

    links_to_remove.clear();

    for link_entry in &handler.out_links {
        let mut link = link_entry.1.lock().await;
        if link.status() == LinkStatus::Closed {
            link.close();
            links_to_remove.push(*link_entry.0);
        }
    }

    for addr in &links_to_remove {
        handler.out_links.remove(addr);
    }

    for link_entry in &handler.out_links {
        let mut link = link_entry.1.lock().await;

        if link.status() == LinkStatus::Active && link.elapsed() > INTERVAL_OUTPUT_LINK_RESTART {
            link.restart();
        }

        if link.status() == LinkStatus::Pending
            && link.elapsed() > INTERVAL_OUTPUT_LINK_REPEAT {
                log::warn!(
                    "tp({}): repeat link request {}",
                    handler.config.name,
                    link.id()
                );
                handler.send_packet(link.request()).await;
            }
    }
}

async fn handle_keep_links<'a>(handler: MutexGuard<'a, TransportHandler>) {
    for link in handler.out_links.values() {
        let link = link.lock().await;

        if link.status() == LinkStatus::Active {
            handler.send_packet(link.keep_alive_packet(KEEP_ALIVE_REQUEST)).await;
        }
    }
}

async fn handle_cleanup<'a>(handler: MutexGuard<'a, TransportHandler>) {
    handler.iface_manager.lock().await.cleanup();
}

async fn retransmit_announces<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    let transport_id = *handler.config.identity.address_hash();
    let announces = handler.announce_table.to_retransmit(&transport_id);

    if announces.is_empty() {
        return;
    }

    for (received_from, announce) in announces {
        let message = TxMessage {
            tx_type: TxMessageType::Broadcast(Some(received_from)),
            packet: announce,
        };

        handler.send(message).await;
    }
}

#[allow(dead_code)]
fn create_retransmit_packet(packet: &Packet) -> Packet {
    Packet {
        header: Header {
            ifac_flag: packet.header.ifac_flag,
            header_type: packet.header.header_type,
            propagation_type: packet.header.propagation_type,
            destination_type: packet.header.destination_type,
            packet_type: packet.header.packet_type,
            hops: packet.header.hops + 1,
        },
        ifac: packet.ifac,
        destination: packet.destination,
        transport: packet.transport,
        context: packet.context,
        data: packet.data,
    }
}


async fn manage_transport(
    handler: Arc<Mutex<TransportHandler>>,
    rx_receiver: Arc<Mutex<InterfaceRxReceiver>>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
) {
    let cancel = handler.lock().await.cancel.clone();
    let retransmit = handler.lock().await.config.retransmit;

    let _packet_task = {
        let handler = handler.clone();
        let cancel = cancel.clone();

        log::trace!(
            "tp({}): start packet task",
            handler.lock().await.config.name
        );

        tokio::spawn(async move {
            loop {
                let mut rx_receiver = rx_receiver.lock().await;

                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    Some(message) = rx_receiver.recv() => {
                        let _ = iface_messages_tx.send(message);

                        let packet = message.packet;

                        let handler = handler.lock().await;

                        if PACKET_TRACE {
                            log::debug!("tp: << rx({}) = {} {}", message.address, packet, packet.hash());
                        }

                        if !handler.filter_duplicate_packets(&packet).await {
                            log::debug!(
                                "tp({}): dropping duplicate packet: dst={}, ctx={:?}, type={:?}",
                                handler.config.name,
                                packet.destination,
                                packet.context,
                                packet.header.packet_type
                            );
                            continue;
                        }

                        // Check if this packet came from a local client interface
                        let from_local_client = handler.iface_manager.lock().await
                            .is_local_client(&message.address);

                        // Always forward packets to local IPC client interfaces.
                        // This ensures local clients receive all traffic regardless of
                        // the transport's broadcast/retransmit settings.
                        handler.iface_manager.lock().await
                            .send_to_local_clients(packet, Some(message.address)).await;

                        // Forward packets from local clients to all network interfaces,
                        // regardless of the broadcast setting. This matches Python behavior
                        // where local client packets are always relayed to the network.
                        if from_local_client && packet.header.packet_type != PacketType::Announce {
                            handler.iface_manager.lock().await
                                .send_from_local_client(packet, message.address).await;
                        }

                        if handler.config.broadcast && packet.header.packet_type != PacketType::Announce {
                            // TODO: remove seperate handling for announces in handle_announce.
                            // Send broadcast message expect current iface address
                            handler.send(TxMessage { tx_type: TxMessageType::Broadcast(Some(message.address)), packet }).await;
                        }

                        match packet.header.packet_type {
                            PacketType::Announce => handle_announce(
                                &packet,
                                handler,
                                message.address,
                                from_local_client,
                            ).await,
                            PacketType::LinkRequest => handle_link_request(
                                &packet,
                                message.address,
                                handler
                            ).await,
                            PacketType::Proof => handle_proof(&packet, handler).await,
                            PacketType::Data => handle_data(&packet, message.address, handler).await,
                        }
                    }
                };
            }
        })
    };

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_LINKS_CHECK) => {
                        handle_check_links(handler.lock().await).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_OUTPUT_LINK_KEEP) => {
                        handle_keep_links(handler.lock().await).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_IFACE_CLEANUP) => {
                        handle_cleanup(handler.lock().await).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_PACKET_CACHE_CLEANUP) => {
                        let mut handler = handler.lock().await;

                        handler
                            .packet_cache
                            .lock()
                            .await
                            .release(INTERVAL_KEEP_PACKET_CACHED);

                        handler.link_table.remove_stale();
                    },
                }
            }
        });
    }

    if retransmit {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_ANNOUNCES_RETRANSMIT) => {
                        retransmit_announces(handler.lock().await).await;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::packet::HeaderType;

    #[tokio::test]
    async fn drop_duplicates() {
        let mut config: TransportConfig = Default::default();
        config.set_retransmit(true);

        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let source1 = AddressHash::new_from_slice(&[1u8; 32]);
        let source2 = AddressHash::new_from_slice(&[2u8; 32]);
        let next_hop_iface = AddressHash::new_from_slice(&[3u8; 32]);
        let destination = AddressHash::new_from_slice(&[4u8; 32]);

        let mut announce: Packet = Default::default();
        announce.header.header_type = HeaderType::Type2;
        announce.header.packet_type = PacketType::Announce;
        announce.header.hops = 3;
        announce.transport = Some(destination);

        assert!(handler.lock().await.filter_duplicate_packets(&announce).await);

        handle_announce(&announce, handler.lock().await, next_hop_iface, false).await;

        let mut data_packet: Packet = Default::default();
        data_packet.data = PacketDataBuffer::new_from_slice(b"foo");
        data_packet.destination = destination;
        let mut duplicate: Packet = data_packet.clone();

        let mut different_packet = data_packet.clone();
        different_packet.data = PacketDataBuffer::new_from_slice(b"bar");

        assert!(handler.lock().await.filter_duplicate_packets(&data_packet).await);
        assert!(!handler.lock().await.filter_duplicate_packets(&duplicate).await);
        assert!(handler.lock().await.filter_duplicate_packets(&different_packet).await);

        tokio::time::sleep(Duration::from_secs(2)).await;
        handler.lock().await.packet_cache.lock().await.release(Duration::from_secs(1));

        // Packet should have been removed from cache (stale)
        assert!(handler.lock().await.filter_duplicate_packets(&duplicate).await);
    }
}
