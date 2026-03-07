use alloc::sync::Arc;
use sha2::Digest;
// announce_limits and announce_table are accessed via AnnounceManager
// link_table is accessed via LinkManager
use packet_cache::PacketCache;
// PathTable is accessed via PathManager
use rand_core::OsRng;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time;
use tokio_util::sync::CancellationToken;

use tokio::sync::broadcast;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;

use crate::destination::link::LinkInner;
use crate::destination::link::LinkEventData;
use crate::destination::link::LinkResult;
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
use crate::identity::{Identity, PrivateIdentity, get_ratchet_id, RATCHET_KEY_SIZE};

use crate::iface::Interface;
use crate::iface::InterfaceContext;
use crate::iface::InterfaceManager;
use crate::iface::InterfaceRegistry;
use crate::iface::InterfaceRxReceiver;
use crate::iface::InterfaceStatsSnapshot;
use crate::iface::RxMessage;
use crate::iface::TxMessage;
use crate::iface::TxMessageType;
use crate::iface::stats::InterfaceMode;

use crate::packet::DestinationType;
use crate::packet::Header;
use crate::packet::HeaderType;
use crate::packet::IfacFlag;
use crate::packet::Packet;
use crate::packet::PacketContext;
use crate::packet::PacketDataBuffer;
use crate::packet::PacketType;
use crate::packet::TransportType;
use crate::receipt::{PacketReceiptInner, ReceiptManager, EXPLICIT_PROOF_LENGTH};
use crate::discovery::{InterfaceDiscoveryStorage, PythonDiscoveryHandler, DEFAULT_DISCOVERY_STAMP_VALUE};
use crate::persistence::{KnownDestinations, RatchetManager};

pub mod announce_handler;
mod announce_limits;
pub mod announce_manager;
pub mod announce_queue;
mod announce_table;
pub mod link_manager;
mod link_table;
mod packet_cache;
pub mod path_manager;
pub mod path_table;

// Phase 5: Transport enhancements
pub mod blackhole;
pub mod blackhole_info;
pub mod destination;
pub mod link;
pub mod path_request;
pub mod receipt;
pub mod remote_management;
pub mod resource;
pub mod reverse_table;
pub mod tunnel;

pub use destination::RegisteredDestination;
pub use link::Link;
pub use receipt::PacketReceipt;
pub use resource::Resource;

// Re-export request handler types for external consumers
pub use crate::destination::request::{AllowPolicy, RequestHandler, RequestRouter, SharedAllowList, sync_handler};

use announce_handler::{AnnounceCallback, AnnounceHandlerConfig, AnnounceHandlerHandle, AnnounceHandlerRegistry};
use announce_manager::AnnounceManager;
use announce_queue::{AnnounceQueueManager, QueuedAnnounce};
use link_manager::LinkManager;
use path_manager::PathManager;
use path_request::PathRequestManager;

// TODO: Configure via features
const PACKET_TRACE: bool = false;
pub const PATHFINDER_M: usize = 128; // Max hops

// Announce retransmission parameters (matches Python Transport.py lines 67-69)
const PATHFINDER_R: u8 = 1;           // Retransmit retries
const PATHFINDER_G: u64 = 5;          // Retry grace period (seconds)
const PATHFINDER_RW: f64 = 0.5;       // Random window for announce rebroadcast

const INTERVAL_LINKS_CHECK: Duration = Duration::from_secs(1);
const INTERVAL_INPUT_LINK_CLEANUP: Duration = Duration::from_secs(20);
const INTERVAL_OUTPUT_LINK_RESTART: Duration = Duration::from_secs(60);
const INTERVAL_OUTPUT_LINK_REPEAT: Duration = Duration::from_secs(6);
const INTERVAL_OUTPUT_LINK_KEEP: Duration = Duration::from_secs(5);
const INTERVAL_IFACE_CLEANUP: Duration = Duration::from_secs(10);
const INTERVAL_ANNOUNCES_RETRANSMIT: Duration = Duration::from_secs(1);
const INTERVAL_KEEP_PACKET_CACHED: Duration = Duration::from_secs(180);
const INTERVAL_PACKET_CACHE_CLEANUP: Duration = Duration::from_secs(90);
const INTERVAL_ANNOUNCE_QUEUE_PROCESS: Duration = Duration::from_millis(100);

// Other constants
const KEEP_ALIVE_REQUEST: u8 = 0xFF;
const KEEP_ALIVE_RESPONSE: u8 = 0xFE;

/// Maximum concurrent response resource transfers per destination.
/// Provides load shedding — when exceeded, oversized responses are dropped
/// and the client will time out (correct behavior under overload).
const MAX_CONCURRENT_RESPONSE_RESOURCES: usize = 64;

/// Timeout for a single response resource transfer.
const RESPONSE_RESOURCE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct ReceivedData {
    pub destination: AddressHash,
    pub data: PacketDataBuffer,
}

pub struct TransportConfig {
    name: Arc<str>,
    identity: PrivateIdentity,
    broadcast: bool,
    retransmit: bool,
    /// When true, this transport is in client mode (connected to a daemon).
    /// Client mode transports don't run announce retransmission - the daemon handles that.
    client_mode: bool,
    /// When true, proofs contain only the signature (implicit).
    /// When false, proofs contain hash + signature (explicit).
    /// Default: true, matching Python's default behavior.
    use_implicit_proof: bool,
    /// Path to persistent storage directory (for ratchets, known destinations, etc.)
    /// Defaults to `std::env::temp_dir()` if not set.
    storage_path: Option<PathBuf>,
}

#[derive(Clone)]
pub struct AnnounceEvent {
    pub destination: DestinationDesc,
    pub app_data: PacketDataBuffer,
    /// Whether this announce originated from the path table (cached) rather than a fresh network announce
    pub is_path_response: bool,
}

struct TransportHandler {
    config: TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    interface_registry: Arc<InterfaceRegistry>,

    /// Unified path management (routing table + request deduplication)
    path_manager: PathManager,

    /// Unified announce management (caching + rate limiting + events)
    announce_manager: AnnounceManager,

    /// Per-interface announce queues for ANNOUNCE_CAP bandwidth limiting
    announce_queue_manager: AnnounceQueueManager,

    /// Unified link management (in/out links + routing table + events)
    link_manager: LinkManager,

    /// Blackhole manager for blocking specific identities
    blackhole_manager: blackhole::BlackholeManager,

    /// Known destinations cache for collision detection and identity recall
    known_destinations: KnownDestinations,

    /// Ratchet manager for forward secrecy key storage (shared via Arc)
    ratchet_manager: Arc<RatchetManager>,

    /// Registry of announce handlers for receiving announce notifications
    announce_handler_registry: AnnounceHandlerRegistry,

    single_in_destinations: HashMap<AddressHash, Arc<Mutex<SingleInputDestination>>>,
    single_out_destinations: HashMap<AddressHash, Arc<Mutex<SingleOutputDestination>>>,

    packet_cache: Mutex<PacketCache>,

    /// Receipt manager for tracking packet proofs
    receipt_manager: ReceiptManager,

    received_data_tx: broadcast::Sender<ReceivedData>,

    cancel: CancellationToken,
}

#[derive(Clone)]
pub struct Transport {
    name: Arc<str>,
    link_in_event_tx: broadcast::Sender<LinkEventData>,
    link_out_event_tx: broadcast::Sender<LinkEventData>,
    received_data_tx: broadcast::Sender<ReceivedData>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
    handler: Arc<Mutex<TransportHandler>>,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    interface_registry: Arc<InterfaceRegistry>,
    cancel: CancellationToken,
}

impl TransportConfig {
    pub fn new<T: Into<String>>(name: T, identity: &PrivateIdentity, enable_transport: bool) -> Self {
        Self {
            name: Arc::from(name.into()),
            identity: identity.clone(),
            broadcast: enable_transport,
            retransmit: enable_transport,
            client_mode: false,
            use_implicit_proof: true,
            storage_path: None,
        }
    }

    /// Create a client-mode transport configuration.
    ///
    /// Client mode transports connect to a daemon via LocalClientInterface.
    /// They don't run announce retransmission (the daemon handles that).
    pub fn new_client_mode<T: Into<String>>(name: T, identity: &PrivateIdentity) -> Self {
        Self {
            name: Arc::from(name.into()),
            identity: identity.clone(),
            broadcast: false,
            retransmit: false,
            client_mode: true,
            use_implicit_proof: true,
            storage_path: None,
        }
    }

    /// Returns true if this transport is in client mode.
    pub fn is_client_mode(&self) -> bool {
        self.client_mode
    }

    pub fn set_retransmit(&mut self, retransmit: bool) {
        self.retransmit = retransmit;
    }
    pub fn set_broadcast(&mut self, broadcast: bool) {
        self.broadcast = broadcast;
    }

    pub fn set_use_implicit_proof(&mut self, use_implicit_proof: bool) {
        self.use_implicit_proof = use_implicit_proof;
    }

    /// Set the persistent storage path for ratchets and known destinations.
    pub fn set_storage_path(&mut self, path: PathBuf) {
        self.storage_path = Some(path);
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            name: "tp".into(),
            identity: PrivateIdentity::new_from_rand(OsRng),
            broadcast: false,
            retransmit: false,
            client_mode: false,
            use_implicit_proof: true,
            storage_path: None,
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

        // Create interface registry for stats tracking
        let interface_registry = Arc::new(InterfaceRegistry::new());

        let mut iface_manager = InterfaceManager::new(16);
        iface_manager.set_interface_registry(interface_registry.clone());

        let rx_receiver = iface_manager.receiver();

        let iface_manager = Arc::new(Mutex::new(iface_manager));

        let cancel = CancellationToken::new();

        // Spawn background task for calculating interface speeds (like Python's count_traffic_loop)
        {
            let registry = interface_registry.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = interval.tick() => {
                            registry.update_speeds().await;
                        }
                    }
                }
            });
        }
        let name = config.name.clone();
        let storage_path = config.storage_path.clone().unwrap_or_else(std::env::temp_dir);
        let ratchet_manager = Arc::new(RatchetManager::new(&storage_path));
        if let Err(e) = ratchet_manager.load() {
            log::warn!("Failed to load ratchets from disk: {}", e);
        }
        let handler = Arc::new(Mutex::new(TransportHandler {
            config,
            iface_manager: iface_manager.clone(),
            interface_registry: interface_registry.clone(),
            path_manager: PathManager::new(),
            announce_manager: AnnounceManager::new(announce_tx),
            announce_queue_manager: AnnounceQueueManager::new(),
            link_manager: LinkManager::new(link_in_event_tx.clone()),
            blackhole_manager: blackhole::BlackholeManager::new(),
            known_destinations: KnownDestinations::new(&storage_path),
            ratchet_manager,
            announce_handler_registry: AnnounceHandlerRegistry::new(),
            single_in_destinations: HashMap::new(),
            single_out_destinations: HashMap::new(),
            packet_cache: Mutex::new(PacketCache::new()),
            receipt_manager: ReceiptManager::new(1024),
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
            interface_registry,
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
            .path_manager
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

    /// Spawn a network interface and register it with the interface manager.
    ///
    /// This is the preferred API for most callers. Use `iface_manager()` directly
    /// only when you need the raw `Arc<Mutex<InterfaceManager>>` (e.g. TcpServer
    /// and LocalServerInterface constructors that spawn child connections at
    /// accept time).
    pub async fn spawn_interface<T: Interface, F, R>(&self, inner: T, worker: F) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
    {
        self.iface_manager.lock().await.spawn(inner, worker)
    }

    /// Spawn a local IPC client interface.
    ///
    /// Local client interfaces always receive packets regardless of broadcast
    /// settings.
    pub async fn spawn_local_client_interface<T: Interface, F, R>(
        &self,
        inner: T,
        worker: F,
    ) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
    {
        self.iface_manager.lock().await.spawn_local_client(inner, worker)
    }

    /// Get the interface registry for stats tracking.
    pub fn interface_registry(&self) -> Arc<InterfaceRegistry> {
        self.interface_registry.clone()
    }

    /// Get a shared reference to the transport's ratchet manager.
    ///
    /// Higher-layer protocols can use this to look up ratchet keys
    /// for forward-secret encryption without maintaining a separate
    /// manager instance.
    pub async fn ratchet_manager(&self) -> Arc<RatchetManager> {
        self.handler.lock().await.ratchet_manager.clone()
    }

    /// Get interface statistics for all registered interfaces.
    pub async fn get_interface_stats(&self) -> Vec<InterfaceStatsSnapshot> {
        self.interface_registry.get_all_stats().await
    }

    pub fn iface_rx(&self) -> broadcast::Receiver<RxMessage> {
        self.iface_messages_tx.subscribe()
    }

    pub async fn recv_announces(&self) -> broadcast::Receiver<AnnounceEvent> {
        self.handler.lock().await.announce_manager.subscribe()
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
        let discovery_name = DestinationName::new("rnstransport", "discovery.interface")
            .expect("valid destination name");

        // Subscribe to announces
        let mut announce_rx = self.handler.lock().await.announce_manager.subscribe();

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
                                // Filter by aspect: only process announces for the discovery aspect
                                // Compute expected destination hash for this identity + discovery aspect
                                let identity_hash = event.destination.identity.address_hash.as_slice();
                                let expected_dest_hash = AddressHash::new_from_hash(&Hash::new(
                                    Hash::generator()
                                        .chain_update(discovery_name.as_name_hash_slice())
                                        .chain_update(identity_hash)
                                        .finalize()
                                        .into(),
                                ));

                                // Compare with actual destination hash from the announce
                                let actual_dest_hash = event.destination.address_hash;
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
                                    LinkEvent::Request(payload, request_id) => {
                                        // Get the remote identity from the link
                                        let remote_identity_hash = {
                                            let handler = transport.lock().await;
                                            if let Some(link) = handler.link_manager.get_in_link(&event.id) {
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
                                                path_table: Some(handler.path_manager.get_paths(None)),
                                                rate_table: Some(handler.announce_manager.get_rate_table()),
                                                interface_stats: vec![], // TODO: gather interface stats
                                                link_count: Some(handler.link_manager.in_links_len() as u64),
                                            }
                                        };

                                        // Process the request
                                        if let Some(response) = service.process_request(
                                            payload.as_slice(),
                                            event.id.as_slice(),
                                            remote_identity_hash.as_ref(),
                                            &context,
                                            request_id,
                                        ).await {
                                            // Send the response back on the link
                                            let handler = transport.lock().await;
                                            handler.send_response_on_link(
                                                &event.id,
                                                &response,
                                                "remote_management",
                                            ).await;
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
                                    LinkEvent::Request(payload, request_id) => {
                                        // Get the remote identity from the link
                                        let remote_identity_hash = {
                                            let handler = transport.lock().await;
                                            if let Some(link) = handler.link_manager.get_in_link(&event.id) {
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
                                            request_id,
                                        ).await {
                                            // Send the response back on the link
                                            let handler = transport.lock().await;
                                            handler.send_response_on_link(
                                                &event.id,
                                                &response,
                                                "blackhole_info",
                                            ).await;
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

    /// Start request dispatch for a registered destination.
    ///
    /// Spawns an async task that listens for `LinkEvent::Request` on links
    /// targeting this destination, routes through its `RequestRouter`, and
    /// sends responses back on the link.
    ///
    /// When a response exceeds the link MDU, it falls back to sending the
    /// response as a Resource transfer (matching Python RNS behavior).
    ///
    /// This is the generic equivalent of `start_remote_management()` — any
    /// destination with registered request handlers can use this to get
    /// automatic request routing.
    pub fn start_request_dispatch(
        &self,
        dest: &RegisteredDestination,
        cancel: CancellationToken,
    ) {
        use crate::destination::link::LinkEvent;
        use crate::destination::request::{parse_request, pack_response};

        let dest_hash = *dest.address_hash();
        let router = dest.router().clone();
        let mut link_events = self.in_link_events();
        let transport = self.handler.clone();
        let link_in_event_tx = self.link_in_event_tx.clone();
        let response_resource_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RESPONSE_RESOURCES));

        tokio::spawn(async move {
            log::debug!("request_dispatch({}): started", dest_hash);

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        log::info!("request_dispatch({}): shutting down", dest_hash);
                        break;
                    }

                    result = link_events.recv() => {
                        match result {
                            Ok(event) => {
                                // Only handle events for our destination
                                if event.address_hash != dest_hash {
                                    continue;
                                }

                                if let LinkEvent::Request(payload, request_id) = &event.event {
                                    // Get remote identity from the link
                                    let remote_identity_hash = {
                                        let handler = transport.lock().await;
                                        if let Some(link) = handler.link_manager.get_in_link(&event.id) {
                                            let link = link.lock().await;
                                            link.remote_identity_hash()
                                        } else {
                                            None
                                        }
                                    };

                                    // Parse the request
                                    let (requested_at, path_hash, data) = match parse_request(payload.as_slice()) {
                                        Ok(parsed) => parsed,
                                        Err(e) => {
                                            log::warn!("request_dispatch({}): parse error: {}", dest_hash, e);
                                            continue;
                                        }
                                    };

                                    // Clone the handler out of the RwLock before awaiting,
                                    // so the lock isn't held across the .await point.
                                    let handler = {
                                        let router = router.read().await;
                                        router.get(&path_hash).cloned()
                                    };

                                    let response = if let Some(handler) = handler {
                                        if !handler.is_allowed(remote_identity_hash.as_ref()) {
                                            log::warn!(
                                                "request_dispatch({}): access denied for path {}",
                                                dest_hash, handler.path
                                            );
                                            continue;
                                        }
                                        handler.invoke(
                                            &data,
                                            request_id,
                                            event.id.as_slice(),
                                            remote_identity_hash.as_ref(),
                                            requested_at,
                                        ).await
                                    } else {
                                        log::warn!(
                                            "request_dispatch({}): no handler for path hash {:?}",
                                            dest_hash, hex::encode(path_hash)
                                        );
                                        continue;
                                    };

                                    // Send response if handler returned one
                                    let label = format!("request_dispatch({})", dest_hash);
                                    if let Some(response_data) = response {
                                        match pack_response(request_id, &response_data) {
                                            Ok(packed) => {
                                                // Check if the packed response fits in a single link packet
                                                let link_mdu = {
                                                    let handler = transport.lock().await;
                                                    handler.link_manager.get_in_link(&event.id)
                                                        .map(|arc| {
                                                            // try_lock to avoid deadlock; fall back to 0 on contention
                                                            arc.try_lock()
                                                                .map(|l| l.mdu())
                                                                .unwrap_or(0)
                                                        })
                                                        .unwrap_or(0)
                                                };

                                                if packed.len() <= link_mdu {
                                                    // Fits in a single packet — use the fast path
                                                    let handler = transport.lock().await;
                                                    handler.send_response_on_link(
                                                        &event.id,
                                                        &packed,
                                                        &label,
                                                    ).await;
                                                } else {
                                                    // Response exceeds link MDU — fall back to Resource transfer
                                                    log::info!(
                                                        "{}: response too large for link packet ({} > {}), \
                                                         falling back to resource transfer",
                                                        label, packed.len(), link_mdu,
                                                    );

                                                    match response_resource_semaphore.clone().try_acquire_owned() {
                                                        Ok(permit) => {
                                                            // Build an encrypt_fn from the link's key material
                                                            let encrypt_fn = {
                                                                let handler = transport.lock().await;
                                                                handler.link_manager.get_in_link(&event.id)
                                                                    .and_then(|arc| {
                                                                        arc.try_lock()
                                                                            .map(|l| l.build_encrypt_fn())
                                                                            .ok()
                                                                    })
                                                            };

                                                            match Resource::new_response(
                                                                &mut OsRng,
                                                                &packed,
                                                                encrypt_fn.as_deref(),
                                                                *request_id,
                                                            ) {
                                                                Ok(resource) => {
                                                                    let transport_clone = transport.clone();
                                                                    let link_id = event.id;
                                                                    let cancel_clone = cancel.clone();
                                                                    let event_tx = link_in_event_tx.clone();
                                                                    let label_clone = label.clone();

                                                                    tokio::spawn(drive_response_resource(
                                                                        transport_clone,
                                                                        event_tx,
                                                                        link_id,
                                                                        resource,
                                                                        label_clone,
                                                                        cancel_clone,
                                                                        permit,
                                                                    ));
                                                                }
                                                                Err(e) => {
                                                                    log::warn!(
                                                                        "{}: failed to create response resource: {:?}",
                                                                        label, e,
                                                                    );
                                                                }
                                                            }
                                                        }
                                                        Err(_) => {
                                                            log::warn!(
                                                                "{}: response resource limit reached ({}), \
                                                                 shedding oversized response",
                                                                label, MAX_CONCURRENT_RESPONSE_RESOURCES,
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                log::warn!(
                                                    "request_dispatch({}): pack_response error: {}",
                                                    dest_hash, e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                log::warn!("request_dispatch({}): lagged {} events", dest_hash, n);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                log::info!("request_dispatch({}): event channel closed", dest_hash);
                                break;
                            }
                        }
                    }
                }
            }
        });
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
    ) -> PacketReceipt {
        let hash = packet.hash().to_bytes();
        let dest_truncated: [u8; 16] = {
            let slice = destination_hash.as_slice();
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&slice[..16]);
            arr
        };

        let truncated_hash = {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&hash[..16]);
            arr
        };

        let receipt = PacketReceiptInner::new_with_destination(hash, dest_truncated, hops, None);
        let inner = self.handler.lock().await.receipt_manager.add(receipt).await;

        self.send_packet(packet).await;
        PacketReceipt::new(inner, hash, truncated_hash, Some(dest_truncated))
    }

    /// Send plaintext data to a single destination, encrypting it for the
    /// destination's identity. Mirrors Python's `RNS.Packet(dest, data).send()`.
    ///
    /// Looks up the destination from announces (`single_out_destinations`) or
    /// the `known_destinations` persistence cache. Encrypts the plaintext,
    /// constructs a Data packet, and sends it with receipt tracking.
    ///
    /// Returns a `PacketReceipt` for delivery confirmation.
    pub async fn send_to_destination(
        &self,
        destination_hash: &AddressHash,
        plaintext: &[u8],
        context: PacketContext,
    ) -> Result<PacketReceipt, RnsError> {
        // Try to encrypt via a cached SingleOutputDestination first, then
        // fall back to known_destinations for identity lookup. Both paths
        // consult the ratchet manager for forward secrecy.
        let (ciphertext, ratchet_id) = {
            let handler = self.handler.lock().await;
            if let Some(dest) = handler.single_out_destinations.get(destination_hash) {
                let mut dest_guard = dest.lock().await;
                let ct = dest_guard.encrypt(OsRng, plaintext, Some(&handler.ratchet_manager))?;
                let rid = dest_guard.latest_ratchet_id;
                (ct, rid)
            } else {
                // Fall back to known_destinations persistence cache.
                let hash: [u8; 16] = destination_hash.as_slice().try_into()
                    .map_err(|_| RnsError::InvalidData)?;
                let identity = handler.known_destinations.recall_identity(&hash)
                    .ok_or(RnsError::UnknownDestination)?;

                // Check for a stored ratchet key for this destination
                let ratchet = handler.ratchet_manager.get(&hash);
                let (target_pub, rid) = if let Some(ref ratchet_bytes) = ratchet {
                    let rbytes: [u8; RATCHET_KEY_SIZE] = ratchet_bytes.as_slice()
                        .try_into()
                        .map_err(|_| RnsError::InvalidData)?;
                    (x25519_dalek::PublicKey::from(rbytes), Some(get_ratchet_id(&rbytes)))
                } else {
                    (identity.public_key, None)
                };

                // encrypt_single uses the identity hash (not destination hash) as salt,
                // matching Python's Identity.get_salt().
                let ct = crate::destination::encrypt_single(
                    OsRng,
                    &target_pub,
                    identity.address_hash.as_slice(),
                    plaintext,
                )?;
                (ct, rid)
            }
        };

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination: *destination_hash,
            transport: None,
            context,
            data: PacketDataBuffer::new_from_slice(&ciphertext),
            ratchet_id,
        };

        Ok(self.send_packet_with_receipt(packet, *destination_hash, 0).await)
    }

    pub async fn send_announce(
        &self,
        destination: &RegisteredDestination,
        app_data: Option<&[u8]>,
    ) {
        let packet = match destination.announce(app_data).await {
            Ok(packet) => packet,
            Err(e) => {
                log::error!("send_announce: failed to create announce packet: {}", e);
                return;
            }
        };
        self.handler.lock().await.send_packet(packet).await;
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
        for link in handler.link_manager.out_link_values() {
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
        for link in handler.link_manager.out_link_values() {
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
        for link in handler.link_manager.in_link_values() {
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
        let Some(link_arc) = handler.link_manager.get_in_link(link_id) else {
            log::warn!("send_resource_request: in-link {} not found", link_id);
            return false;
        };
        let link = link_arc.lock().await;
        let status = link.status();
        if status != LinkStatus::Active {
            log::warn!("send_resource_request: in-link {} is {:?}", link_id, status);
            return false;
        }
        match link.resource_request_packet(request_data) {
            Ok(packet) => {
                handler.send_packet(packet).await;
                true
            }
            Err(e) => {
                log::warn!("send_resource_request: failed to create packet on in-link {}: {}", link_id, e);
                false
            }
        }
    }

    /// Send a resource proof packet on an incoming link by link ID.
    pub async fn send_resource_proof(&self, link_id: &AddressHash, proof_data: &[u8]) -> bool {
        let handler = self.handler.lock().await;
        let Some(link_arc) = handler.link_manager.get_in_link(link_id) else {
            log::warn!("send_resource_proof: in-link {} not found", link_id);
            return false;
        };
        let link = link_arc.lock().await;
        let status = link.status();
        if status != LinkStatus::Active {
            log::warn!("send_resource_proof: in-link {} is {:?}", link_id, status);
            return false;
        }
        match link.resource_proof_packet(proof_data) {
            Ok(packet) => {
                handler.send_packet(packet).await;
                true
            }
            Err(e) => {
                log::warn!("send_resource_proof: failed to create packet on in-link {}: {}", link_id, e);
                false
            }
        }
    }

    /// Get the remote identity from an inbound link, if the peer has identified.
    ///
    /// Returns the identity set synchronously during LNID packet processing,
    /// which is available before the `LinkEvent::Identified` event is dispatched.
    /// Useful as a fallback when the event-based identity map may not yet be populated.
    pub async fn get_in_link_remote_identity(&self, link_id: &AddressHash) -> Option<Identity> {
        let handler = self.handler.lock().await;
        if let Some(link) = handler.link_manager.get_in_link(link_id) {
            let link = link.lock().await;
            link.remote_identity().copied()
        } else {
            None
        }
    }

    /// Send a resource request packet on an outgoing link by address hash.
    /// Used when receiving a resource from a remote server (e.g., propagation node).
    pub async fn send_resource_request_out(&self, link_id: &AddressHash, request_data: &[u8]) -> bool {
        let handler = self.handler.lock().await;
        let Some(link_arc) = handler.link_manager.get_out_link(link_id) else {
            log::warn!("send_resource_request_out: out-link {} not found", link_id);
            return false;
        };
        let link = link_arc.lock().await;
        let status = link.status();
        if status != LinkStatus::Active {
            log::warn!("send_resource_request_out: out-link {} is {:?}", link_id, status);
            return false;
        }
        match link.resource_request_packet(request_data) {
            Ok(packet) => {
                handler.send_packet(packet).await;
                true
            }
            Err(e) => {
                log::warn!("send_resource_request_out: failed to create packet on out-link {}: {}", link_id, e);
                false
            }
        }
    }

    /// Send a resource proof packet on an outgoing link by address hash.
    /// Used when receiving a resource from a remote server (e.g., propagation node).
    pub async fn send_resource_proof_out(&self, link_id: &AddressHash, proof_data: &[u8]) -> bool {
        let handler = self.handler.lock().await;
        let Some(link_arc) = handler.link_manager.get_out_link(link_id) else {
            log::warn!("send_resource_proof_out: out-link {} not found", link_id);
            return false;
        };
        let link = link_arc.lock().await;
        let status = link.status();
        if status != LinkStatus::Active {
            log::warn!("send_resource_proof_out: out-link {} is {:?}", link_id, status);
            return false;
        }
        match link.resource_proof_packet(proof_data) {
            Ok(packet) => {
                handler.send_packet(packet).await;
                true
            }
            Err(e) => {
                log::warn!("send_resource_proof_out: failed to create packet on out-link {}: {}", link_id, e);
                false
            }
        }
    }

    /// Send a resource data packet on an outgoing link by link ID (for sender side).
    pub async fn send_resource_data(&self, link_id: &AddressHash, data: &[u8]) -> bool {
        let handler = self.handler.lock().await;
        let Some(link_arc) = handler.link_manager.get_out_link(link_id) else {
            log::warn!("send_resource_data: out-link {} not found", link_id);
            return false;
        };
        let link = link_arc.lock().await;
        let status = link.status();
        if status != LinkStatus::Active {
            log::warn!("send_resource_data: out-link {} is {:?}", link_id, status);
            return false;
        }
        match link.resource_data_packet(data) {
            Ok(packet) => {
                handler.send_packet(packet).await;
                true
            }
            Err(e) => {
                log::warn!("send_resource_data: failed to create packet on out-link {}: {}", link_id, e);
                false
            }
        }
    }

    /// Send a resource hashmap update packet on an outgoing link by link ID (for sender side).
    pub async fn send_resource_hashmap_update(&self, link_id: &AddressHash, hashmap_data: &[u8]) -> bool {
        let handler = self.handler.lock().await;
        let Some(link_arc) = handler.link_manager.get_out_link(link_id) else {
            log::warn!("send_resource_hashmap_update: out-link {} not found", link_id);
            return false;
        };
        let link = link_arc.lock().await;
        let status = link.status();
        if status != LinkStatus::Active {
            log::warn!("send_resource_hashmap_update: out-link {} is {:?}", link_id, status);
            return false;
        }
        match link.resource_hashmap_update_packet(hashmap_data) {
            Ok(packet) => {
                handler.send_packet(packet).await;
                true
            }
            Err(e) => {
                log::warn!("send_resource_hashmap_update: failed to create packet on out-link {}: {}", link_id, e);
                false
            }
        }
    }

    pub async fn find_out_link(&self, link_id: &AddressHash) -> Option<Link> {
        let handler_guard = self.handler.lock().await;
        let link_arc = handler_guard.link_manager.get_out_link(link_id)?;
        let link_guard = link_arc.lock().await;
        let id = *link_guard.id();
        let destination = *link_guard.destination();
        let initiator = link_guard.is_initiator();
        drop(link_guard);
        Some(Link::new(link_arc, self.handler.clone(), id, destination, initiator))
    }

    pub async fn find_in_link(&self, link_id: &AddressHash) -> Option<Link> {
        let handler_guard = self.handler.lock().await;
        let link_arc = handler_guard.link_manager.get_in_link(link_id)?;
        let link_guard = link_arc.lock().await;
        let id = *link_guard.id();
        let destination = *link_guard.destination();
        let initiator = link_guard.is_initiator();
        drop(link_guard);
        Some(Link::new(link_arc, self.handler.clone(), id, destination, initiator))
    }

    /// Decrypt data using an incoming link's key.
    /// This is used for decrypting resource data that was encrypted at the resource level.
    pub async fn decrypt_with_in_link(&self, link_id: &AddressHash, data: &[u8]) -> Result<Vec<u8>, RnsError> {
        if let Some(link_handle) = self.find_in_link(link_id).await {
            link_handle.decrypt(data).await
        } else {
            Err(RnsError::InvalidArgument)
        }
    }

    /// Decrypt data using an outgoing link's key.
    /// This is used for decrypting resource data received from a remote server
    /// (e.g., a propagation node sending a response resource).
    pub async fn decrypt_with_out_link(&self, link_id: &AddressHash, data: &[u8]) -> Result<Vec<u8>, RnsError> {
        if let Some(link_handle) = self.find_out_link(link_id).await {
            link_handle.decrypt(data).await
        } else {
            Err(RnsError::InvalidArgument)
        }
    }

    pub async fn link(&self, destination: DestinationDesc) -> Link {
        let existing = self
            .handler
            .lock()
            .await
            .link_manager
            .get_out_link(&destination.address_hash);

        if let Some(link_arc) = existing {
            let link_guard = link_arc.lock().await;
            if link_guard.status() != LinkStatus::Closed {
                let id = *link_guard.id();
                let dest = *link_guard.destination();
                let initiator = link_guard.is_initiator();
                drop(link_guard);
                return Link::new(link_arc, self.handler.clone(), id, dest, initiator);
            } else {
                log::warn!("tp({}): link was closed", self.name);
            }
        }

        let mut link = LinkInner::new(destination, self.link_out_event_tx.clone());

        let packet = link.request();

        log::debug!(
            "tp({}): create new link {} for destination {}",
            self.name,
            link.id(),
            destination
        );

        let id = *link.id();
        let initiator = link.is_initiator();
        let link_arc = Arc::new(Mutex::new(link));

        self.send_packet(packet).await;

        self.handler
            .lock()
            .await
            .link_manager
            .insert_out_link(destination.address_hash, link_arc.clone());

        Link::new(link_arc, self.handler.clone(), id, destination, initiator)
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
        &self,
        identity: PrivateIdentity,
        name: DestinationName,
    ) -> RegisteredDestination {
        let destination = SingleInputDestination::new(identity, name);
        let desc = destination.desc;

        log::debug!("tp({}): add destination {}", self.name, desc.address_hash);

        let inner = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .single_in_destinations
            .insert(desc.address_hash, inner.clone());

        RegisteredDestination::new(inner, desc)
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
        self.handler.lock().await.path_manager.has_path(destination)
    }

    /// Get the number of hops to a destination
    pub async fn hops_to(&self, destination: &AddressHash) -> Option<u8> {
        self.handler.lock().await.path_manager.hops_to(destination)
    }

    /// Get the number of hops to a destination, or PATHFINDER_M (128) if unknown.
    pub async fn hops_to_or_max(&self, destination: &AddressHash) -> u8 {
        self.handler.lock().await.path_manager.hops_to_or_max(destination)
    }

    /// Mark a destination's path as unresponsive.
    pub async fn mark_path_unresponsive(&self, dest: &AddressHash) -> bool {
        self.handler.lock().await.path_manager.mark_path_unresponsive(dest)
    }

    /// Mark a destination's path as responsive.
    pub async fn mark_path_responsive(&self, dest: &AddressHash) -> bool {
        self.handler.lock().await.path_manager.mark_path_responsive(dest)
    }

    /// Mark a destination's path state as unknown.
    pub async fn mark_path_unknown_state(&self, dest: &AddressHash) -> bool {
        self.handler.lock().await.path_manager.mark_path_unknown_state(dest)
    }

    /// Check if a destination's path is in unresponsive state.
    pub async fn path_is_unresponsive(&self, dest: &AddressHash) -> bool {
        self.handler.lock().await.path_manager.path_is_unresponsive(dest)
    }

    /// Get the next hop for a destination
    pub async fn get_next_hop(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.handler.lock().await.path_manager.next_hop(destination)
    }

    /// Get the interface hash for the next hop
    pub async fn get_next_hop_iface(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.handler.lock().await.path_manager.next_hop_iface(destination)
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
            // Fall back to known_destinations (populated from announces)
            let hash: &[u8; 16] = destination.as_slice().try_into().ok()?;
            handler.known_destinations.recall_identity(hash)
        }
    }

    /// Register a known identity for a destination hash.
    ///
    /// Stores the public key material in `known_destinations` so that
    /// `recall_identity()` can look it up without a real announce having
    /// been received. Useful for injecting identities in tests or when
    /// the identity is already known through an out-of-band mechanism.
    pub async fn register_known_identity(
        &self,
        destination_hash: &[u8; 16],
        identity: &Identity,
    ) {
        self.register_known_identity_with_app_data(destination_hash, identity, None)
            .await;
    }

    /// Register a known identity with optional app_data for a destination hash.
    ///
    /// Like `register_known_identity()`, but also stores app_data so that
    /// `recall_app_data()` returns it. Useful for injecting announce-like
    /// state (e.g. propagation node data) in tests.
    pub async fn register_known_identity_with_app_data(
        &self,
        destination_hash: &[u8; 16],
        identity: &Identity,
        app_data: Option<&[u8]>,
    ) {
        let handler = self.handler.lock().await;
        let mut public_key = Vec::with_capacity(64);
        public_key.extend_from_slice(identity.public_key_bytes());
        public_key.extend_from_slice(identity.verifying_key_bytes());
        let _ = handler.known_destinations.remember(
            destination_hash,
            &[],          // no packet_hash
            &public_key,
            app_data,
        );
    }

    /// Recall cached announce app_data for a destination.
    ///
    /// Returns the app_data bytes if an announce from this destination has been
    /// received and cached. Mirrors Python's `Identity.recall_app_data()`.
    pub async fn recall_app_data(&self, destination: &AddressHash) -> Option<Vec<u8>> {
        let handler = self.handler.lock().await;
        let hash: &[u8; 16] = destination.as_slice().try_into().ok()?;
        handler.known_destinations.recall_app_data(hash)
    }

    /// Get all paths in the path table, optionally filtered by max hops
    pub async fn get_path_table(&self, max_hops: Option<u8>) -> Vec<path_table::PathInfo> {
        self.handler.lock().await.path_manager.get_paths(max_hops)
    }

    /// Drop a specific path from the path table
    /// Returns true if the path existed and was removed
    pub async fn drop_path(&self, destination: &AddressHash) -> bool {
        self.handler.lock().await.path_manager.drop_path(destination)
    }

    /// Drop all paths that route through a specific transport instance
    /// Returns the number of paths dropped
    pub async fn drop_via(&self, transport_hash: &AddressHash) -> usize {
        self.handler.lock().await.path_manager.drop_via(transport_hash)
    }

    /// Get the number of entries in the path table
    pub async fn path_table_size(&self) -> usize {
        self.handler.lock().await.path_manager.len()
    }

    // =========================================================================
    // Announce Rate Query Methods (for rnpath CLI)
    // =========================================================================

    /// Get announce rate information for all tracked destinations
    pub async fn get_rate_table(&self) -> Vec<announce_limits::RateInfo> {
        self.handler.lock().await.announce_manager.get_rate_table()
    }

    /// Get announce rate information for a specific destination
    pub async fn get_rate_info(&self, destination: &AddressHash) -> Option<announce_limits::RateInfo> {
        self.handler.lock().await.announce_manager.get_rate_info(destination)
    }

    // =========================================================================
    // Announce Queue Methods (for rnpath CLI)
    // =========================================================================

    /// Drop all queued announces from the announce table and per-interface queues.
    pub async fn drop_announce_queues(&self) {
        let mut handler = self.handler.lock().await;
        handler.announce_manager.clear();
        handler.announce_queue_manager.clear_all();
    }

    // =========================================================================
    // Blackhole Methods
    // =========================================================================

    /// Add an identity to the blackhole.
    ///
    /// Blackholed identities will have their announces and packets blocked.
    pub async fn blackhole_identity(&self, identity_hash: AddressHash) {
        self.handler.lock().await.blackhole_manager.add(identity_hash);
    }

    /// Add an identity to the blackhole with a duration.
    ///
    /// The identity will be automatically unblackholed after the duration expires.
    pub async fn blackhole_identity_temporary(
        &self,
        identity_hash: AddressHash,
        duration: std::time::Duration,
    ) {
        self.handler
            .lock()
            .await
            .blackhole_manager
            .add_temporary(identity_hash, duration);
    }

    /// Remove an identity from the blackhole.
    pub async fn unblackhole_identity(&self, identity_hash: &AddressHash) {
        self.handler.lock().await.blackhole_manager.remove(identity_hash);
    }

    /// Check if an identity is blackholed.
    pub async fn is_blackholed(&self, identity_hash: &AddressHash) -> bool {
        self.handler.lock().await.blackhole_manager.is_blackholed(identity_hash)
    }

    /// Get list of all blackholed identities.
    pub async fn get_blackholed_identities(&self) -> Vec<AddressHash> {
        self.handler.lock().await.blackhole_manager.list()
    }

    // =========================================================================
    // Announce Handler Methods
    // =========================================================================

    /// Register an announce handler.
    ///
    /// The handler will be called when announces matching its configuration are received.
    /// This mirrors Python's `Transport.register_announce_handler()` API.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the handler (aspect filter, path response settings)
    /// * `callback` - The callback to invoke when matching announces are received
    ///
    /// # Returns
    ///
    /// A handle that can be used to deregister the handler later.
    pub async fn register_announce_handler(
        &self,
        config: AnnounceHandlerConfig,
        callback: Arc<dyn AnnounceCallback>,
    ) -> AnnounceHandlerHandle {
        self.handler
            .lock()
            .await
            .announce_handler_registry
            .register(config, callback)
    }

    /// Deregister an announce handler.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle returned from `register_announce_handler()`
    pub async fn deregister_announce_handler(&self, handle: AnnounceHandlerHandle) {
        self.handler
            .lock()
            .await
            .announce_handler_registry
            .deregister(handle);
    }

    /// Get the number of registered announce handlers.
    pub async fn announce_handler_count(&self) -> usize {
        self.handler.lock().await.announce_handler_registry.len()
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
    /// If `tag` is Some, uses the provided request tag; otherwise generates a random one.
    ///
    /// Unlike some implementations, this always sends the request even if a path
    /// already exists, allowing callers to discover fresher routes.
    ///
    /// Returns true if the request was sent, false if rate-limited.
    pub async fn request_path(
        &self,
        destination: &AddressHash,
        on_interface: Option<AddressHash>,
    ) -> bool {
        let handler = self.handler.lock().await;

        // Build the path request packet
        let transport_id = if handler.config.retransmit {
            Some(*handler.config.identity.address_hash())
        } else {
            None
        };

        let (packet, _tag) =
            PathRequestManager::create_request_packet(destination, transport_id.as_ref(), None);

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

/// Drive a response resource transfer on an incoming link.
///
/// Spawned by `start_request_dispatch()` when a response exceeds the link MDU.
/// Sends the advertisement, then handles ResourceRequest/ResourceProof events
/// to drive the transfer to completion (or timeout/cancellation).
///
/// The `_permit` is held for the lifetime of this task and released automatically
/// on completion, providing backpressure via the semaphore.
async fn drive_response_resource(
    transport: Arc<Mutex<TransportHandler>>,
    link_in_event_tx: broadcast::Sender<LinkEventData>,
    link_id: AddressHash,
    resource: Resource,
    label: String,
    cancel: CancellationToken,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    use crate::destination::link::LinkEvent;

    let resource_hash = hex::encode(&resource.hash()[..8]);

    // Build a Link facade for this incoming link
    let link_handle = {
        let handler = transport.lock().await;
        let Some(link_arc) = handler.link_manager.get_in_link(&link_id) else {
            log::warn!(
                "{}: in-link {} not found for response resource {}",
                label, link_id, resource_hash,
            );
            return;
        };
        let link_guard = link_arc.lock().await;
        let id = *link_guard.id();
        let destination = *link_guard.destination();
        let initiator = link_guard.is_initiator();
        drop(link_guard);
        Link::new(link_arc, transport.clone(), id, destination, initiator)
    };

    // Register the resource as outgoing on the link
    if let Err(e) = link_handle.register_outgoing_resource(&resource).await {
        log::warn!(
            "{}: failed to register outgoing response resource {}: {:?}",
            label, resource_hash, e,
        );
        return;
    }

    // Send the advertisement
    let advertisement = resource.create_advertisement();
    if let Err(e) = link_handle.send_resource_advertisement(&advertisement, 0).await {
        log::warn!(
            "{}: failed to send resource advertisement {}: {:?}",
            label, resource_hash, e,
        );
        return;
    }
    resource.mark_adv_sent();
    log::debug!("{}: sent response resource advertisement {}", label, resource_hash);

    // Subscribe to link events and drive the transfer
    let mut link_events = link_in_event_tx.subscribe();
    let deadline = tokio::time::Instant::now() + RESPONSE_RESOURCE_TIMEOUT;

    loop {
        if tokio::time::Instant::now() >= deadline {
            log::warn!(
                "{}: response resource {} timed out",
                label, resource_hash,
            );
            link_handle.resource_concluded(resource.truncated_hash(), false).await;
            return;
        }

        tokio::select! {
            _ = cancel.cancelled() => {
                log::debug!(
                    "{}: response resource {} cancelled",
                    label, resource_hash,
                );
                link_handle.resource_concluded(resource.truncated_hash(), false).await;
                return;
            }

            result = link_events.recv() => {
                match result {
                    Ok(event) => {
                        // Only handle events for our link
                        if event.id != link_id {
                            continue;
                        }

                        match &event.event {
                            LinkEvent::ResourceRequest(payload) => {
                                match resource.handle_request(payload.as_slice()) {
                                    Ok(result) => {
                                        // Send hashmap update if needed
                                        if let Some(ref hmu_data) = result.hashmap_update {
                                            if let Err(e) = link_handle
                                                .send_resource_hashmap_update(hmu_data)
                                                .await
                                            {
                                                log::warn!(
                                                    "{}: failed to send HMU for {}: {:?}",
                                                    label, resource_hash, e,
                                                );
                                            }
                                        }

                                        // Send requested parts
                                        let parts: Vec<_> = result.parts_to_send
                                            .iter()
                                            .filter_map(|&idx| {
                                                resource.get_part_data(idx).map(|d| (idx, d))
                                            })
                                            .collect();

                                        for (idx, part_data) in parts {
                                            if let Err(e) = link_handle
                                                .send_resource_data(&part_data)
                                                .await
                                            {
                                                log::warn!(
                                                    "{}: failed to send part {} of {}: {:?}",
                                                    label, idx, resource_hash, e,
                                                );
                                                link_handle.resource_concluded(
                                                    resource.truncated_hash(), false,
                                                ).await;
                                                return;
                                            }
                                            resource.mark_part_sent(idx);
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "{}: handle_request error for {}: {:?}",
                                            label, resource_hash, e,
                                        );
                                    }
                                }
                            }

                            LinkEvent::ResourceProof(payload) => {
                                if resource.verify_proof(payload.as_slice()) {
                                    log::debug!(
                                        "{}: response resource {} proof verified, transfer complete",
                                        label, resource_hash,
                                    );
                                    link_handle.resource_concluded(
                                        resource.truncated_hash(), true,
                                    ).await;
                                    return;
                                }
                            }

                            LinkEvent::Closed => {
                                log::debug!(
                                    "{}: link closed during response resource {} transfer",
                                    label, resource_hash,
                                );
                                link_handle.resource_concluded(
                                    resource.truncated_hash(), false,
                                ).await;
                                return;
                            }

                            _ => {} // Ignore other events
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!(
                            "{}: response resource {} lagged {} events",
                            label, resource_hash, n,
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        log::debug!(
                            "{}: event channel closed for response resource {}",
                            label, resource_hash,
                        );
                        link_handle.resource_concluded(
                            resource.truncated_hash(), false,
                        ).await;
                        return;
                    }
                }
            }

            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

impl TransportHandler {
    /// Send a response packet on an inbound link, logging all failure modes.
    ///
    /// Consolidates the repeated "look up link, check status, encrypt, send"
    /// pattern used by request dispatch, remote management, and blackhole info.
    /// Returns `true` if the response was sent successfully.
    async fn send_response_on_link(
        &self,
        link_id: &AddressHash,
        data: &[u8],
        label: &str,
    ) -> bool {
        let Some(link_arc) = self.link_manager.get_in_link(link_id) else {
            log::warn!("{}: link {} not found, cannot send response", label, link_id);
            return false;
        };

        let link = link_arc.lock().await;
        let status = link.status();
        if status != LinkStatus::Active {
            log::warn!("{}: link {} is {:?}, cannot send response", label, link_id, status);
            return false;
        }

        match link.response_packet(data) {
            Ok(packet) => {
                self.send_packet(packet).await;
                log::debug!("{}: sent response on link {}", label, link_id);
                true
            }
            Err(e) => {
                log::warn!("{}: failed to create response packet on link {}: {}", label, link_id, e);
                false
            }
        }
    }

    async fn send_packet(&self, packet: Packet) {
        // Check if destination needs routing through path_table
        // This adds HEADER_2 routing for remote destinations (hops > 1)
        // and keeps HEADER_1 for directly reachable destinations (hops == 1)
        let (routed_packet, maybe_iface) = self.path_manager.handle_packet(&packet);

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
                    if let Some(link) = self.link_manager.get_in_link(&packet.destination) {
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
    for link in handler.link_manager.out_link_values() {
        let mut link = link.lock().await;
        if let LinkResult::Activated = link.handle_packet(packet) {
            match link.create_rtt() {
                Ok(rtt_packet) => handler.send_packet(rtt_packet).await,
                Err(e) => log::error!("link({}): failed to create RTT packet: {}", link.id(), e),
            }
        }
    }

    // Handle packet proofs (for receipts)
    // For explicit proofs, use the proof hash (first 32 bytes) to locate receipt.
    if packet.context != PacketContext::LinkRequestProof {
        let truncated_hash: [u8; 16] = if packet.data.len() == EXPLICIT_PROOF_LENGTH {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&packet.data.as_slice()[..16]);
            arr
        } else {
            // Fallback to packet destination (non-link proofs)
            let slice = packet.destination.as_slice();
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&slice[..16]);
            arr
        };

        if let Some(receipt) = handler.receipt_manager.get(&truncated_hash).await {
            let proof_data = packet.data.as_slice();

            if packet.header.destination_type == DestinationType::Link {
                // Link proof: validate with the link peer identity
                let mut peer_identity = None;
                if let Some(link) = handler.link_manager.get_in_link(&packet.destination) {
                    let link_guard = link.lock().await;
                    peer_identity = Some(*link_guard.peer_identity());
                } else {
                    let out_links: Vec<Arc<Mutex<LinkInner>>> =
                        handler.link_manager.out_link_values().cloned().collect();
                    for link in out_links {
                        let link_guard = link.lock().await;
                        if *link_guard.id() == packet.destination {
                            peer_identity = Some(*link_guard.peer_identity());
                            break;
                        }
                    }
                }

                if let Some(identity) = peer_identity {
                    let mut receipt_guard = receipt.lock().await;
                    if receipt_guard.validate_link_proof(proof_data, &identity, None) {
                        log::debug!(
                            "tp({}): validated link proof for packet {}",
                            handler.config.name,
                            packet.destination
                        );
                    }
                }
            } else {
                let mut receipt_guard = receipt.lock().await;
                if let Some(dest_hash) = receipt_guard.destination_hash() {
                    // Non-link proof: validate with destination identity
                    let dest_hash_arr = AddressHash::new(*dest_hash);
                    if let Some(dest) = handler.single_out_destinations.get(&dest_hash_arr) {
                        let dest_lock = dest.lock().await;
                        let identity = &dest_lock.identity;

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

    let maybe_packet = handler.link_manager.handle_proof(packet);

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
    let (packet, maybe_iface) = handler.path_manager.handle_inbound_packet(
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
            let lookup = handler.link_manager.handle_keepalive(packet);

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
    from_local_client: bool,
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

    if handler.path_manager.has_seen_request(&unique_tag) {
        log::debug!(
            "tp({}): ignoring duplicate path request for {}",
            handler.config.name,
            destination_hash
        );
        return;
    }

    // Add to tag cache
    handler.path_manager.mark_request_seen(unique_tag);

    // Process the path request
    process_path_request(
        destination_hash,
        requesting_transport_id,
        Some(&tag),
        iface,
        from_local_client,
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
    from_local_client: bool,
    mut handler: MutexGuard<'a, TransportHandler>,
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
        let mut dest = destination.lock().await;
        if let Ok(mut announce_packet) = dest.announce(OsRng, None) {
            announce_packet.context = PacketContext::PathResponse;
            drop(dest);
            handler.send_packet(announce_packet).await;
        }
        return;
    }

    // Case 2: Path known in path_table — answer if transport enabled or request is from local client
    if (is_transport_enabled || from_local_client)
        && handler.path_manager.has_path(&destination_hash)
    {
        if let Some(next_hop) = handler.path_manager.next_hop(&destination_hash) {
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

            // Get the cached announce packet and the interface it was received on
            // from the path table. The path table persists for the lifetime of the
            // path, unlike the announce_table which evicts after retransmission (~5-6s).
            let announce_info = handler
                .path_manager
                .get_announce_packet(&destination_hash)
                .map(|p| {
                    let hops = handler.path_manager.hops_to(&destination_hash).unwrap_or(0);
                    let announce_iface = handler.path_manager.next_hop_iface(&destination_hash)
                        .unwrap_or(attached_interface);
                    (*p, hops, announce_iface)
                });

            if let Some((announce_packet, hops, announce_iface)) = announce_info {
                log::debug!(
                    "tp({}): answering path request for {}, path known ({} hops, local_client={})",
                    handler.config.name,
                    destination_hash,
                    hops,
                    from_local_client
                );

                if from_local_client {
                    // Local client requests get an immediate response (matches Python:
                    // retransmit_timeout = now when is_from_local_client)
                    let mut response_packet = announce_packet;
                    response_packet.context = PacketContext::PathResponse;
                    handler
                        .send(TxMessage {
                            tx_type: TxMessageType::Broadcast(Some(attached_interface)),
                            packet: response_packet,
                        })
                        .await;
                } else {
                    // Transport node answering a network request: schedule via announce
                    // table with grace period so closer peers can answer first (matches
                    // Python: retransmit_timeout = now + PATH_REQUEST_GRACE).
                    // Exclude the interface the announce was ORIGINALLY received from
                    // (not the path request source), matching Python's behavior.
                    handler.announce_manager.add_path_response(
                        &announce_packet,
                        destination_hash,
                        announce_iface,
                        hops,
                        path_request::PATH_REQUEST_RESPONSE_GRACE,
                    );
                }
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
            PathRequestManager::create_request_packet(&destination_hash, transport_id.as_ref(), None);

        // Send on all interfaces except the one that sent us the request
        handler
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(Some(attached_interface)),
                packet: forward_packet,
            })
            .await;
    } else {
        log::debug!(
            "tp({}): ignoring path request for {}, no path known (transport={}, local_client={})",
            handler.config.name,
            destination_hash,
            is_transport_enabled,
            from_local_client
        );
    }
}

async fn handle_data<'a>(packet: &Packet, iface: AddressHash, from_local_client: bool, handler: MutexGuard<'a, TransportHandler>) {
    let mut data_handled = false;

    // Check for path request control packets (PLAIN destination type)
    if packet.header.destination_type == DestinationType::Plain {
        let path_request_hash = *PlainDestination::new("rnstransport", "path.request")
            .expect("valid destination name")
            .address_hash();

        if packet.destination == path_request_hash {
            handle_path_request(packet, iface, from_local_client, handler).await;
            return;
        }
    }

    if packet.header.destination_type == DestinationType::Link {
        if let Some(link) = handler.link_manager.get_in_link(&packet.destination) {
            let link_arc = link.clone();
            let (result, dest_hash, initiator) = {
                let mut link = link_arc.lock().await;
                let result = link.handle_packet(packet);
                (result, link.destination().address_hash, link.is_initiator())
            };

            if let LinkResult::KeepAlive = result {
                let link = link_arc.lock().await;
                let packet = link.keep_alive_packet(KEEP_ALIVE_RESPONSE);
                handler.send_packet(packet).await;
            }

            if let LinkResult::DataReceived = result {
                let should_prove = if initiator {
                    if let Some(dest) = handler.single_out_destinations.get(&dest_hash) {
                        let dest = dest.lock().await;
                        dest.should_prove(packet)
                    } else {
                        false
                    }
                } else if let Some(dest) = handler.single_in_destinations.get(&dest_hash) {
                    let dest = dest.lock().await;
                    dest.should_prove(packet)
                } else {
                    false
                };

                if should_prove {
                    let link = link_arc.lock().await;
                    let proof = link.proof_packet(packet);
                    handler.send_packet(proof).await;
                }
            }
        }

        let out_links: Vec<Arc<Mutex<LinkInner>>> =
            handler.link_manager.out_link_values().cloned().collect();
        for link_arc in out_links {
            let (result, dest_hash, initiator) = {
                let mut link = link_arc.lock().await;
                let result = link.handle_packet(packet);
                (result, link.destination().address_hash, link.is_initiator())
            };

            if let LinkResult::DataReceived = result {
                let should_prove = if initiator {
                    if let Some(dest) = handler.single_out_destinations.get(&dest_hash) {
                        let dest = dest.lock().await;
                        dest.should_prove(packet)
                    } else {
                        false
                    }
                } else if let Some(dest) = handler.single_in_destinations.get(&dest_hash) {
                    let dest = dest.lock().await;
                    dest.should_prove(packet)
                } else {
                    false
                };

                if should_prove {
                    let link = link_arc.lock().await;
                    let proof = link.proof_packet(packet);
                    handler.send_packet(proof).await;
                }
            }

            data_handled = true;
        }

        if handle_keepalive_response(packet, &handler).await {
            return;
        }

        let lookup = handler.link_manager.original_destination(&packet.destination);
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
        if let Some(destination) = handler
            .single_in_destinations
            .get(&packet.destination)
            .cloned()
        {
            data_handled = true;

            let (received, proof_packet) = {
                let mut dest = destination.lock().await;
                let received = dest.receive(packet);
                let proof_packet = if received && dest.should_prove(packet) {
                    Some(dest.proof_packet(packet, handler.config.use_implicit_proof))
                } else {
                    None
                };
                (received, proof_packet)
            };

            if received {
                handler.received_data_tx.send(ReceivedData {
                    destination: packet.destination,
                    data: packet.data,
                }).ok();
            }

            if let Some(proof) = proof_packet {
                handler.send_packet(proof).await;
            }
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
    // Debug log to trace announce processing
    log::debug!(
        "handle_announce: processing announce for {} (from_local_client={}, hops={}, client_mode={})",
        packet.destination,
        from_local_client,
        packet.header.hops,
        handler.config.is_client_mode()
    );

    if let Some(blocked_until) = handler.announce_manager.check_rate_limit(&packet.destination) {
        log::info!(
            "tp({}): too many announces from {}, blocked for {} seconds",
            handler.config.name,
            &packet.destination,
            blocked_until.as_secs(),
        );
        return;
    }

    // Early blackhole rejection — reject announces from blackholed identities
    // before expensive signature verification (Python: Identity.py:433-436).
    // The identity hash is SHA256(public_key || verifying_key)[..16], and the
    // raw keys sit at offset 0..64 of packet.data.
    if packet.data.len() >= 64 {
        let identity_hash = AddressHash::new_from_slice(&packet.data.as_slice()[..64]);
        if handler.blackhole_manager.is_blackholed(&identity_hash) {
            log::debug!(
                "handle_announce: dropped announce from blackholed identity {}",
                identity_hash
            );
            return;
        }
    }

    let destination_known = handler.has_destination(&packet.destination);
    log::debug!(
        "handle_announce: destination_known={} for {}",
        destination_known,
        packet.destination
    );

    if let Ok(validation) = DestinationAnnounce::validate_full(packet) {
        log::debug!("handle_announce: validation succeeded for {}", packet.destination);
        let destination = validation.destination;
        let app_data = validation.app_data;
        let dest_hash = destination.identity.address_hash;

        // Build the full 64-byte public key (encryption + signing) for comparison
        let announced_pub_key = {
            let mut key = Vec::with_capacity(64);
            key.extend_from_slice(destination.identity.public_key_bytes());
            key.extend_from_slice(destination.identity.verifying_key_bytes());
            key
        };

        // Convert destination hash to fixed-size array for KnownDestinations API
        let dest_hash_bytes: [u8; 16] = {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(packet.destination.as_slice());
            buf
        };

        // Hash collision detection (Python: Identity.py:449-455).
        // If a different public key is already known for this destination hash,
        // reject the announce as a possible collision or attack.
        if let Some(known) = handler.known_destinations.recall(&dest_hash_bytes) {
            if known.public_key != announced_pub_key {
                log::error!(
                    "Announce for {} has valid signature but public key differs from known key. \
                     Possible hash collision or attack. Rejecting.",
                    packet.destination
                );
                return;
            }
        }

        // Remember this destination (Python: Identity.py:457)
        let _ = handler.known_destinations.remember(
            &dest_hash_bytes,
            &[],  // packet_hash — not currently tracked at this layer
            &announced_pub_key,
            if app_data.is_empty() { None } else { Some(app_data) },
        );

        // Store ratchet if present (Python: Identity.py:477-478)
        if let Some(ref ratchet) = validation.ratchet {
            if let Err(e) = handler.ratchet_manager.remember(&dest_hash_bytes, ratchet) {
                log::warn!("Failed to store ratchet for {}: {}", packet.destination, e);
            }
        }

        // Capture the announced identity and desc before wrapping in Arc<Mutex<>>
        let announced_identity = destination.identity;
        let dest_desc = destination.desc;

        let destination = Arc::new(Mutex::new(destination));

        // Get hop count for logging
        let hops = packet.header.hops;

        // Determine interface name for logging
        let iface_name = if from_local_client {
            "LocalInterface[unix-client]"
        } else {
            "TCPInterface"
        };

        if !destination_known {
            handler
                .single_out_destinations
                .entry(packet.destination)
                .or_insert_with(|| {
                    log::debug!(
                        "Valid announce for {} {} hops away, received on {}",
                        packet.destination,
                        hops,
                        iface_name
                    );
                    destination.clone()
                });

            handler.announce_manager.add(
                packet,
                dest_hash,
                iface,
                from_local_client,
            );

            // Get actual interface mode from interface registry for correct path expiry times
            let interface_mode = handler
                .interface_registry
                .get(&iface)
                .await
                .map(|metadata| metadata.mode)
                .unwrap_or(InterfaceMode::Full);

            let path_updated = handler.path_manager.handle_announce(
                packet,
                packet.transport,
                iface,
                interface_mode,
            );

            // Notify announce handlers if the path was updated
            if path_updated {
                use crate::destination::NAME_HASH_LENGTH;
                use crate::identity::PUBLIC_KEY_LENGTH;
                use announce_handler::AnnounceData;

                let announce_data = AnnounceData {
                    destination_hash: packet.destination,
                    announced_identity,
                    app_data: if app_data.is_empty() {
                        None
                    } else {
                        Some(PacketDataBuffer::new_from_slice(app_data))
                    },
                    announce_packet_hash: packet.hash(),
                    is_path_response: packet.context == PacketContext::PathResponse,
                };

                // Extract name hash from packet data (10 bytes at offset 64)
                let name_hash = if packet.data.len() >= PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH {
                    let mut nh = Hash::new_empty();
                    nh.as_slice_mut()[..NAME_HASH_LENGTH].copy_from_slice(
                        &packet.data.as_slice()[PUBLIC_KEY_LENGTH * 2..PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH]
                    );
                    Some(nh)
                } else {
                    None
                };

                handler.announce_handler_registry.notify_spawned(announce_data, name_hash.as_ref());
            }
        }

        log::debug!(
            "handle_announce: past destination_known block for {}, proceeding to emit",
            packet.destination
        );

        // Retransmit announces if transport is enabled OR if from local client.
        // This matches Python behavior where local client announces are always
        // forwarded to network interfaces even when transport is disabled.
        let should_retransmit = handler.config.retransmit || from_local_client;
        if should_retransmit {
            let transport_id = *handler.config.identity.address_hash();
            if let Some((recv_from, retransmit_packet)) = handler.announce_manager.new_packet(
                &dest_hash,
                &transport_id,
            ) {
                let hops = retransmit_packet.header.hops;

                // Local announces (hops=0) bypass bandwidth limiting
                if hops == 0 {
                    log::debug!(
                        "Rebroadcasting local announce for {} with hop count {}",
                        retransmit_packet.destination,
                        hops
                    );
                    handler.send(TxMessage {
                        tx_type: TxMessageType::Broadcast(Some(recv_from)),
                        packet: retransmit_packet
                    }).await;
                } else {
                    // For non-local announces, use per-interface bandwidth limiting
                    let interfaces = handler.iface_manager.lock().await.network_interface_addresses();

                    for iface_addr in interfaces {
                        // Skip the interface that sent us this announce
                        if iface_addr == recv_from {
                            continue;
                        }

                        // Check if this interface can transmit now
                        if handler.announce_queue_manager.can_transmit_now(&iface_addr, hops) {
                            // Send immediately and record transmit time
                            log::debug!(
                                "Rebroadcasting announce for {} on {} with hop count {}",
                                retransmit_packet.destination,
                                iface_addr,
                                hops
                            );

                            // Estimate packet size for timing calculation (100 bytes is reasonable)
                            let packet_size = 100;
                            handler.announce_queue_manager.record_transmit(&iface_addr, packet_size);

                            handler.send(TxMessage {
                                tx_type: TxMessageType::Direct(iface_addr),
                                packet: retransmit_packet
                            }).await;
                        } else {
                            // Queue for later transmission
                            let queued = QueuedAnnounce {
                                timestamp: std::time::Instant::now(),
                                hops,
                                packet: retransmit_packet,
                                destination_hash: dest_hash,
                                received_from: recv_from,
                            };
                            handler.announce_queue_manager.enqueue(&iface_addr, queued);

                            log::trace!(
                                "Queued announce for {} on {} (queue size: {})",
                                retransmit_packet.destination,
                                iface_addr,
                                handler.announce_queue_manager.total_queued()
                            );
                        }
                    }
                }
            }
        }

        // Emit announce event to subscribers
        let _ = handler.announce_manager.emit(AnnounceEvent {
            destination: dest_desc,
            app_data: PacketDataBuffer::new_from_slice(app_data),
            is_path_response: packet.context == PacketContext::PathResponse,
        });
    } else {
        log::warn!(
            "handle_announce: validation FAILED for {} - announce will not be processed",
            packet.destination
        );
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
            if !handler.link_manager.has_in_link(&link_id) {
                log::trace!(
                    "tp({}): send proof to {}",
                    handler.config.name,
                    packet.destination
                );

                let link = LinkInner::new_from_request(
                    packet,
                    destination.sign_key().clone(),
                    destination.desc,
                    handler.link_manager.in_event_sender(),
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
                        .link_manager
                        .insert_in_link(*link.id(), Arc::new(Mutex::new(link)));
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
    handler.link_manager.add_table_entry(
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
    } else if let Some(entry) = handler.path_manager.next_hop_full(&packet.destination) {
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

    // Clean up input links — collect dest hashes of timed-out links
    let mut timed_out_input_destinations: Vec<AddressHash> = Vec::new();

    let mut linkclose_packets: Vec<Packet> = Vec::new();

    for (addr, link_arc) in handler.link_manager.in_links() {
        let mut link = link_arc.lock().await;
        if link.elapsed() > INTERVAL_INPUT_LINK_CLEANUP {
            timed_out_input_destinations.push(link.destination().address_hash);
            if let Some(packet) = link.close() {
                linkclose_packets.push(packet);
            }
            links_to_remove.push(*addr);
        }
    }

    for addr in &links_to_remove {
        handler.link_manager.remove_in_link(addr);
    }

    // Mark paths as unresponsive for timed-out input link destinations
    for dest_hash in &timed_out_input_destinations {
        if handler.path_manager.mark_path_unresponsive(dest_hash) {
            log::debug!(
                "Marked path to {} as unresponsive due to timed-out input link",
                dest_hash
            );
        }
    }

    links_to_remove.clear();

    // Collect destination hashes of closed output links to mark paths unresponsive
    let mut closed_destinations: Vec<AddressHash> = Vec::new();

    for (addr, link_arc) in handler.link_manager.out_links() {
        let mut link = link_arc.lock().await;
        if link.status() == LinkStatus::Closed {
            closed_destinations.push(link.destination().address_hash);
            if let Some(packet) = link.close() {
                linkclose_packets.push(packet);
            }
            links_to_remove.push(*addr);
        }
    }

    for addr in &links_to_remove {
        handler.link_manager.remove_out_link(addr);
    }

    // Mark paths as unresponsive for destinations whose links were closed/timed-out.
    // This enables the multi-factor path update logic to accept alternative paths.
    for dest_hash in &closed_destinations {
        if handler.path_manager.mark_path_unresponsive(dest_hash) {
            log::debug!(
                "Marked path to {} as unresponsive due to closed link",
                dest_hash
            );
        }
    }

    // Send LINKCLOSE packets collected during link cleanup
    for packet in linkclose_packets {
        handler.send_packet(packet).await;
    }

    for (_, link_arc) in handler.link_manager.out_links() {
        let mut link = link_arc.lock().await;

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
    for link in handler.link_manager.out_link_values() {
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
    let announces = handler.announce_manager.to_retransmit(&transport_id);

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

/// Process announce queues for ANNOUNCE_CAP bandwidth limiting.
///
/// This function processes per-interface announce queues and sends queued
/// announces when the interface is allowed to transmit (based on bandwidth cap).
async fn process_announce_queues<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    // Get all ready announces from queues
    let ready = handler.announce_queue_manager.process_queues();

    if ready.is_empty() {
        return;
    }

    for (iface_addr, queued) in ready {
        log::debug!(
            "Processing queued announce for {} on {} (hops={})",
            queued.destination_hash,
            iface_addr,
            queued.hops
        );

        // Record the transmit time for this interface
        let packet_size = 100; // Estimate packet size
        handler.announce_queue_manager.record_transmit(&iface_addr, packet_size);

        // Send to the specific interface
        handler.send(TxMessage {
            tx_type: TxMessageType::Direct(iface_addr),
            packet: queued.packet,
        }).await;
    }
}

#[allow(dead_code)]
fn create_retransmit_packet(packet: &Packet) -> Packet {
    Packet {
        header: Header {
            ifac_flag: packet.header.ifac_flag,
            header_type: packet.header.header_type,
            context_flag: packet.header.context_flag,
            transport_type: packet.header.transport_type,
            destination_type: packet.header.destination_type,
            packet_type: packet.header.packet_type,
            hops: packet.header.hops + 1,
        },
        ifac: packet.ifac,
        destination: packet.destination,
        transport: packet.transport,
        context: packet.context,
        data: packet.data,
        ratchet_id: None,
    }
}


async fn manage_transport(
    handler: Arc<Mutex<TransportHandler>>,
    rx_receiver: Arc<Mutex<InterfaceRxReceiver>>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
) {
    let cancel = handler.lock().await.cancel.clone();
    let retransmit = handler.lock().await.config.retransmit;
    let client_mode = handler.lock().await.config.is_client_mode();

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

                        // Determine whether to broadcast this packet.
                        // Python never broadcasts LinkRequests or LinkRequestProofs —
                        // LinkRequests are routed via path table (send_to_next_hop),
                        // and LRPROOFs via link table (send_backwards).
                        // Other proofs (receipt proofs) are broadcast here since
                        // the reverse table is not yet implemented.
                        // Announces are handled separately in handle_announce.
                        let is_link_request_proof = packet.header.packet_type == PacketType::Proof
                            && packet.context == PacketContext::LinkRequestProof;
                        if handler.config.broadcast
                            && packet.header.packet_type != PacketType::Announce
                            && packet.header.packet_type != PacketType::LinkRequest
                            && !is_link_request_proof
                        {
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
                            PacketType::Data => handle_data(&packet, message.address, from_local_client, handler).await,
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

                        handler.link_manager.remove_stale();
                    },
                }
            }
        });
    }

    // In client mode, the daemon handles announce retransmission
    if retransmit && !client_mode {
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

    // Process announce queues for ANNOUNCE_CAP bandwidth limiting
    if retransmit && !client_mode {
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
                    _ = time::sleep(INTERVAL_ANNOUNCE_QUEUE_PROCESS) => {
                        process_announce_queues(handler.lock().await).await;
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
    use rand_core::RngCore;

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

    #[tokio::test]
    async fn test_blackhole_identity() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let identity_hash = AddressHash::new_from_slice(&[0xABu8; 32]);

        // Initially not blackholed
        assert!(!transport.is_blackholed(&identity_hash).await);
        assert!(transport.get_blackholed_identities().await.is_empty());

        // Blackhole the identity
        transport.blackhole_identity(identity_hash).await;

        // Should now be blackholed
        assert!(transport.is_blackholed(&identity_hash).await);
        assert_eq!(transport.get_blackholed_identities().await.len(), 1);

        // Unblackhole
        transport.unblackhole_identity(&identity_hash).await;

        // Should no longer be blackholed
        assert!(!transport.is_blackholed(&identity_hash).await);
        assert!(transport.get_blackholed_identities().await.is_empty());
    }

    #[tokio::test]
    async fn test_blackhole_identity_temporary() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let identity_hash = AddressHash::new_from_slice(&[0xCDu8; 32]);

        // Blackhole temporarily for 1 hour
        transport
            .blackhole_identity_temporary(identity_hash, Duration::from_secs(3600))
            .await;

        // Should be blackholed
        assert!(transport.is_blackholed(&identity_hash).await);
    }

    #[tokio::test]
    async fn test_multiple_blackholed_identities() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let id1 = AddressHash::new_from_slice(&[1u8; 32]);
        let id2 = AddressHash::new_from_slice(&[2u8; 32]);
        let id3 = AddressHash::new_from_slice(&[3u8; 32]);

        transport.blackhole_identity(id1).await;
        transport.blackhole_identity(id2).await;
        transport.blackhole_identity(id3).await;

        assert_eq!(transport.get_blackholed_identities().await.len(), 3);
        assert!(transport.is_blackholed(&id1).await);
        assert!(transport.is_blackholed(&id2).await);
        assert!(transport.is_blackholed(&id3).await);

        // Remove one
        transport.unblackhole_identity(&id2).await;
        assert_eq!(transport.get_blackholed_identities().await.len(), 2);
        assert!(!transport.is_blackholed(&id2).await);
    }

    #[tokio::test]
    async fn test_register_announce_handler() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        // Initially no handlers
        assert_eq!(transport.announce_handler_count().await, 0);

        // Register a handler
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let handle = transport
            .register_announce_handler(
                AnnounceHandlerConfig::default(),
                Arc::new(move |_data: announce_handler::AnnounceData| {
                    call_count_clone.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .await;

        assert_eq!(transport.announce_handler_count().await, 1);

        // Deregister
        transport.deregister_announce_handler(handle).await;
        assert_eq!(transport.announce_handler_count().await, 0);
    }

    #[tokio::test]
    async fn test_multiple_announce_handlers() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let handle1 = transport
            .register_announce_handler(
                AnnounceHandlerConfig::default(),
                Arc::new(|_: announce_handler::AnnounceData| {}),
            )
            .await;

        let handle2 = transport
            .register_announce_handler(
                AnnounceHandlerConfig::default().receive_path_responses(),
                Arc::new(|_: announce_handler::AnnounceData| {}),
            )
            .await;

        assert_eq!(transport.announce_handler_count().await, 2);

        // Remove first handler
        transport.deregister_announce_handler(handle1).await;
        assert_eq!(transport.announce_handler_count().await, 1);

        // Remove second handler
        transport.deregister_announce_handler(handle2).await;
        assert_eq!(transport.announce_handler_count().await, 0);
    }

    #[tokio::test]
    async fn test_blackhole_rejects_announce() {
        use crate::destination::{DestinationName, SingleInputDestination};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        // Create an identity and build a valid announce packet
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut destination =
            SingleInputDestination::new(identity.clone(), DestinationName::new("test", "app").unwrap());
        let announce = destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        // Compute the identity hash (SHA256 of public_key || verifying_key, truncated)
        let identity_hash = identity.as_identity().address_hash;

        // Blackhole this identity
        handler.lock().await.blackhole_manager.add(identity_hash);

        // The announce should be silently dropped (blackhole check fires before validate)
        let iface = AddressHash::new_from_slice(&[0xFFu8; 32]);
        handle_announce(&announce, handler.lock().await, iface, false).await;

        // Destination should NOT have been stored in single_out_destinations
        assert!(
            !handler
                .lock()
                .await
                .single_out_destinations
                .contains_key(&announce.destination),
            "Blackholed identity's announce should be rejected"
        );
    }

    #[tokio::test]
    async fn test_hash_collision_rejects_announce() {
        use crate::destination::{DestinationName, SingleInputDestination};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        // Create two different identities
        let identity_a = PrivateIdentity::new_from_rand(OsRng);
        let identity_b = PrivateIdentity::new_from_rand(OsRng);

        // Create a valid announce from identity A
        let mut dest_a =
            SingleInputDestination::new(identity_a.clone(), DestinationName::new("test", "app").unwrap());
        let announce_a = dest_a
            .announce(OsRng, None)
            .expect("valid announce packet");

        // Pre-populate known_destinations with identity B's key under identity A's
        // destination hash — simulating a collision scenario.
        let dest_hash: [u8; 16] = {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(announce_a.destination.as_slice());
            buf
        };
        let fake_key_b = {
            let mut key = Vec::with_capacity(64);
            key.extend_from_slice(identity_b.as_identity().public_key_bytes());
            key.extend_from_slice(identity_b.as_identity().verifying_key_bytes());
            key
        };
        handler
            .lock()
            .await
            .known_destinations
            .remember(&dest_hash, &[], &fake_key_b, None)
            .expect("remember should succeed");

        // Process the announce from identity A — should be rejected because the
        // stored key (B) differs from the announced key (A).
        let iface = AddressHash::new_from_slice(&[0xFFu8; 32]);
        handle_announce(&announce_a, handler.lock().await, iface, false).await;

        assert!(
            !handler
                .lock()
                .await
                .single_out_destinations
                .contains_key(&announce_a.destination),
            "Announce with colliding hash should be rejected"
        );

        // The stored key should still be identity B's (unchanged)
        let stored = handler
            .lock()
            .await
            .known_destinations
            .recall(&dest_hash)
            .expect("destination should still be in known_destinations");
        assert_eq!(
            stored.public_key, fake_key_b,
            "Known key should not have been overwritten by the rejected announce"
        );
    }

    #[tokio::test]
    async fn test_valid_announce_remembered() {
        use crate::destination::{DestinationName, SingleInputDestination};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut destination =
            SingleInputDestination::new(identity.clone(), DestinationName::new("test", "app").unwrap());
        let announce = destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        let iface = AddressHash::new_from_slice(&[0xFFu8; 32]);
        handle_announce(&announce, handler.lock().await, iface, false).await;

        // Validated announces are stored in single_out_destinations (remote destinations
        // learned via announces), not single_in_destinations (locally-owned destinations).
        assert!(
            handler
                .lock()
                .await
                .single_out_destinations
                .contains_key(&announce.destination),
            "Valid announce should be accepted and stored in single_out_destinations"
        );

        // KnownDestinations should remember the key
        let dest_hash: [u8; 16] = {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(announce.destination.as_slice());
            buf
        };
        let stored = handler
            .lock()
            .await
            .known_destinations
            .recall(&dest_hash)
            .expect("destination should be remembered after valid announce");

        let expected_key = {
            let mut key = Vec::with_capacity(64);
            key.extend_from_slice(identity.as_identity().public_key_bytes());
            key.extend_from_slice(identity.as_identity().verifying_key_bytes());
            key
        };
        assert_eq!(stored.public_key, expected_key);
    }

    #[tokio::test]
    async fn test_recall_identity_returns_none_for_unknown() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let unknown_hash = AddressHash::new_from_slice(&[0xDEu8; 32]);
        assert!(
            transport.recall_identity(&unknown_hash).await.is_none(),
            "recall_identity should return None for an unknown destination"
        );
    }

    #[tokio::test]
    async fn test_recall_identity_from_known_destinations() {
        // Verifies the fallback path: when a destination is only in
        // known_destinations (e.g. loaded from disk) and NOT in
        // single_out_destinations, recall_identity should still find it.
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let pub_id = identity.as_identity();
        let public_key_bytes = pub_id.to_bytes();

        // Use a synthetic destination hash (not derived from any real
        // destination name) — we only need the hash to be a valid key.
        let dest_hash_bytes = [0xAAu8; 16];
        let dest_hash = AddressHash::new({
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&dest_hash_bytes);
            buf
        });

        // Populate known_destinations directly (simulates loading from disk).
        // Do NOT insert into single_out_destinations.
        handler
            .lock()
            .await
            .known_destinations
            .remember(&dest_hash_bytes, &[], &public_key_bytes, None)
            .expect("remember should succeed");

        // recall_identity should find the identity via the fallback path
        let recalled = transport.recall_identity(&dest_hash).await;
        assert!(recalled.is_some(), "recall_identity should fall back to known_destinations");

        let recalled = recalled.unwrap();
        assert_eq!(
            recalled.public_key.as_bytes(),
            pub_id.public_key.as_bytes(),
            "recalled identity public key should match"
        );
        assert_eq!(
            recalled.verifying_key.as_bytes(),
            pub_id.verifying_key.as_bytes(),
            "recalled identity verifying key should match"
        );
    }

    #[tokio::test]
    async fn test_recall_identity_prefers_single_out_destinations() {
        // When the same destination hash exists in both single_out_destinations
        // and known_destinations, the single_out_destinations entry should win.
        use crate::destination::{DestinationName, SingleOutputDestination};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let identity_a = PrivateIdentity::new_from_rand(OsRng);
        let identity_b = PrivateIdentity::new_from_rand(OsRng);
        let pub_id_a = *identity_a.as_identity();
        let pub_id_b = *identity_b.as_identity();

        let name = DestinationName::new("test", "recall").unwrap();

        // Build a SingleOutputDestination with identity A and grab its address hash
        let dest_a = SingleOutputDestination::new(pub_id_a, name);
        let address_hash = dest_a.desc.address_hash;
        let dest_hash_bytes: [u8; 16] = {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(address_hash.as_slice());
            buf
        };

        // Insert identity A's destination into single_out_destinations
        handler
            .lock()
            .await
            .single_out_destinations
            .insert(address_hash, Arc::new(Mutex::new(dest_a)));

        // Insert identity B's key into known_destinations under the SAME hash
        let key_b = pub_id_b.to_bytes();
        handler
            .lock()
            .await
            .known_destinations
            .remember(&dest_hash_bytes, &[], &key_b, None)
            .expect("remember should succeed");

        // recall_identity should return identity A (from single_out_destinations)
        let recalled = transport.recall_identity(&address_hash).await
            .expect("recall_identity should return an identity");

        assert_eq!(
            recalled.public_key.as_bytes(),
            pub_id_a.public_key.as_bytes(),
            "recall_identity should prefer single_out_destinations over known_destinations"
        );
    }

    #[tokio::test]
    async fn test_send_to_destination_via_single_out() {
        // When a destination is in single_out_destinations (learned from an announce),
        // send_to_destination should encrypt and return a PacketReceiptInner.
        use crate::destination::{DestinationName, SingleOutputDestination};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        // Create a remote identity and build a SingleOutputDestination
        let remote_identity = PrivateIdentity::new_from_rand(OsRng);
        let pub_id = *remote_identity.as_identity();
        let name = DestinationName::new("test", "send").unwrap();
        let dest = SingleOutputDestination::new(pub_id, name);
        let address_hash = dest.desc.address_hash;

        // Insert into single_out_destinations (simulates having received an announce)
        transport
            .get_handler()
            .lock()
            .await
            .single_out_destinations
            .insert(address_hash, Arc::new(Mutex::new(dest)));

        let plaintext = b"hello reticulum";
        let result = transport
            .send_to_destination(&address_hash, plaintext, PacketContext::None)
            .await;

        assert!(result.is_ok(), "send_to_destination should succeed for a known destination");
        let receipt = result.unwrap();
        // Verify the receipt was created with the correct destination
        let receipt_dest = receipt.destination_hash()
            .expect("receipt should have a destination hash");
        assert_eq!(
            &receipt_dest[..],
            &address_hash.as_slice()[..16],
            "receipt destination should match"
        );
    }

    #[tokio::test]
    async fn test_send_to_destination_via_known_destinations() {
        // When a destination is only in known_destinations (persistence fallback),
        // send_to_destination should still succeed.
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let remote_identity = PrivateIdentity::new_from_rand(OsRng);
        let pub_id = remote_identity.as_identity();
        let public_key_bytes = pub_id.to_bytes();

        // Use a synthetic destination hash
        let dest_hash_bytes = [0xBBu8; 16];
        let dest_hash = AddressHash::new(dest_hash_bytes);

        // Populate known_destinations only (not single_out_destinations)
        handler
            .lock()
            .await
            .known_destinations
            .remember(&dest_hash_bytes, &[], &public_key_bytes, None)
            .expect("remember should succeed");

        let plaintext = b"fallback path test";
        let result = transport
            .send_to_destination(&dest_hash, plaintext, PacketContext::None)
            .await;

        assert!(result.is_ok(), "send_to_destination should succeed via known_destinations fallback");
    }

    #[tokio::test]
    async fn test_send_to_destination_unknown_returns_error() {
        // When no identity is known for the destination, send_to_destination
        // should return UnknownDestination error.
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let unknown_hash = AddressHash::new_from_slice(&[0xDDu8; 32]);
        let result = transport
            .send_to_destination(&unknown_hash, b"test", PacketContext::None)
            .await;

        assert!(result.is_err(), "should return error for unknown destination");
        assert_eq!(
            result.unwrap_err(),
            RnsError::UnknownDestination,
            "error should be UnknownDestination"
        );
    }

    #[tokio::test]
    async fn test_send_to_destination_roundtrip_decrypt() {
        // Verify the ciphertext produced by send_to_destination can be decrypted
        // by the corresponding SingleInputDestination (owner of the private key).
        use crate::destination::{DestinationName, SingleInputDestination, SingleOutputDestination};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        // Create identities: remote destination (sender targets this)
        let remote_priv = PrivateIdentity::new_from_rand(OsRng);
        let remote_pub = *remote_priv.as_identity();
        let name = DestinationName::new("test", "roundtrip").unwrap();

        // Build both output (for encrypting) and input (for decrypting) destinations
        let out_dest = SingleOutputDestination::new(remote_pub, name.clone());
        let in_dest = SingleInputDestination::new(remote_priv.clone(), name);
        let address_hash = out_dest.desc.address_hash;

        // Register the output destination so send_to_destination can find it
        transport
            .get_handler()
            .lock()
            .await
            .single_out_destinations
            .insert(address_hash, Arc::new(Mutex::new(out_dest)));

        // Send plaintext
        let plaintext = b"roundtrip crypto test";
        let _receipt = transport
            .send_to_destination(&address_hash, plaintext, PacketContext::None)
            .await
            .expect("send should succeed");

        // Retrieve the encrypted packet data from the receipt manager or packet cache.
        // Since we can't easily intercept the packet, we'll verify the roundtrip
        // by calling encrypt then decrypt directly with the same identity pair.
        let ciphertext = crate::destination::encrypt_single(
            OsRng,
            &remote_pub.public_key,
            remote_pub.address_hash.as_slice(),
            plaintext,
        )
        .expect("encrypt should succeed");

        let result = in_dest.decrypt(OsRng, &ciphertext, None, false);
        assert!(result.is_ok(), "decryption should succeed");
        assert_eq!(
            result.unwrap().plaintext,
            plaintext,
            "decrypted plaintext should match original"
        );
    }

    #[tokio::test]
    async fn test_announce_with_ratchet_stores_in_ratchet_manager() {
        // When a ratchet-bearing announce is processed via handle_announce,
        // the ratchet should be stored in the transport's ratchet_manager.
        use crate::destination::{DestinationName, SingleInputDestination};
        use crate::identity::ratchet_public_bytes;

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let dest = SingleInputDestination::new(
            identity.clone(),
            DestinationName::new("test", "ratchet").unwrap(),
        );

        // Generate a ratchet key pair and create a ratchet-bearing announce
        let ratchet_priv: [u8; RATCHET_KEY_SIZE] = {
            let mut key = [0u8; RATCHET_KEY_SIZE];
            OsRng.fill_bytes(&mut key);
            key
        };
        let ratchet_pub = ratchet_public_bytes(&ratchet_priv);

        let announce = dest
            .announce_with_ratchet(OsRng, &ratchet_pub, None)
            .expect("valid ratchet announce");

        // Verify context_flag is set (signals ratchet presence)
        assert!(announce.header.context_flag, "ratchet announce should have context_flag set");

        // Process the announce
        let iface = AddressHash::new_from_slice(&[0xFFu8; 32]);
        handle_announce(&announce, handler.lock().await, iface, false).await;

        // The ratchet should now be stored in the ratchet_manager
        let dest_hash: [u8; 16] = {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(announce.destination.as_slice());
            buf
        };
        let stored = handler.lock().await.ratchet_manager.get(&dest_hash);
        assert!(stored.is_some(), "ratchet should be stored after ratchet announce");
        assert_eq!(
            stored.unwrap().as_slice(),
            &ratchet_pub[..],
            "stored ratchet should match announced ratchet public key"
        );
    }

    #[tokio::test]
    async fn test_announce_without_ratchet_does_not_store_ratchet() {
        // When a normal announce (no ratchet) is processed, no ratchet should
        // be stored in the ratchet_manager.
        use crate::destination::{DestinationName, SingleInputDestination};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut dest = SingleInputDestination::new(
            identity.clone(),
            DestinationName::new("test", "noratchet").unwrap(),
        );
        let announce = dest.announce(OsRng, None).expect("valid announce");

        // context_flag should be false for a non-ratchet announce
        assert!(!announce.header.context_flag, "non-ratchet announce should not have context_flag");

        let iface = AddressHash::new_from_slice(&[0xFFu8; 32]);
        handle_announce(&announce, handler.lock().await, iface, false).await;

        let dest_hash: [u8; 16] = {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(announce.destination.as_slice());
            buf
        };
        let stored = handler.lock().await.ratchet_manager.get(&dest_hash);
        assert!(stored.is_none(), "no ratchet should be stored for non-ratchet announce");
    }

    #[tokio::test]
    async fn test_send_to_destination_uses_ratchet_via_single_out() {
        // When a ratchet is available, send_to_destination should encrypt
        // with the ratchet key and set the ratchet_id on the packet.
        use crate::destination::{DestinationName, SingleOutputDestination};
        use crate::identity::ratchet_public_bytes;

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        // Create remote identity and destination
        let remote_priv = PrivateIdentity::new_from_rand(OsRng);
        let remote_pub = *remote_priv.as_identity();
        let name = DestinationName::new("test", "ratchetsend").unwrap();
        let out_dest = SingleOutputDestination::new(remote_pub, name.clone());
        let address_hash = out_dest.desc.address_hash;

        // Store a ratchet for this destination
        let ratchet_priv: [u8; RATCHET_KEY_SIZE] = {
            let mut key = [0u8; RATCHET_KEY_SIZE];
            OsRng.fill_bytes(&mut key);
            key
        };
        let ratchet_pub = ratchet_public_bytes(&ratchet_priv);
        let dest_hash: [u8; 16] = {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(address_hash.as_slice());
            buf
        };
        handler
            .lock()
            .await
            .ratchet_manager
            .remember(&dest_hash, &ratchet_pub)
            .expect("remember ratchet should succeed");

        // Insert the output destination
        handler
            .lock()
            .await
            .single_out_destinations
            .insert(address_hash, Arc::new(Mutex::new(out_dest)));

        // Send — should use the ratchet key for encryption
        let plaintext = b"ratchet encrypted";
        let result = transport
            .send_to_destination(&address_hash, plaintext, PacketContext::None)
            .await;
        assert!(result.is_ok(), "send_to_destination with ratchet should succeed");

        // Verify the output destination has a ratchet_id set after encryption
        let dest_arc = handler
            .lock()
            .await
            .single_out_destinations
            .get(&address_hash)
            .unwrap()
            .clone();
        let dest_guard = dest_arc.lock().await;
        assert!(
            dest_guard.latest_ratchet_id.is_some(),
            "latest_ratchet_id should be set when ratchet is used"
        );
        let expected_rid = get_ratchet_id(&ratchet_pub);
        assert_eq!(
            dest_guard.latest_ratchet_id.unwrap(),
            expected_rid,
            "ratchet_id should match the stored ratchet"
        );
    }

    #[tokio::test]
    async fn test_send_to_destination_uses_ratchet_via_known_destinations() {
        // When a destination is only in known_destinations and a ratchet is stored,
        // send_to_destination should encrypt with the ratchet key.
        use crate::identity::ratchet_public_bytes;

        let tmp = std::env::temp_dir().join("reticulum_test_ratchet_known_dest");
        let _ = std::fs::create_dir_all(&tmp);

        let mut config: TransportConfig = Default::default();
        config.set_storage_path(tmp.clone());
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let remote_priv = PrivateIdentity::new_from_rand(OsRng);
        let pub_id = remote_priv.as_identity();
        let public_key_bytes = pub_id.to_bytes();

        // Use a synthetic destination hash
        let dest_hash_bytes = [0xCCu8; 16];
        let dest_hash = AddressHash::new(dest_hash_bytes);

        // Populate known_destinations only
        handler
            .lock()
            .await
            .known_destinations
            .remember(&dest_hash_bytes, &[], &public_key_bytes, None)
            .expect("remember should succeed");

        // Store a ratchet for this destination
        let ratchet_priv: [u8; RATCHET_KEY_SIZE] = {
            let mut key = [0u8; RATCHET_KEY_SIZE];
            OsRng.fill_bytes(&mut key);
            key
        };
        let ratchet_pub = ratchet_public_bytes(&ratchet_priv);
        handler
            .lock()
            .await
            .ratchet_manager
            .remember(&dest_hash_bytes, &ratchet_pub)
            .expect("remember ratchet should succeed");

        // Send — should use ratchet key for encryption via fallback path
        let plaintext = b"ratchet fallback";
        let result = transport
            .send_to_destination(&dest_hash, plaintext, PacketContext::None)
            .await;
        assert!(result.is_ok(), "send_to_destination should succeed via known_destinations with ratchet");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_ratchet_roundtrip_encrypt_decrypt() {
        // End-to-end: encrypt with ratchet public key → decrypt with ratchet
        // private key. Verifies the crypto primitives match Python's ratchet path.
        use crate::destination::{DestinationName, SingleInputDestination};
        use crate::identity::ratchet_public_bytes;

        let remote_priv = PrivateIdentity::new_from_rand(OsRng);
        let remote_pub = *remote_priv.as_identity();
        let name = DestinationName::new("test", "ratchetrt").unwrap();

        // Create ratchet key pair
        let ratchet_priv: [u8; RATCHET_KEY_SIZE] = {
            let mut key = [0u8; RATCHET_KEY_SIZE];
            OsRng.fill_bytes(&mut key);
            key
        };
        let ratchet_pub = ratchet_public_bytes(&ratchet_priv);

        // Encrypt with ratchet public key
        let salt = remote_pub.address_hash.as_slice();

        let plaintext = b"ratchet roundtrip test";
        let ciphertext = crate::destination::encrypt_single(
            OsRng,
            &x25519_dalek::PublicKey::from(ratchet_pub),
            salt,
            plaintext,
        )
        .expect("ratchet encrypt should succeed");

        // Build input destination and decrypt with the ratchet private key
        let in_dest = SingleInputDestination::new(remote_priv.clone(), name);
        let ratchets = vec![ratchet_priv.to_vec()];
        let result = in_dest.decrypt(OsRng, &ciphertext, Some(&ratchets), false);
        assert!(result.is_ok(), "decryption with ratchet key should succeed");

        let decrypted = result.unwrap();
        assert_eq!(decrypted.plaintext, plaintext, "plaintext should match");
        assert!(
            decrypted.ratchet_id.is_some(),
            "ratchet_id should be set when decrypted with ratchet"
        );
    }

    #[tokio::test]
    async fn test_storage_path_propagates_to_transport() {
        // Verify that setting storage_path on TransportConfig is used by
        // the TransportHandler's KnownDestinations and RatchetManager.
        let tmp = std::env::temp_dir().join("reticulum_test_storage_path");
        let _ = std::fs::create_dir_all(&tmp);

        let mut config: TransportConfig = Default::default();
        config.set_storage_path(tmp.clone());
        let transport = Transport::new(config);

        // The ratchet_manager should have its storage_dir based on our tmp path
        // We verify by remembering a ratchet and checking it persists at the right location
        let handler = transport.get_handler();
        let dest_hash = [0xEEu8; 16];
        let ratchet_bytes = [0x42u8; RATCHET_KEY_SIZE];
        handler
            .lock()
            .await
            .ratchet_manager
            .remember(&dest_hash, &ratchet_bytes)
            .expect("remember should succeed");

        let recalled = handler.lock().await.ratchet_manager.get(&dest_hash);
        assert!(recalled.is_some(), "ratchet should be recallable");
        assert_eq!(recalled.unwrap().as_slice(), &ratchet_bytes[..]);

        // Clean up
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // =========================================================================
    // Helper: create a handshaked (Active) link pair for out-link tests
    // =========================================================================

    /// Create an initiator link and a server link, complete the handshake, and
    /// return the (initiator_link, link_id). Both links will be in Active state
    /// with matching derived keys.
    fn create_active_link_pair() -> (LinkInner, LinkInner, AddressHash) {
        use crate::destination::link::LinkEventData;

        // Server destination identity
        let server_priv = PrivateIdentity::new_from_rand(OsRng);
        let server_pub = *server_priv.as_identity();
        let dest_desc = crate::destination::DestinationDesc {
            address_hash: server_pub.address_hash,
            identity: server_pub,
            name: crate::destination::DestinationName::new("test", "outlink").unwrap(),
        };

        let (tx1, _) = tokio::sync::broadcast::channel::<LinkEventData>(16);
        let (tx2, _) = tokio::sync::broadcast::channel::<LinkEventData>(16);

        // Initiator creates link and sends request
        let mut initiator = LinkInner::new(dest_desc.clone(), tx1);
        let request_packet = initiator.request();
        let link_id = *initiator.id();

        // Server creates link from request (using destination's signing key)
        let signing_key = server_priv.sign_key().clone();
        let mut server_link =
            LinkInner::new_from_request(&request_packet, signing_key, dest_desc.clone(), tx2)
                .expect("new_from_request should succeed");

        // Server proves the link (also activates server side)
        let mut proof_packet = server_link.prove();

        // Set the context that transport normally adds when routing
        proof_packet.context = PacketContext::LinkRequestProof;

        // Initiator handles proof → completes handshake and activates
        let result = initiator.handle_packet(&proof_packet);
        assert!(matches!(result, LinkResult::Activated));
        assert_eq!(initiator.status(), LinkStatus::Active);
        assert_eq!(server_link.status(), LinkStatus::Active);

        (initiator, server_link, link_id)
    }

    // =========================================================================
    // Tests for send_resource_request_out / send_resource_proof_out
    // =========================================================================

    #[tokio::test]
    async fn test_send_resource_request_out_active_link() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let (initiator, _server, link_id) = create_active_link_pair();

        // Insert initiator as an out-link
        transport
            .get_handler()
            .lock()
            .await
            .link_manager
            .insert_out_link(link_id, Arc::new(Mutex::new(initiator)));

        let result = transport
            .send_resource_request_out(&link_id, b"test request data")
            .await;
        assert!(result, "should succeed for an active out-link");
    }

    #[tokio::test]
    async fn test_send_resource_request_out_no_link() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let fake_id = AddressHash::new_from_slice(&[0xAAu8; 32]);
        let result = transport
            .send_resource_request_out(&fake_id, b"data")
            .await;
        assert!(!result, "should return false when out-link does not exist");
    }

    #[tokio::test]
    async fn test_send_resource_proof_out_active_link() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let (initiator, _server, link_id) = create_active_link_pair();

        transport
            .get_handler()
            .lock()
            .await
            .link_manager
            .insert_out_link(link_id, Arc::new(Mutex::new(initiator)));

        let result = transport
            .send_resource_proof_out(&link_id, b"proof data")
            .await;
        assert!(result, "should succeed for an active out-link");
    }

    #[tokio::test]
    async fn test_send_resource_proof_out_no_link() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let fake_id = AddressHash::new_from_slice(&[0xBBu8; 32]);
        let result = transport
            .send_resource_proof_out(&fake_id, b"data")
            .await;
        assert!(!result, "should return false when out-link does not exist");
    }

    #[tokio::test]
    async fn test_send_resource_request_out_closed_link() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let (mut initiator, _server, link_id) = create_active_link_pair();
        initiator.close();

        transport
            .get_handler()
            .lock()
            .await
            .link_manager
            .insert_out_link(link_id, Arc::new(Mutex::new(initiator)));

        let result = transport
            .send_resource_request_out(&link_id, b"data")
            .await;
        assert!(!result, "should return false when out-link is closed");
    }

    // =========================================================================
    // Tests for decrypt_with_out_link
    // =========================================================================

    #[tokio::test]
    async fn test_decrypt_with_out_link_roundtrip() {
        // Encrypt with the server link, decrypt via the initiator (out-link).
        // This matches the real use case: a remote server encrypts data on
        // its side of the link, and the local client decrypts via the out-link.
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let (initiator, server, link_id) = create_active_link_pair();

        // Server encrypts
        let plaintext = b"secret resource data";
        let mut enc_buf = vec![0u8; plaintext.len() + 256];
        let ciphertext = server
            .encrypt(plaintext, &mut enc_buf)
            .expect("server encrypt should succeed");
        let ciphertext = ciphertext.to_vec();

        // Insert initiator as out-link
        transport
            .get_handler()
            .lock()
            .await
            .link_manager
            .insert_out_link(link_id, Arc::new(Mutex::new(initiator)));

        // Decrypt via transport API
        let decrypted = transport
            .decrypt_with_out_link(&link_id, &ciphertext)
            .await
            .expect("decrypt_with_out_link should succeed");
        assert_eq!(decrypted, plaintext, "decrypted data should match original");
    }

    #[tokio::test]
    async fn test_decrypt_with_out_link_no_link() {
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let fake_id = AddressHash::new_from_slice(&[0xCCu8; 32]);
        let result = transport
            .decrypt_with_out_link(&fake_id, b"ciphertext")
            .await;
        assert!(result.is_err(), "should error when link does not exist");
        assert_eq!(result.unwrap_err(), RnsError::InvalidArgument);
    }

    #[tokio::test]
    async fn test_handle_proof_validates_explicit_proof() {
        // Exercises the non-link proof path in handle_proof, which previously
        // used blocking_lock() and would panic inside the tokio runtime.
        use crate::destination::{DestinationName, SingleOutputDestination};
        use crate::receipt::{generate_proof, PacketReceiptInner};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        // Create a remote identity and register its destination
        let remote_priv = PrivateIdentity::new_from_rand(OsRng);
        let remote_pub = *remote_priv.as_identity();
        let name = DestinationName::new("test", "proof").unwrap();
        let dest = SingleOutputDestination::new(remote_pub, name);
        let address_hash = dest.desc.address_hash;

        handler
            .lock()
            .await
            .single_out_destinations
            .insert(address_hash, Arc::new(Mutex::new(dest)));

        // Build a packet whose hash we can sign as a proof
        let mut original_packet: Packet = Default::default();
        original_packet.header.destination_type = DestinationType::Single;
        original_packet.header.packet_type = PacketType::Data;
        original_packet.destination = address_hash;
        original_packet.data = PacketDataBuffer::new_from_slice(b"test payload");
        let packet_hash = original_packet.hash().to_bytes();

        // Create receipt keyed by the packet's truncated hash, linked to the
        // destination so handle_proof can look up the identity for validation
        let dest_truncated: [u8; 16] = address_hash.as_slice()[..16].try_into().unwrap();
        let receipt = PacketReceiptInner::new_with_destination(packet_hash, dest_truncated, 0, None);
        let receipt_arc = handler.lock().await.receipt_manager.add(receipt).await;

        // Generate an explicit proof (hash + signature) signed by the remote identity
        let proof_data = generate_proof(&packet_hash, &remote_priv, true);

        // Build a proof packet matching the non-link path:
        // destination_type != Link, context != LinkRequestProof
        let mut proof_packet: Packet = Default::default();
        proof_packet.header.packet_type = PacketType::Proof;
        proof_packet.header.destination_type = DestinationType::Single;
        proof_packet.context = PacketContext::None;
        proof_packet.destination = address_hash;
        proof_packet.data = PacketDataBuffer::new_from_slice(&proof_data);

        // This would panic with "Cannot block the current thread from within
        // a runtime" before the blocking_lock() -> lock().await fix.
        handle_proof(&proof_packet, handler.lock().await).await;

        // Receipt should now be delivered
        let receipt_guard = receipt_arc.lock().await;
        assert!(
            receipt_guard.is_delivered(),
            "receipt should be marked Delivered after valid explicit proof"
        );
    }

    #[tokio::test]
    async fn test_handle_proof_validates_implicit_proof() {
        // Same code path as explicit, but with an implicit proof (signature only).
        // For implicit proofs, handle_proof looks up the receipt by
        // packet.destination (since the data doesn't contain the hash prefix),
        // so the proof packet's destination must equal the receipt's truncated
        // hash (first 16 bytes of the original packet hash).
        use crate::destination::{DestinationName, SingleOutputDestination};
        use crate::receipt::{generate_proof, PacketReceiptInner};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let remote_priv = PrivateIdentity::new_from_rand(OsRng);
        let remote_pub = *remote_priv.as_identity();
        let name = DestinationName::new("test", "implproof").unwrap();
        let dest = SingleOutputDestination::new(remote_pub, name);
        let address_hash = dest.desc.address_hash;

        handler
            .lock()
            .await
            .single_out_destinations
            .insert(address_hash, Arc::new(Mutex::new(dest)));

        let mut original_packet: Packet = Default::default();
        original_packet.header.destination_type = DestinationType::Single;
        original_packet.destination = address_hash;
        original_packet.data = PacketDataBuffer::new_from_slice(b"implicit test");
        let packet_hash = original_packet.hash().to_bytes();

        // Receipt stored by truncated packet hash, but destination_hash points
        // to the real destination so handle_proof can look up the identity
        let dest_truncated: [u8; 16] = address_hash.as_slice()[..16].try_into().unwrap();
        let receipt = PacketReceiptInner::new_with_destination(packet_hash, dest_truncated, 0, None);
        let receipt_arc = handler.lock().await.receipt_manager.add(receipt).await;

        // Implicit proof: signature only, no hash prefix
        let proof_data = generate_proof(&packet_hash, &remote_priv, false);

        // For implicit proofs, handle_proof uses packet.destination as the
        // receipt lookup key (since data.len() != EXPLICIT_PROOF_LENGTH).
        // Set destination to the receipt's truncated hash so the lookup works.
        let receipt_key: [u8; 16] = packet_hash[..16].try_into().unwrap();
        let mut proof_packet: Packet = Default::default();
        proof_packet.header.packet_type = PacketType::Proof;
        proof_packet.header.destination_type = DestinationType::Single;
        proof_packet.context = PacketContext::None;
        proof_packet.destination = AddressHash::new(receipt_key);
        proof_packet.data = PacketDataBuffer::new_from_slice(&proof_data);

        handle_proof(&proof_packet, handler.lock().await).await;

        let receipt_guard = receipt_arc.lock().await;
        assert!(
            receipt_guard.is_delivered(),
            "receipt should be marked Delivered after valid implicit proof"
        );
    }

    #[tokio::test]
    async fn test_handle_proof_unknown_destination_does_not_panic() {
        // Receipt exists but destination is not in single_out_destinations.
        // Should not panic or crash — receipt stays undelivered.
        use crate::receipt::{generate_proof, PacketReceiptInner};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let remote_priv = PrivateIdentity::new_from_rand(OsRng);
        let address_hash = AddressHash::new_from_slice(&[0xAAu8; 32]);

        let mut original_packet: Packet = Default::default();
        original_packet.header.destination_type = DestinationType::Single;
        original_packet.destination = address_hash;
        original_packet.data = PacketDataBuffer::new_from_slice(b"no dest");
        let packet_hash = original_packet.hash().to_bytes();

        let dest_truncated: [u8; 16] = address_hash.as_slice()[..16].try_into().unwrap();
        let receipt = PacketReceiptInner::new_with_destination(packet_hash, dest_truncated, 0, None);
        let receipt_arc = handler.lock().await.receipt_manager.add(receipt).await;

        let proof_data = generate_proof(&packet_hash, &remote_priv, true);

        let mut proof_packet: Packet = Default::default();
        proof_packet.header.packet_type = PacketType::Proof;
        proof_packet.header.destination_type = DestinationType::Single;
        proof_packet.context = PacketContext::None;
        proof_packet.destination = address_hash;
        proof_packet.data = PacketDataBuffer::new_from_slice(&proof_data);

        // No destination registered — should complete without panic
        handle_proof(&proof_packet, handler.lock().await).await;

        let receipt_guard = receipt_arc.lock().await;
        assert!(
            !receipt_guard.is_delivered(),
            "receipt should remain undelivered when destination is unknown"
        );
    }

    #[tokio::test]
    async fn test_handle_proof_wrong_identity_rejects() {
        // Proof is signed by a different identity than the destination's.
        // The proof should fail validation; receipt stays undelivered.
        use crate::destination::{DestinationName, SingleOutputDestination};
        use crate::receipt::{generate_proof, PacketReceiptInner};

        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);
        let handler = transport.get_handler();

        // Register destination with one identity
        let dest_priv = PrivateIdentity::new_from_rand(OsRng);
        let dest_pub = *dest_priv.as_identity();
        let name = DestinationName::new("test", "wrongid").unwrap();
        let dest = SingleOutputDestination::new(dest_pub, name);
        let address_hash = dest.desc.address_hash;

        handler
            .lock()
            .await
            .single_out_destinations
            .insert(address_hash, Arc::new(Mutex::new(dest)));

        let mut original_packet: Packet = Default::default();
        original_packet.header.destination_type = DestinationType::Single;
        original_packet.destination = address_hash;
        original_packet.data = PacketDataBuffer::new_from_slice(b"wrong signer");
        let packet_hash = original_packet.hash().to_bytes();

        let dest_truncated: [u8; 16] = address_hash.as_slice()[..16].try_into().unwrap();
        let receipt = PacketReceiptInner::new_with_destination(packet_hash, dest_truncated, 0, None);
        let receipt_arc = handler.lock().await.receipt_manager.add(receipt).await;

        // Sign with a DIFFERENT identity than the destination's
        let attacker_priv = PrivateIdentity::new_from_rand(OsRng);
        let proof_data = generate_proof(&packet_hash, &attacker_priv, true);

        let mut proof_packet: Packet = Default::default();
        proof_packet.header.packet_type = PacketType::Proof;
        proof_packet.header.destination_type = DestinationType::Single;
        proof_packet.context = PacketContext::None;
        proof_packet.destination = address_hash;
        proof_packet.data = PacketDataBuffer::new_from_slice(&proof_data);

        handle_proof(&proof_packet, handler.lock().await).await;

        let receipt_guard = receipt_arc.lock().await;
        assert!(
            !receipt_guard.is_delivered(),
            "receipt should not be delivered when proof is signed by wrong identity"
        );
    }

    #[tokio::test]
    async fn test_register_known_identity_makes_recall_work() {
        // register_known_identity should populate known_destinations so
        // that recall_identity returns the registered identity.
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let pub_id = identity.as_identity();
        let dest_hash_bytes = [0xBBu8; 16];
        let dest_hash = AddressHash::new(dest_hash_bytes);

        // Before registration, recall should return None.
        assert!(transport.recall_identity(&dest_hash).await.is_none());

        // Register and verify recall succeeds.
        transport
            .register_known_identity(&dest_hash_bytes, &pub_id)
            .await;

        let recalled = transport
            .recall_identity(&dest_hash)
            .await
            .expect("recall_identity should succeed after register_known_identity");

        assert_eq!(
            recalled.public_key.as_bytes(),
            pub_id.public_key.as_bytes(),
            "recalled public key should match"
        );
        assert_eq!(
            recalled.verifying_key.as_bytes(),
            pub_id.verifying_key.as_bytes(),
            "recalled verifying key should match"
        );
    }

    #[tokio::test]
    async fn test_register_known_identity_no_app_data() {
        // register_known_identity (no app_data variant) should not store
        // any app_data — recall_app_data should return None.
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let pub_id = identity.as_identity();
        let dest_hash_bytes = [0xCCu8; 16];
        let dest_hash = AddressHash::new(dest_hash_bytes);

        transport
            .register_known_identity(&dest_hash_bytes, &pub_id)
            .await;

        assert!(
            transport.recall_app_data(&dest_hash).await.is_none(),
            "recall_app_data should return None when registered without app_data"
        );
    }

    #[tokio::test]
    async fn test_register_known_identity_with_app_data() {
        // register_known_identity_with_app_data should store both the
        // identity and the app_data, making both recallable.
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let pub_id = identity.as_identity();
        let dest_hash_bytes = [0xDDu8; 16];
        let dest_hash = AddressHash::new(dest_hash_bytes);

        let app_data = b"propagation_node_data";
        transport
            .register_known_identity_with_app_data(
                &dest_hash_bytes,
                &pub_id,
                Some(app_data),
            )
            .await;

        // Identity should be recallable.
        let recalled = transport
            .recall_identity(&dest_hash)
            .await
            .expect("recall_identity should succeed");
        assert_eq!(
            recalled.public_key.as_bytes(),
            pub_id.public_key.as_bytes(),
        );

        // App data should be recallable.
        let recalled_app_data = transport
            .recall_app_data(&dest_hash)
            .await
            .expect("recall_app_data should return the stored app_data");
        assert_eq!(recalled_app_data, app_data);
    }

    #[tokio::test]
    async fn test_register_known_identity_overwrites_previous() {
        // A second registration for the same destination hash should
        // overwrite the previous identity and app_data.
        let config: TransportConfig = Default::default();
        let transport = Transport::new(config);

        let identity1 = PrivateIdentity::new_from_rand(OsRng);
        let identity2 = PrivateIdentity::new_from_rand(OsRng);
        let pub_id1 = identity1.as_identity();
        let pub_id2 = identity2.as_identity();
        let dest_hash_bytes = [0xEEu8; 16];
        let dest_hash = AddressHash::new(dest_hash_bytes);

        // Register first identity with app_data.
        transport
            .register_known_identity_with_app_data(
                &dest_hash_bytes,
                &pub_id1,
                Some(b"first"),
            )
            .await;

        // Overwrite with second identity and different app_data.
        transport
            .register_known_identity_with_app_data(
                &dest_hash_bytes,
                &pub_id2,
                Some(b"second"),
            )
            .await;

        let recalled = transport
            .recall_identity(&dest_hash)
            .await
            .expect("recall_identity should succeed");
        assert_eq!(
            recalled.public_key.as_bytes(),
            pub_id2.public_key.as_bytes(),
            "should recall the second (overwritten) identity"
        );

        let recalled_app_data = transport
            .recall_app_data(&dest_hash)
            .await
            .expect("recall_app_data should return overwritten data");
        assert_eq!(recalled_app_data, b"second");
    }

}
