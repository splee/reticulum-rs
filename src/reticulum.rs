//! Top-level Reticulum Network Stack initialization.
//!
//! This module provides the [`Reticulum`] struct which handles complete initialization
//! of the Reticulum network stack, matching the Python `RNS.Reticulum` class behavior.
//!
//! # Overview
//!
//! The `Reticulum` struct serves as the main entry point for the Rust SDK. It handles:
//! - Configuration loading and directory creation
//! - Identity management (loading/creating transport identity)
//! - Shared instance negotiation (server → client → standalone fallback)
//! - Interface spawning from configuration
//! - RPC server setup (in shared instance mode)
//!
//! # Instance Modes
//!
//! Reticulum supports three operating modes:
//!
//! - **SharedInstance**: This instance owns the transport and interfaces. It acts as
//!   the daemon that other local programs connect to.
//! - **ConnectedToSharedInstance**: This instance connects to an existing daemon via IPC.
//!   Has a client-mode transport that relays packets through the daemon. Applications
//!   can use transport methods (add_destination, recv_announces, etc.) transparently.
//! - **Standalone**: This instance operates independently with full transport capabilities
//!   but no IPC. Used when `share_instance=false` in config or when negotiation fails.
//!
//! # Example
//!
//! ```no_run
//! use reticulum::reticulum::Reticulum;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize Reticulum with default settings
//!     let rns = Reticulum::builder().build().await?;
//!
//!     println!("Running in {:?} mode", rns.instance_mode());
//!
//!     // Keep running until Ctrl+C
//!     tokio::signal::ctrl_c().await?;
//!     rns.shutdown();
//!
//!     Ok(())
//! }
//! ```

use std::io::{Read, Write as IoWrite};
use std::path::PathBuf;
use std::sync::Arc;

use rand_core::OsRng;
use tokio_util::sync::CancellationToken;

use crate::config::{LogLevel, ReticulumConfig, StoragePaths};
use crate::identity::PrivateIdentity;
use crate::ipc::addr::{connect, IpcListener, ListenerAddr};
use crate::ipc::{LocalClientInterface, LocalServerInterface};
use crate::rpc::client::{RpcClient, RpcClientError};
use crate::rpc::protocol::{InterfaceStats, PathEntry};
use crate::rpc::RpcServer;
use crate::stamper::Stamper;
use crate::transport::{Transport, TransportConfig};

/// Instance mode indicating how this Reticulum instance is operating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceMode {
    /// This instance is the shared instance (owns interfaces and transport).
    /// Acts as the server that other local programs connect to.
    SharedInstance,

    /// This instance is connected to a shared instance via LocalClientInterface.
    /// Has a client-mode transport that relays packets through the shared instance.
    /// Applications can use transport methods (add_destination, recv_announces, etc.)
    /// which work by relaying through the daemon.
    ConnectedToSharedInstance,

    /// This instance operates standalone with full transport capabilities.
    /// Used when share_instance=false or when shared instance negotiation fails.
    Standalone,
}

/// Type of shared instance communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedInstanceType {
    /// Use TCP sockets (Windows default, or explicit config).
    Tcp,
    /// Use Unix domain sockets (Unix default).
    Unix,
}

/// Configuration for IPC socket binding and connections.
///
/// Used internally to configure the LocalServerInterface for shared instance
/// mode and IPC communication between daemon and clients.
#[derive(Debug, Clone)]
pub(crate) struct IpcConfig<'a> {
    /// Directory for filesystem Unix sockets (macOS/BSD).
    pub socket_dir: &'a std::path::Path,
    /// Port for LocalServerInterface (TCP fallback on Windows).
    pub local_interface_port: u16,
    /// Port for RPC server (TCP fallback on Windows).
    pub local_control_port: u16,
    /// Socket path identifier (e.g., "default" or custom instance name).
    pub socket_path: Option<&'a str>,
}

impl<'a> IpcConfig<'a> {
    /// Create a ListenerAddr for the transport IPC socket.
    pub fn transport_addr(&self) -> ListenerAddr {
        ListenerAddr::default_transport(
            self.socket_path.unwrap_or("default"),
            self.socket_dir,
            self.local_interface_port,
        )
    }

    /// Create a ListenerAddr for the RPC socket.
    pub fn rpc_addr(&self) -> ListenerAddr {
        ListenerAddr::default_rpc(
            self.socket_path.unwrap_or("default"),
            self.socket_dir,
            self.local_control_port,
        )
    }
}

/// Builder for configuring and creating a [`Reticulum`] instance.
///
/// The builder pattern allows flexible configuration before initialization,
/// matching the Python constructor parameters.
///
/// # Example
///
/// ```no_run
/// use reticulum::reticulum::Reticulum;
/// use reticulum::config::LogLevel;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let rns = Reticulum::builder()
///         .log_level(LogLevel::Debug)
///         .require_shared_instance(false)
///         .build()
///         .await?;
///     Ok(())
/// }
/// ```
pub struct ReticulumBuilder {
    /// Custom configuration directory (default: auto-discover).
    config_dir: Option<PathBuf>,

    /// Override log level (default: from config file).
    log_level: Option<LogLevel>,

    /// Verbosity adjustment to add to config log level.
    verbosity: Option<i8>,

    /// If true, initialization fails if no shared instance is available.
    /// Used by client applications that must connect to an existing daemon.
    require_shared_instance: bool,

    /// Force a specific shared instance type ("tcp" or "unix").
    shared_instance_type: Option<SharedInstanceType>,

    /// Custom cancellation token (default: creates new one).
    cancel_token: Option<CancellationToken>,

    /// Skip interface spawning (useful for testing or client-only mode).
    skip_interfaces: bool,
}

impl ReticulumBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            config_dir: None,
            log_level: None,
            verbosity: None,
            require_shared_instance: false,
            shared_instance_type: None,
            cancel_token: None,
            skip_interfaces: false,
        }
    }

    /// Set the configuration directory.
    ///
    /// If not set, searches for config in:
    /// 1. /etc/reticulum (if config file exists)
    /// 2. ~/.config/reticulum (if config file exists)
    /// 3. ~/.reticulum (default fallback)
    pub fn config_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config_dir = Some(dir.into());
        self
    }

    /// Override the log level from configuration.
    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.log_level = Some(level);
        self
    }

    /// Add verbosity adjustment to config log level.
    /// Positive values increase verbosity, negative decrease.
    pub fn verbosity(mut self, adjustment: i8) -> Self {
        self.verbosity = Some(adjustment);
        self
    }

    /// Require connection to an existing shared instance.
    ///
    /// If true and no shared instance is found, initialization fails
    /// with an error instead of falling back to standalone mode.
    pub fn require_shared_instance(mut self, require: bool) -> Self {
        self.require_shared_instance = require;
        self
    }

    /// Force a specific shared instance type.
    pub fn shared_instance_type(mut self, instance_type: SharedInstanceType) -> Self {
        self.shared_instance_type = Some(instance_type);
        self
    }

    /// Use a custom cancellation token for shutdown coordination.
    pub fn cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Skip spawning interfaces from configuration.
    /// Useful for testing or when only client mode is needed.
    pub fn skip_interfaces(mut self, skip: bool) -> Self {
        self.skip_interfaces = skip;
        self
    }

    /// Build and initialize the Reticulum instance.
    ///
    /// This performs the full initialization sequence:
    /// 1. Load configuration
    /// 2. Ensure directories exist
    /// 3. Load or create identity
    /// 4. Perform shared instance negotiation
    /// 5. Start transport and interfaces (if applicable)
    /// 6. Start RPC server (if shared instance)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Configuration cannot be loaded
    /// - `require_shared_instance` is true but no shared instance exists
    /// - Critical initialization steps fail
    pub async fn build(self) -> Result<Reticulum, ReticulumError> {
        Reticulum::initialize(self).await
    }
}

impl Default for ReticulumBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The main Reticulum network stack instance.
///
/// This struct provides a high-level API for initializing and interacting with
/// the Reticulum network. See module-level documentation for details.
pub struct Reticulum {
    /// Loaded configuration.
    config: ReticulumConfig,

    /// Transport identity (daemon/network identity).
    identity: PrivateIdentity,

    /// The current instance mode after negotiation.
    instance_mode: InstanceMode,

    /// Transport layer (Some only in SharedInstance or Standalone mode).
    transport: Option<Arc<Transport>>,

    /// RPC client for communicating with shared instance (Some only in ConnectedToSharedInstance mode).
    rpc_client: Option<RpcClient>,

    /// Cancellation token for graceful shutdown.
    cancel: CancellationToken,

    /// Port for local interface (IPC).
    local_interface_port: u16,

    /// Port for RPC control.
    local_control_port: u16,

    /// Socket path for Unix domain sockets (if using AF_UNIX).
    local_socket_path: Option<String>,
}

impl Reticulum {
    /// Create a builder for configuring a Reticulum instance.
    pub fn builder() -> ReticulumBuilder {
        ReticulumBuilder::new()
    }

    /// Internal initialization from builder settings.
    async fn initialize(builder: ReticulumBuilder) -> Result<Self, ReticulumError> {
        // Step 1: Load configuration
        let config =
            ReticulumConfig::load(builder.config_dir.clone()).map_err(ReticulumError::ConfigLoad)?;

        // Step 2: Apply log level (config value + verbosity adjustment)
        let mut log_level = builder.log_level.unwrap_or(config.log_level);
        if let Some(adjustment) = builder.verbosity {
            let level_num = log_level as i16 + adjustment as i16;
            let clamped = level_num.clamp(0, 7) as u8;
            log_level = LogLevel::from(clamped);
        }
        crate::logging::init_with_level(log_level);

        log::info!(
            "Reticulum initializing from {:?}",
            config.paths.config_dir
        );

        // Step 3: Load or create transport identity
        let identity = Self::load_or_create_identity(&config.paths)?;
        log::debug!("Transport identity: {}", identity.address_hash());

        // Step 4: Prepare instance parameters
        let local_interface_port = config.shared_instance_port;
        let local_control_port = config.control_port;
        let socket_dir = config.paths.config_dir.join("sockets");

        // Ensure socket directory exists
        std::fs::create_dir_all(&socket_dir).map_err(ReticulumError::Io)?;

        // Determine socket path (for Unix systems)
        let local_socket_path = Some("default".to_string());

        let cancel = builder.cancel_token.unwrap_or_default();

        // Step 5: Build IPC configuration
        let ipc_config = IpcConfig {
            socket_dir: &socket_dir,
            local_interface_port,
            local_control_port,
            socket_path: local_socket_path.as_deref(),
        };

        // Step 6: Shared instance negotiation
        let (instance_mode, transport, rpc_client) = if config.share_instance {
            Self::negotiate_shared_instance(
                &config,
                &identity,
                &ipc_config,
                builder.require_shared_instance,
                builder.skip_interfaces,
                cancel.clone(),
            )
            .await?
        } else {
            // share_instance = false: run standalone
            log::info!("Shared instance disabled, running standalone");
            let transport = Self::create_standalone_transport(
                &config,
                &identity,
                builder.skip_interfaces,
                cancel.clone(),
            )
            .await?;
            (InstanceMode::Standalone, Some(Arc::new(transport)), None)
        };

        log::info!("Reticulum initialized in {:?} mode", instance_mode);

        Ok(Self {
            config,
            identity,
            instance_mode,
            transport,
            rpc_client,
            cancel,
            local_interface_port,
            local_control_port,
            local_socket_path,
        })
    }

    /// Perform shared instance negotiation.
    ///
    /// Attempts to:
    /// 1. Bind as LocalServerInterface → becomes SharedInstance
    /// 2. If bind fails, connect as LocalClientInterface → becomes ConnectedToSharedInstance
    /// 3. If both fail and require_shared_instance is false → becomes Standalone
    /// 4. If both fail and require_shared_instance is true → returns error
    async fn negotiate_shared_instance(
        config: &ReticulumConfig,
        identity: &PrivateIdentity,
        ipc: &IpcConfig<'_>,
        require_shared_instance: bool,
        skip_interfaces: bool,
        cancel: CancellationToken,
    ) -> Result<(InstanceMode, Option<Arc<Transport>>, Option<RpcClient>), ReticulumError> {
        // Build the IPC address for LocalServerInterface
        let local_addr = ipc.transport_addr();

        // Try to bind as server (shared instance)
        match Self::try_bind_as_server(&local_addr).await {
            Ok(()) => {
                // We successfully bound - we are the shared instance
                if require_shared_instance {
                    // User wanted to connect to existing instance, but we became one
                    return Err(ReticulumError::SharedInstanceRequired(
                        "Started as shared instance but require_shared_instance was set".into(),
                    ));
                }

                log::info!("Started as shared instance on {}", local_addr.display());

                // Create full transport with interfaces
                let transport = Self::create_shared_instance_transport(
                    config,
                    identity,
                    ipc,
                    skip_interfaces,
                    cancel.clone(),
                )
                .await?;

                Ok((InstanceMode::SharedInstance, Some(transport), None))
            }
            Err(bind_error) => {
                // Bind failed - try to connect as client
                log::debug!(
                    "Could not bind as server: {}, trying client mode",
                    bind_error
                );

                match Self::try_connect_as_client(&local_addr).await {
                    Ok(()) => {
                        // Connected to existing shared instance
                        log::info!(
                            "Connected to shared instance on {}",
                            local_addr.display()
                        );

                        // Create client-mode transport with LocalClientInterface
                        // This allows applications to use transport methods (add_destination,
                        // recv_announces, etc.) that relay through the daemon.
                        let transport =
                            Self::create_client_mode_transport(identity, local_addr.clone()).await;

                        // Build RPC client for management queries (status, paths, etc.)
                        let rpc_addr = ipc.rpc_addr();

                        // Derive RPC key from identity (matches Python behavior)
                        let rpc_key = config
                            .rpc_key
                            .clone()
                            .unwrap_or_else(|| Stamper::full_hash(&identity.to_bytes()).to_vec());

                        let rpc_client = RpcClient::new(rpc_addr, rpc_key);

                        Ok((
                            InstanceMode::ConnectedToSharedInstance,
                            Some(transport),
                            Some(rpc_client),
                        ))
                    }
                    Err(connect_error) => {
                        // Both bind and connect failed
                        if require_shared_instance {
                            Err(ReticulumError::SharedInstanceRequired(format!(
                                "Could not bind ({}) or connect ({})",
                                bind_error, connect_error
                            )))
                        } else {
                            // Fallback to standalone
                            log::warn!("Shared instance negotiation failed, running standalone");
                            let transport = Self::create_standalone_transport(
                                config,
                                identity,
                                skip_interfaces,
                                cancel.clone(),
                            )
                            .await?;
                            Ok((InstanceMode::Standalone, Some(Arc::new(transport)), None))
                        }
                    }
                }
            }
        }
    }

    /// Try to bind as LocalServerInterface.
    async fn try_bind_as_server(addr: &ListenerAddr) -> Result<(), std::io::Error> {
        // Attempt to bind - this will fail if another instance is already listening
        let listener = IpcListener::bind(addr).await?;
        // Drop the listener immediately - we just wanted to test if we could bind
        // The actual LocalServerInterface will be spawned later
        drop(listener);
        Ok(())
    }

    /// Try to connect as LocalClientInterface.
    async fn try_connect_as_client(addr: &ListenerAddr) -> Result<(), std::io::Error> {
        // Try to connect to test if server is running
        let stream = connect(addr).await?;
        drop(stream);
        Ok(())
    }

    /// Create transport for shared instance mode.
    async fn create_shared_instance_transport(
        config: &ReticulumConfig,
        identity: &PrivateIdentity,
        ipc: &IpcConfig<'_>,
        skip_interfaces: bool,
        cancel: CancellationToken,
    ) -> Result<Arc<Transport>, ReticulumError> {
        let mut tc = TransportConfig::new("reticulum", identity, config.enable_transport);
        tc.set_use_implicit_proof(config.use_implicit_proof);
        let transport = Transport::new(tc);
        let transport_arc = Arc::new(transport);

        // Start LocalServerInterface for IPC
        let local_addr = ipc.transport_addr();

        {
            let iface_manager_arc = transport_arc.iface_manager();
            let mut iface_manager = iface_manager_arc.lock().await;
            iface_manager.spawn(
                LocalServerInterface::new(local_addr, transport_arc.iface_manager()),
                LocalServerInterface::spawn,
            );
        }

        // Start RPC server
        let rpc_addr = ipc.rpc_addr();

        // Derive RPC key from transport identity (matches Python behavior)
        let rpc_key = config
            .rpc_key
            .clone()
            .unwrap_or_else(|| Stamper::full_hash(&identity.to_bytes()).to_vec());

        let rpc_server = RpcServer::new(rpc_addr, transport_arc.clone(), cancel.clone(), rpc_key);
        tokio::spawn(async move {
            rpc_server.run().await;
        });

        // Spawn configured interfaces
        if !skip_interfaces {
            Self::spawn_interfaces_from_config(config, &transport_arc).await;
        }

        Ok(transport_arc)
    }

    /// Create transport for standalone mode.
    async fn create_standalone_transport(
        config: &ReticulumConfig,
        identity: &PrivateIdentity,
        skip_interfaces: bool,
        _cancel: CancellationToken,
    ) -> Result<Transport, ReticulumError> {
        let mut tc = TransportConfig::new("reticulum", identity, config.enable_transport);
        tc.set_use_implicit_proof(config.use_implicit_proof);
        let transport = Transport::new(tc);

        if !skip_interfaces {
            let transport_arc = Arc::new(transport);
            Self::spawn_interfaces_from_config(config, &transport_arc).await;

            // We need to get the transport back from the Arc
            // Since we just created it and only hold one reference, this should work
            match Arc::try_unwrap(transport_arc) {
                Ok(t) => Ok(t),
                Err(_) => panic!("Transport Arc should have single owner after interface spawn"),
            }
        } else {
            Ok(transport)
        }
    }

    /// Create transport for client mode (connected to a shared instance).
    ///
    /// In client mode, we create a Transport with LocalClientInterface as the only interface.
    /// The LocalClientInterface relays packets to/from the daemon. This matches Python's
    /// architecture where clients still have a Transport that processes packets locally
    /// but relays them through the daemon for network I/O.
    async fn create_client_mode_transport(
        identity: &PrivateIdentity,
        local_addr: ListenerAddr,
    ) -> Arc<Transport> {
        // Create transport in client mode (no announce retransmission)
        let transport = Transport::new(TransportConfig::new_client_mode("reticulum-client", identity));
        let transport_arc = Arc::new(transport);

        // Spawn LocalClientInterface to relay packets to/from daemon
        {
            let iface_manager_arc = transport_arc.iface_manager();
            let mut iface_manager = iface_manager_arc.lock().await;
            iface_manager.spawn(
                LocalClientInterface::new(local_addr),
                LocalClientInterface::spawn,
            );
        }

        transport_arc
    }

    /// Spawn interfaces from configuration.
    async fn spawn_interfaces_from_config(config: &ReticulumConfig, transport: &Arc<Transport>) {
        use crate::iface::tcp_client::TcpClient;
        use crate::iface::tcp_server::TcpServer;

        for iface_config in config.interface_configs() {
            if !iface_config.enabled {
                log::debug!(
                    "Interface '{}' is disabled, skipping",
                    iface_config.name
                );
                continue;
            }

            log::info!(
                "Starting interface: {} ({})",
                iface_config.name,
                iface_config.interface_type
            );

            match iface_config.interface_type.as_str() {
                "TCPServerInterface" | "tcp_server" => {
                    let listen_ip = iface_config.listen_ip.as_deref().unwrap_or("0.0.0.0");
                    let listen_port = iface_config.listen_port.unwrap_or(4242);
                    let addr = format!("{}:{}", listen_ip, listen_port);

                    transport.iface_manager().lock().await.spawn(
                        TcpServer::new(&addr, transport.iface_manager()),
                        TcpServer::spawn,
                    );
                }
                "TCPClientInterface" | "tcp_client" => {
                    if let (Some(host), Some(port)) =
                        (&iface_config.target_host, iface_config.target_port)
                    {
                        let addr = format!("{}:{}", host, port);
                        transport
                            .iface_manager()
                            .lock()
                            .await
                            .spawn(TcpClient::new(&addr), TcpClient::spawn);
                    } else {
                        log::warn!(
                            "TCPClientInterface '{}' missing target_host or target_port",
                            iface_config.name
                        );
                    }
                }
                other => {
                    log::warn!("Unknown interface type: {}", other);
                }
            }
        }
    }

    /// Load or create the transport identity.
    fn load_or_create_identity(paths: &StoragePaths) -> Result<PrivateIdentity, ReticulumError> {
        let identity_file = paths.identity_path.join("transport_identity");

        if identity_file.exists() {
            let mut file = std::fs::File::open(&identity_file).map_err(ReticulumError::Io)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(ReticulumError::Io)?;

            if bytes.len() == 64 {
                if let Ok(identity) = PrivateIdentity::new_from_bytes(&bytes) {
                    log::info!("Loaded transport identity from {:?}", identity_file);
                    return Ok(identity);
                }
            }
            log::warn!(
                "Identity file exists but is invalid, creating new identity"
            );
        }

        // Create new identity
        log::info!("Creating new transport identity...");
        let identity = PrivateIdentity::new_from_rand(OsRng);

        // Save identity
        if let Some(parent) = identity_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match std::fs::File::create(&identity_file) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(&identity.to_bytes()) {
                    log::warn!("Failed to save transport identity: {}", e);
                } else {
                    log::debug!("Transport identity saved to {:?}", identity_file);
                }
            }
            Err(e) => {
                log::warn!("Failed to create identity file: {}", e);
            }
        }

        Ok(identity)
    }

    // =========================================================================
    // Instance Mode Detection
    // =========================================================================

    /// Returns the current instance mode.
    pub fn instance_mode(&self) -> InstanceMode {
        self.instance_mode
    }

    /// Returns true if this is the shared instance (server mode).
    pub fn is_shared_instance(&self) -> bool {
        self.instance_mode == InstanceMode::SharedInstance
    }

    /// Returns true if connected to a shared instance (client mode).
    pub fn is_connected_to_shared_instance(&self) -> bool {
        self.instance_mode == InstanceMode::ConnectedToSharedInstance
    }

    /// Returns true if running standalone (no IPC).
    pub fn is_standalone_instance(&self) -> bool {
        self.instance_mode == InstanceMode::Standalone
    }

    // =========================================================================
    // Transport Access
    // =========================================================================

    /// Returns a reference to the transport layer.
    ///
    /// Transport is available in all modes:
    /// - SharedInstance/Standalone: Full transport with network interfaces
    /// - ConnectedToSharedInstance: Client-mode transport with LocalClientInterface
    ///   that relays packets to/from the daemon
    pub fn transport(&self) -> &Transport {
        self.transport
            .as_ref()
            .expect("Transport should always be available")
    }

    /// Returns the transport if available.
    ///
    /// This method is provided for compatibility but will always return Some
    /// since transport is available in all modes.
    pub fn transport_opt(&self) -> Option<&Transport> {
        self.transport.as_ref().map(|arc| arc.as_ref())
    }

    /// Returns true if transport is enabled (for routing).
    pub fn transport_enabled(&self) -> bool {
        self.config.enable_transport
    }

    // =========================================================================
    // Configuration Access
    // =========================================================================

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &ReticulumConfig {
        &self.config
    }

    /// Returns the storage paths.
    pub fn paths(&self) -> &StoragePaths {
        &self.config.paths
    }

    /// Returns the transport identity.
    pub fn identity(&self) -> &PrivateIdentity {
        &self.identity
    }

    /// Returns the local interface port.
    pub fn local_interface_port(&self) -> u16 {
        self.local_interface_port
    }

    /// Returns the local control port.
    pub fn local_control_port(&self) -> u16 {
        self.local_control_port
    }

    /// Returns the local socket path (if using Unix sockets).
    pub fn local_socket_path(&self) -> Option<&str> {
        self.local_socket_path.as_deref()
    }

    // =========================================================================
    // Network Status Queries (works in all modes)
    // =========================================================================

    /// Get interface statistics.
    ///
    /// In shared instance or standalone mode, queries local transport.
    /// In client mode, queries via RPC.
    pub async fn get_interface_stats(&self) -> Result<Vec<InterfaceStats>, ReticulumError> {
        match self.instance_mode {
            InstanceMode::ConnectedToSharedInstance => {
                let client = self.rpc_client.as_ref().unwrap();
                client.get_interface_stats().await.map_err(ReticulumError::Rpc)
            }
            _ => {
                let stats = self.transport().get_interface_stats().await;
                // Convert internal stats to RPC format (matching server.rs)
                Ok(stats
                    .into_iter()
                    .map(|s| InterfaceStats {
                        name: s.name,
                        interface_type: s.interface_type,
                        online: s.online,
                        rx_packets: 0, // TODO: Add packet counting if needed
                        tx_packets: 0,
                        rx_bytes: s.rx_bytes,
                        tx_bytes: s.tx_bytes,
                        bitrate: s.bitrate,
                        address: s.endpoint_address,
                    })
                    .collect())
            }
        }
    }

    /// Get the path table.
    ///
    /// In shared instance or standalone mode, queries local transport.
    /// In client mode, queries via RPC.
    pub async fn get_path_table(
        &self,
        max_hops: Option<u8>,
    ) -> Result<Vec<PathEntry>, ReticulumError> {
        match self.instance_mode {
            InstanceMode::ConnectedToSharedInstance => {
                let client = self.rpc_client.as_ref().unwrap();
                client
                    .get_path_table(max_hops.map(|h| h as u32))
                    .await
                    .map_err(ReticulumError::Rpc)
            }
            _ => {
                let paths = self.transport().get_path_table(max_hops).await;
                // Convert internal path entries to RPC format
                Ok(paths
                    .into_iter()
                    .map(|p| PathEntry {
                        destination_hash: p.destination,
                        hops: p.hops as u32,
                        interface: p.interface_hash,
                        via: if p.next_hop.is_empty() {
                            None
                        } else {
                            Some(p.next_hop)
                        },
                        expires: p.expires.unwrap_or(0.0),
                    })
                    .collect())
            }
        }
    }

    /// Get the number of active links.
    pub async fn get_link_count(&self) -> Result<u64, ReticulumError> {
        match self.instance_mode {
            InstanceMode::ConnectedToSharedInstance => {
                let client = self.rpc_client.as_ref().unwrap();
                client.get_link_count().await.map_err(ReticulumError::Rpc)
            }
            _ => {
                // TODO: Link counting not yet fully implemented in Transport
                // This matches the placeholder in rpc/server.rs
                Ok(0)
            }
        }
    }

    // =========================================================================
    // Shutdown
    // =========================================================================

    /// Initiate graceful shutdown.
    pub fn shutdown(&self) {
        log::info!("Reticulum shutting down...");
        self.cancel.cancel();
    }

    /// Returns the cancellation token for coordinating shutdown.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }
}

/// Errors that can occur during Reticulum initialization or operation.
#[derive(Debug)]
pub enum ReticulumError {
    /// Failed to load configuration.
    ConfigLoad(std::io::Error),

    /// I/O error.
    Io(std::io::Error),

    /// Shared instance was required but not available.
    SharedInstanceRequired(String),

    /// RPC communication error (in client mode).
    Rpc(RpcClientError),

    /// Identity error.
    Identity(String),

    /// Transport error.
    Transport(String),
}

impl std::fmt::Display for ReticulumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigLoad(e) => write!(f, "Failed to load configuration: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::SharedInstanceRequired(msg) => {
                write!(f, "Shared instance required but not available: {}", msg)
            }
            Self::Rpc(e) => write!(f, "RPC error: {}", e),
            Self::Identity(msg) => write!(f, "Identity error: {}", msg),
            Self::Transport(msg) => write!(f, "Transport error: {}", msg),
        }
    }
}

impl std::error::Error for ReticulumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConfigLoad(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Rpc(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = ReticulumBuilder::new();
        assert!(builder.config_dir.is_none());
        assert!(builder.log_level.is_none());
        assert!(!builder.require_shared_instance);
        assert!(!builder.skip_interfaces);
    }

    #[test]
    fn test_builder_configuration() {
        let builder = ReticulumBuilder::new()
            .config_dir("/tmp/test")
            .log_level(LogLevel::Debug)
            .verbosity(2)
            .require_shared_instance(true)
            .skip_interfaces(true);

        assert_eq!(builder.config_dir, Some(PathBuf::from("/tmp/test")));
        assert_eq!(builder.log_level, Some(LogLevel::Debug));
        assert_eq!(builder.verbosity, Some(2));
        assert!(builder.require_shared_instance);
        assert!(builder.skip_interfaces);
    }

    #[test]
    fn test_instance_mode_equality() {
        assert_eq!(InstanceMode::SharedInstance, InstanceMode::SharedInstance);
        assert_ne!(InstanceMode::SharedInstance, InstanceMode::Standalone);
        assert_ne!(
            InstanceMode::ConnectedToSharedInstance,
            InstanceMode::Standalone
        );
    }

    #[test]
    fn test_error_display() {
        let err = ReticulumError::SharedInstanceRequired("test".to_string());
        assert!(err.to_string().contains("test"));

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = ReticulumError::Io(io_err);
        assert!(err.to_string().contains("I/O error"));
    }
}
