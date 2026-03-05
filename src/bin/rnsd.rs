//! Reticulum Network Stack Daemon
//!
//! The main daemon process that manages the Reticulum network stack,
//! interfaces, and routing.

use std::fs;
use std::io::{Read, Write as IoWrite};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use rand_core::OsRng;
use reticulum::cli::hash::parse_identity_hash;
use reticulum::config::{LogLevel, ReticulumConfig, StoragePaths};
use reticulum::destination::request::AllowPolicy;
use reticulum::identity::PrivateIdentity;
use reticulum::stamper::Stamper;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::ipc::addr::ListenerAddr;
use reticulum::ipc::LocalServerInterface;
use reticulum::logging;
use reticulum::rpc::RpcServer;
use reticulum::transport::remote_management::RemoteManagementConfig;
use reticulum::transport::{Transport, TransportConfig};
use tokio_util::sync::CancellationToken;

/// Reticulum Network Stack Daemon
#[derive(Parser, Debug)]
#[command(name = "rnsd")]
#[command(author = "Reticulum Network Stack")]
#[command(version)]
#[command(about = "Reticulum Network Stack Daemon", long_about = None)]
struct Args {
    /// Path to configuration directory
    #[arg(short, long, value_name = "DIR")]
    config: Option<PathBuf>,

    /// Increase verbosity (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity
    #[arg(short, long)]
    quiet: bool,

    /// Run in service/background mode
    #[arg(short, long)]
    service: bool,

    /// Run in interactive mode
    #[arg(short, long)]
    interactive: bool,

    /// Print example configuration
    #[arg(long)]
    exampleconfig: bool,

    /// Enable remote management interface
    #[arg(long)]
    enable_remote_management: bool,

    /// Identity hashes allowed for remote management (can be repeated)
    #[arg(long = "remote-management-allowed", value_name = "HASH")]
    remote_management_allowed: Vec<String>,

    /// Enable publishing of blackhole list (public, no auth required)
    #[arg(long)]
    publish_blackhole: bool,
}

fn main() {
    let args = Args::parse();

    // Print example config if requested
    if args.exampleconfig {
        print_example_config();
        return;
    }

    // Determine log level from verbosity flags or use a default for initial logging
    let cli_log_level = if args.quiet {
        Some(LogLevel::Critical)
    } else if args.verbose > 0 {
        Some(match args.verbose {
            1 => LogLevel::Debug,
            _ => LogLevel::Verbose,
        })
    } else {
        None // Will use config file loglevel
    };

    // Initialize logging with default level for startup messages
    logging::init_with_level(cli_log_level.unwrap_or(LogLevel::Info));

    log::info!("Reticulum Network Stack Daemon starting...");

    // Load configuration
    let config = match ReticulumConfig::load(args.config.clone()) {
        Ok(cfg) => {
            log::info!("Loaded configuration from {:?}", cfg.paths.config_dir);
            cfg
        }
        Err(e) => {
            log::error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    // Update log level from config if no CLI override was specified
    let final_log_level = cli_log_level.unwrap_or(config.log_level);
    logging::init_with_level(final_log_level);
    log::debug!("Log level set to: {:?}", final_log_level);

    log::debug!("Configuration loaded: transport={}, share_instance={}",
        config.enable_transport, config.share_instance);

    // Set up shutdown handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // Run the daemon
    if args.interactive {
        log::info!("Running in interactive mode");
        run_interactive(&config, &args, running);
    } else {
        log::info!("Running in daemon mode");
        run_daemon(&config, &args, running);
    }

    log::info!("Reticulum Network Stack Daemon stopped");
}

/// Load or create the daemon identity.
///
/// Uses binary format (64 bytes) which is compatible with Python.
fn load_or_create_identity(paths: &StoragePaths) -> PrivateIdentity {
    let identity_file = paths.identity_path.join("daemon_identity");

    if identity_file.exists() {
        log::info!("Loading existing identity from {:?}", identity_file);
        match fs::File::open(&identity_file) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                if file.read_to_end(&mut bytes).is_ok() && bytes.len() == 64 {
                    if let Ok(identity) = PrivateIdentity::new_from_bytes(&bytes) {
                        let public = identity.as_identity();
                        log::info!("Identity loaded: {}", format_hash(public.address_hash.as_slice()));
                        return identity;
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to load identity: {}", e);
            }
        }
    }

    // Create new identity
    log::info!("Creating new daemon identity...");
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let public = identity.as_identity();
    log::info!("New identity created: {}", format_hash(public.address_hash.as_slice()));

    // Save identity in binary format (Python-compatible)
    if let Some(parent) = identity_file.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if let Ok(mut file) = fs::File::create(&identity_file) {
        let bytes = identity.to_bytes();
        let _ = file.write_all(&bytes);
        log::debug!("Identity saved to {:?}", identity_file);
    }

    identity
}

fn run_daemon(config: &ReticulumConfig, args: &Args, running: Arc<AtomicBool>) {
    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

    rt.block_on(async {
        // Load or create identity
        let identity = load_or_create_identity(&config.paths);

        // Create transport
        let transport = Transport::new(TransportConfig::new(
            "rnsd",
            &identity,
            config.enable_transport,
        ));
        let transport = Arc::new(transport);

        log::info!("Transport initialized");

        // Output full transport identity hash for scripting/testing purposes
        let transport_hash = hex::encode(identity.address_hash().as_slice());
        log::info!("TRANSPORT_HASH={}", transport_hash);

        // Create cancellation token for shutdown
        let cancel = CancellationToken::new();

        // Start remote management if enabled
        if args.enable_remote_management {
            let mgmt_config = create_remote_management_config(&args.remote_management_allowed);
            log::info!("Starting remote management service...");
            let dest_hash = transport.start_remote_management(
                &identity,
                mgmt_config,
                cancel.clone(),
            ).await;
            log::info!("Remote management destination: {}", format_hash(dest_hash.as_slice()));
            // Output full remote management destination hash for scripting/testing
            log::info!("REMOTE_MGMT_DEST={}", hex::encode(dest_hash.as_slice()));
        }

        // Start blackhole info publishing if enabled
        if args.publish_blackhole {
            log::info!("Starting blackhole info service...");
            let dest_hash = transport.start_blackhole_info_service(
                &identity,
                cancel.clone(),
            ).await;
            log::info!("Blackhole info destination: {}", format_hash(dest_hash.as_slice()));
            // Output full blackhole info destination hash for scripting/testing
            log::info!("BLACKHOLE_INFO_DEST={}", hex::encode(dest_hash.as_slice()));
        }

        // Start shared instance services if enabled
        if config.share_instance {
            log::info!("Shared instance enabled, starting IPC services...");

            // Get socket directory for filesystem sockets (macOS/BSD)
            let socket_dir = config.paths.config_dir.join("sockets");
            if let Err(e) = std::fs::create_dir_all(&socket_dir) {
                log::warn!("Failed to create socket directory: {}", e);
            }

            // Start LocalServerInterface for transport IPC
            let local_addr = ListenerAddr::default_transport(
                "default",
                &socket_dir,
                config.shared_instance_port,
            );
            log::info!("Starting LocalServerInterface on {}", local_addr.display());

            transport.spawn_interface(
                LocalServerInterface::new(local_addr, transport.iface_manager()),
                LocalServerInterface::spawn,
            ).await;

            // Start RPC server for management queries
            // Uses Python-compatible HMAC authentication and pickle serialization
            let rpc_addr = ListenerAddr::default_rpc(
                "default",
                &socket_dir,
                config.control_port,
            );
            log::info!("Starting RPC server on {}", rpc_addr.display());

            // Compute RPC authkey: use config value if present, otherwise derive from transport identity
            let rpc_key = config.rpc_key.clone().unwrap_or_else(|| {
                // Python uses: full_hash(transport_identity.get_private_key())
                // Transport identity is stored separately from daemon identity
                let transport_identity_file = config.paths.storage_path.join("transport_identity");
                if let Ok(bytes) = fs::read(&transport_identity_file) {
                    if bytes.len() == 64 {
                        log::debug!("Loaded transport identity from {:?}", transport_identity_file);
                        return Stamper::full_hash(&bytes).to_vec();
                    }
                }
                // Fallback to daemon identity if transport identity doesn't exist
                log::warn!("Transport identity not found, falling back to daemon identity for RPC key");
                let private_key_bytes = identity.to_bytes();
                Stamper::full_hash(&private_key_bytes).to_vec()
            });
            log::debug!("RPC key: {} ({})",
                hex::encode(&rpc_key[..8.min(rpc_key.len())]),
                if config.rpc_key.is_some() { "from config" } else { "derived from identity" }
            );

            let rpc_server = RpcServer::new(rpc_addr, transport.clone(), cancel.clone(), rpc_key);
            tokio::spawn(async move {
                rpc_server.run().await;
            });
        }

        // Start discovery handler for interface announcements
        log::info!("Starting interface discovery handler...");
        transport.start_discovery_handler(
            config.paths.storage_path.clone(),
            None, // Use default required stamp value (14)
            cancel.clone(),
        ).await;

        // Spawn interfaces from configuration
        let interface_configs = config.interface_configs();
        log::info!("Found {} interface configuration(s)", interface_configs.len());

        for iface_config in interface_configs {
            if !iface_config.enabled {
                log::debug!("Interface '{}' is disabled, skipping", iface_config.name);
                continue;
            }

            log::info!("Starting interface: {} (type: {})",
                iface_config.name, iface_config.interface_type);

            match iface_config.interface_type.as_str() {
                "TCPServerInterface" | "tcp_server" => {
                    let listen_ip = iface_config.listen_ip.as_deref().unwrap_or("0.0.0.0");
                    let listen_port = iface_config.listen_port.unwrap_or(4242);
                    let addr = format!("{}:{}", listen_ip, listen_port);

                    log::info!("  TCP Server listening on {}", addr);

                    transport.spawn_interface(
                        TcpServer::new(&addr, transport.iface_manager()),
                        TcpServer::spawn,
                    ).await;
                }
                "TCPClientInterface" | "tcp_client" => {
                    if let (Some(host), Some(port)) =
                        (&iface_config.target_host, iface_config.target_port)
                    {
                        let addr = format!("{}:{}", host, port);

                        log::info!("  TCP Client connecting to {}", addr);

                        transport.spawn_interface(
                            TcpClient::new(&addr),
                            TcpClient::spawn,
                        ).await;
                    } else {
                        log::warn!("  TCP Client '{}' missing target_host or target_port",
                            iface_config.name);
                    }
                }
                other => {
                    log::warn!("  Unknown interface type '{}' for '{}'",
                        other, iface_config.name);
                }
            }
        }

        log::info!("Daemon started, press Ctrl-C to stop");

        // Subscribe to incoming packets for logging
        let mut rx = transport.iface_rx();

        // Main loop
        loop {
            tokio::select! {
                // Check if shutdown requested
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                }
                // Handle incoming packets
                Ok(msg) = rx.recv() => {
                    log::debug!("Received packet: {} bytes from {}",
                        msg.packet.data.len(),
                        format_hash(msg.address.as_slice()));
                }
            }
        }

        log::info!("Shutting down transport...");
        cancel.cancel();
    });
}

fn run_interactive(config: &ReticulumConfig, _args: &Args, running: Arc<AtomicBool>) {
    println!("Reticulum Network Stack Daemon - Interactive Mode");
    println!("Type 'help' for available commands, 'quit' to exit");
    println!();

    // Start daemon in background
    let config_clone = config.clone();
    let running_clone = running.clone();

    let _daemon_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        rt.block_on(async {
            let identity = load_or_create_identity(&config_clone.paths);
            let transport = Transport::new(TransportConfig::new(
                "rnsd",
                &identity,
                config_clone.enable_transport,
            ));

            // Spawn interfaces
            for iface_config in config_clone.interface_configs() {
                if !iface_config.enabled {
                    continue;
                }
                match iface_config.interface_type.as_str() {
                    "TCPServerInterface" | "tcp_server" => {
                        let listen_ip = iface_config.listen_ip.as_deref().unwrap_or("0.0.0.0");
                        let listen_port = iface_config.listen_port.unwrap_or(4242);
                        let addr = format!("{}:{}", listen_ip, listen_port);
                        transport.spawn_interface(
                            TcpServer::new(&addr, transport.iface_manager()),
                            TcpServer::spawn,
                        ).await;
                    }
                    "TCPClientInterface" | "tcp_client" => {
                        if let (Some(host), Some(port)) =
                            (&iface_config.target_host, iface_config.target_port)
                        {
                            let addr = format!("{}:{}", host, port);
                            transport.spawn_interface(
                                TcpClient::new(&addr),
                                TcpClient::spawn,
                            ).await;
                        }
                    }
                    _ => {}
                }
            }

            while running_clone.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });
    });

    use std::io::{self, BufRead, Write as IoWriteTrait};

    while running.load(Ordering::SeqCst) {
        print!("rns> ");
        io::stdout().flush().unwrap();

        let stdin = io::stdin();
        let mut line = String::new();

        match stdin.lock().read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let cmd = line.trim();
                match cmd {
                    "help" | "?" => {
                        println!("Available commands:");
                        println!("  status    - Show network status");
                        println!("  paths     - Show path table");
                        println!("  ifaces    - Show interfaces");
                        println!("  quit      - Exit daemon");
                    }
                    "status" => {
                        println!("Status: Running");
                        println!("Interfaces: {}", config.interface_configs().len());
                        println!("Transport enabled: {}", config.enable_transport);
                    }
                    "paths" => {
                        println!("Path table is empty");
                    }
                    "ifaces" => {
                        let ifaces = config.interface_configs();
                        if ifaces.is_empty() {
                            println!("No interfaces configured");
                        } else {
                            for iface in ifaces {
                                let status = if iface.enabled { "enabled" } else { "disabled" };
                                println!("  {} ({}) - {}", iface.name, iface.interface_type, status);
                            }
                        }
                    }
                    "quit" | "exit" => {
                        running.store(false, Ordering::SeqCst);
                    }
                    "" => {}
                    _ => {
                        println!("Unknown command: {}", cmd);
                    }
                }
            }
            Err(e) => {
                log::error!("Error reading input: {}", e);
                break;
            }
        }
    }
}

fn format_hash(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2 + 2);
    hex.push('/');
    for byte in bytes.iter().take(8) {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex.push_str(".../");
    hex
}

/// Create remote management configuration from CLI arguments.
fn create_remote_management_config(allowed_hashes: &[String]) -> RemoteManagementConfig {
    if allowed_hashes.is_empty() {
        // If no allowed list specified, allow all identified peers
        log::info!("Remote management: allowing all identified peers");
        RemoteManagementConfig::allow_all()
    } else {
        // Parse hex strings to identity hashes
        let mut identities = Vec::new();
        for hash_str in allowed_hashes {
            match parse_identity_hash(hash_str) {
                Ok(hash) => {
                    log::info!("Remote management: allowing identity {}", hash_str);
                    identities.push(hash);
                }
                Err(e) => {
                    log::warn!("Invalid identity hash '{}': {}", hash_str, e);
                }
            }
        }
        if identities.is_empty() {
            log::warn!("No valid identity hashes, allowing all identified peers");
            RemoteManagementConfig::allow_all()
        } else {
            RemoteManagementConfig {
                enabled: true,
                allow_policy: AllowPolicy::AllowList(identities),
            }
        }
    }
}

fn print_example_config() {
    println!(r#"# Reticulum Network Stack Configuration
# This is an example configuration file

[reticulum]
# Enable transport mode (routing packets for other nodes)
enable_transport = false

# Share instances with other applications
share_instance = true

# Shared instance port
shared_instance_port = 37428

# Panic on unparseable interfaces
panic_on_interface_error = false

[logging]
loglevel = 4

[interfaces]

# Example TCP Server Interface
  [[TCP Server]]
    type = TCPServerInterface
    enabled = true
    listen_ip = 0.0.0.0
    listen_port = 4242

# Example TCP Client Interface
  [[TCP Client]]
    type = TCPClientInterface
    enabled = false
    target_host = 192.168.1.100
    target_port = 4242
"#);
}
