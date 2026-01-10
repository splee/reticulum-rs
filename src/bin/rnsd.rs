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
use reticulum::config::{LogLevel, ReticulumConfig, StoragePaths};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::logging;
use reticulum::transport::{Transport, TransportConfig};

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
}

fn main() {
    let args = Args::parse();

    // Print example config if requested
    if args.exampleconfig {
        print_example_config();
        return;
    }

    // Determine log level from verbosity flags
    let log_level = if args.quiet {
        LogLevel::Critical
    } else {
        match args.verbose {
            0 => LogLevel::Info,
            1 => LogLevel::Debug,
            _ => LogLevel::Verbose,
        }
    };

    // Initialize logging
    logging::init_with_level(log_level);

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
        run_interactive(&config, running);
    } else {
        log::info!("Running in daemon mode");
        run_daemon(&config, running);
    }

    log::info!("Reticulum Network Stack Daemon stopped");
}

/// Load or create the daemon identity
fn load_or_create_identity(paths: &StoragePaths) -> PrivateIdentity {
    let identity_file = paths.identity_path.join("daemon_identity");

    if identity_file.exists() {
        log::info!("Loading existing identity from {:?}", identity_file);
        match fs::File::open(&identity_file) {
            Ok(mut file) => {
                let mut contents = String::new();
                if file.read_to_string(&mut contents).is_ok() {
                    if let Ok(identity) = PrivateIdentity::new_from_hex_string(contents.trim()) {
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

    // Save identity
    if let Some(parent) = identity_file.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if let Ok(mut file) = fs::File::create(&identity_file) {
        let hex = identity.to_hex_string();
        let _ = file.write_all(hex.as_bytes());
        log::debug!("Identity saved to {:?}", identity_file);
    }

    identity
}

fn run_daemon(config: &ReticulumConfig, running: Arc<AtomicBool>) {
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

        log::info!("Transport initialized");

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

                        log::info!("  TCP Client connecting to {}", addr);

                        transport.iface_manager().lock().await.spawn(
                            TcpClient::new(&addr),
                            TcpClient::spawn,
                        );
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
    });
}

fn run_interactive(config: &ReticulumConfig, running: Arc<AtomicBool>) {
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
                            transport.iface_manager().lock().await.spawn(
                                TcpClient::new(&addr),
                                TcpClient::spawn,
                            );
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
    interface_enabled = true
    listen_ip = 0.0.0.0
    listen_port = 4242

# Example TCP Client Interface
  [[TCP Client]]
    type = TCPClientInterface
    interface_enabled = false
    target_host = 192.168.1.100
    target_port = 4242
"#);
}
