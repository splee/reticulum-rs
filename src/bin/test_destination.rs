//! Test helper: Create and announce a destination
//!
//! This binary creates a Reticulum destination and announces it periodically.
//! Used for integration testing to verify destination creation and announcements.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rand_core::OsRng;
use reticulum::config::ReticulumConfig;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::ipc::addr::ListenerAddr;
use reticulum::ipc::LocalClientInterface;
use reticulum::transport::{Transport, TransportConfig};

/// Test destination creator for integration testing
#[derive(Parser, Debug)]
#[command(name = "test_destination")]
#[command(about = "Create and announce a Reticulum destination for testing")]
struct Args {
    /// Application name for destination
    #[arg(short, long, default_value = "test_app")]
    app_name: String,

    /// Aspect for destination
    #[arg(short = 'A', long, default_value = "destination")]
    aspect: String,

    /// Identity name (seed for deterministic identity)
    #[arg(short = 'I', long)]
    identity_name: Option<String>,

    /// TCP server to listen on (e.g., "0.0.0.0:4243")
    #[arg(long)]
    tcp_server: Option<String>,

    /// TCP client to connect to (e.g., "python-hub:4242")
    #[arg(long)]
    tcp_client: Option<String>,

    /// Connect to shared rnsd instance via Unix socket (for local client testing)
    #[arg(long)]
    shared: bool,

    /// Announce interval in seconds
    #[arg(short = 'i', long, default_value = "30")]
    announce_interval: u64,

    /// Number of announces (0 for infinite)
    #[arg(short = 'n', long, default_value = "0")]
    announce_count: u32,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// App data to include in announce (as hex string)
    #[arg(long)]
    app_data: Option<String>,
}

fn main() {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    // Set up shutdown handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

    rt.block_on(async {
        // Create or load identity
        let identity = if let Some(name) = &args.identity_name {
            log::info!("Creating identity from name: {}", name);
            PrivateIdentity::new_from_name(name)
        } else {
            log::info!("Creating random identity");
            PrivateIdentity::new_from_rand(OsRng)
        };

        log::info!(
            "Identity address hash: {}",
            hex::encode(identity.as_identity().address_hash.as_slice())
        );

        // Create transport
        let mut transport = Transport::new(TransportConfig::new("test_dest", &identity, false));

        // Set up interfaces
        if args.shared {
            // Connect to shared rnsd instance via Unix socket
            log::info!("Connecting to shared rnsd instance via Unix socket");

            // Load config to get socket path
            let config = match ReticulumConfig::load(None) {
                Ok(cfg) => cfg,
                Err(e) => {
                    log::error!("Failed to load config: {}", e);
                    std::process::exit(1);
                }
            };

            let socket_dir = config.paths.config_dir.join("sockets");
            let local_addr = ListenerAddr::default_transport(
                "default",
                &socket_dir,
                config.shared_instance_port,
            );

            log::info!("Connecting to {}", local_addr.display());

            transport
                .iface_manager()
                .lock()
                .await
                .spawn(
                    LocalClientInterface::new(local_addr),
                    LocalClientInterface::spawn,
                );

            // Give LocalClientInterface time to connect
            tokio::time::sleep(Duration::from_millis(500)).await;
        } else {
            // Use TCP interfaces for standalone operation
            if let Some(server_addr) = &args.tcp_server {
                log::info!("Starting TCP server on {}", server_addr);
                transport
                    .iface_manager()
                    .lock()
                    .await
                    .spawn(
                        TcpServer::new(server_addr, transport.iface_manager()),
                        TcpServer::spawn,
                    );
            }

            if let Some(client_addr) = &args.tcp_client {
                log::info!("Connecting TCP client to {}", client_addr);
                transport
                    .iface_manager()
                    .lock()
                    .await
                    .spawn(TcpClient::new(client_addr), TcpClient::spawn);
            }

            // Give interfaces time to connect
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        // Create destination
        let dest_name = DestinationName::new(&args.app_name, &args.aspect);
        let destination = transport.add_destination(identity.clone(), dest_name).await;

        let dest_hash = destination.lock().await.desc.address_hash;

        // Output destination hash in a parseable format
        println!("DESTINATION_HASH={}", hex::encode(dest_hash.as_slice()));
        log::info!(
            "Created destination: {}.{} with hash {}",
            args.app_name,
            args.aspect,
            hex::encode(dest_hash.as_slice())
        );

        // Parse app data if provided
        let app_data_bytes = args.app_data.as_ref().and_then(|s| hex::decode(s).ok());
        let app_data_slice = app_data_bytes.as_deref();

        // Announce loop
        let mut announce_count = 0u32;
        let announce_interval = Duration::from_secs(args.announce_interval);

        log::info!("Starting announce loop (interval: {}s)", args.announce_interval);

        while running.load(Ordering::SeqCst) {
            // Send announce
            transport.send_announce(&destination, app_data_slice).await;
            announce_count += 1;

            println!("ANNOUNCE_SENT={}", announce_count);
            log::info!("Sent announce #{} for {}", announce_count, hex::encode(dest_hash.as_slice()));

            // Check if we've reached the announce limit
            if args.announce_count > 0 && announce_count >= args.announce_count {
                log::info!("Reached announce limit ({}), exiting", args.announce_count);
                break;
            }

            // Wait for next announce interval
            let mut remaining = announce_interval;
            while remaining > Duration::ZERO && running.load(Ordering::SeqCst) {
                let sleep_time = std::cmp::min(remaining, Duration::from_millis(100));
                tokio::time::sleep(sleep_time).await;
                remaining = remaining.saturating_sub(sleep_time);
            }
        }

        println!("STATUS=SHUTDOWN");
        log::info!("Destination test complete");
    });
}
