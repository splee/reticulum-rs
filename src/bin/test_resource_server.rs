//! Test helper: Resource server that accepts incoming links and logs resource events
//!
//! This binary creates a destination, announces it, and listens for incoming links.
//! When resource advertisements are received, it logs them but doesn't complete the transfer.
//! This tests the resource event infrastructure.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rand_core::OsRng;
use reticulum::destination::link::{LinkEvent, LinkEventData};
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::resource::ResourceAdvertisement;
use reticulum::transport::{Transport, TransportConfig};

/// Test resource server for integration testing
#[derive(Parser, Debug)]
#[command(name = "test_resource_server")]
#[command(about = "Listen for incoming Reticulum resources for testing")]
struct Args {
    /// Application name for destination
    #[arg(short, long, default_value = "test_app")]
    app_name: String,

    /// Aspect for destination
    #[arg(short = 'A', long, default_value = "resourceserver")]
    aspect: String,

    /// Identity name (seed for deterministic identity)
    #[arg(short, long)]
    identity_name: Option<String>,

    /// TCP server to listen on (e.g., "0.0.0.0:4243")
    #[arg(long)]
    tcp_server: Option<String>,

    /// TCP client to connect to (e.g., "python-hub:4242")
    #[arg(long)]
    tcp_client: Option<String>,

    /// Announce interval in seconds
    #[arg(short = 'i', long, default_value = "30")]
    announce_interval: u64,

    /// Expected number of resources before exit (0 for infinite)
    #[arg(short = 'n', long, default_value = "0")]
    resource_count: u32,

    /// Timeout in seconds (0 for no timeout)
    #[arg(short = 't', long, default_value = "0")]
    timeout: u64,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
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
        let mut transport = Transport::new(TransportConfig::new("resource_server", &identity, false));

        // Set up interfaces
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

        // Send initial announce
        transport.send_announce(&destination, None).await;
        println!("ANNOUNCE_SENT=1");
        log::info!("Sent initial announce");

        // Subscribe to incoming link events
        let mut link_events = transport.in_link_events();

        // Track resources and links
        let mut link_count = 0u32;
        let mut resource_adv_count = 0u32;

        // Set up timeout if specified
        let timeout = if args.timeout > 0 {
            Some(tokio::time::Instant::now() + Duration::from_secs(args.timeout))
        } else {
            None
        };

        // Set up announce interval
        let announce_interval = Duration::from_secs(args.announce_interval);
        let mut next_announce = tokio::time::Instant::now() + announce_interval;
        let mut announce_num = 1u32;

        log::info!("Waiting for incoming links and resources...");

        while running.load(Ordering::SeqCst) {
            // Check timeout
            if let Some(deadline) = timeout {
                if tokio::time::Instant::now() >= deadline {
                    log::info!("Timeout reached, exiting");
                    println!("STATUS=TIMEOUT");
                    break;
                }
            }

            // Check if we've reached resource limit
            if args.resource_count > 0 && resource_adv_count >= args.resource_count {
                log::info!("Reached resource limit ({}), exiting", args.resource_count);
                println!("STATUS=RESOURCE_LIMIT_REACHED");
                break;
            }

            tokio::select! {
                // Handle link events
                Ok(event) = link_events.recv() => {
                    handle_link_event(
                        &event,
                        &mut link_count,
                        &mut resource_adv_count,
                    );
                }
                // Send periodic announces
                _ = tokio::time::sleep_until(next_announce) => {
                    if running.load(Ordering::SeqCst) {
                        announce_num += 1;
                        transport.send_announce(&destination, None).await;
                        println!("ANNOUNCE_SENT={}", announce_num);
                        log::info!("Sent announce #{}", announce_num);
                        next_announce = tokio::time::Instant::now() + announce_interval;
                    }
                }
                // Check for shutdown
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Just checking running flag
                }
            }
        }

        println!("TOTAL_LINKS={}", link_count);
        println!("TOTAL_RESOURCE_ADVERTISEMENTS={}", resource_adv_count);
        println!("STATUS=SHUTDOWN");
        log::info!(
            "Resource server complete: {} links, {} resource advertisements",
            link_count,
            resource_adv_count
        );
    });
}

fn handle_link_event(
    event: &LinkEventData,
    link_count: &mut u32,
    resource_adv_count: &mut u32,
) {
    let link_id_hex = hex::encode(event.id.as_slice());

    match &event.event {
        LinkEvent::Activated => {
            *link_count += 1;
            println!("LINK_ACTIVATED={}", link_id_hex);
            log::info!("Link {} activated (total: {})", link_id_hex, link_count);
        }
        LinkEvent::Data(payload) => {
            log::debug!("Link {}: data {} bytes", link_id_hex, payload.len());
            println!(
                "DATA_RECEIVED={}:{}:{}",
                link_id_hex,
                payload.len(),
                hex::encode(payload.as_slice())
            );
        }
        LinkEvent::ResourceAdvertisement(payload) => {
            *resource_adv_count += 1;
            log::info!(
                "Link {}: resource advertisement {} bytes",
                link_id_hex,
                payload.len()
            );

            // Try to parse the advertisement
            match ResourceAdvertisement::unpack(payload.as_slice()) {
                Ok(adv) => {
                    println!(
                        "RESOURCE_ADVERTISEMENT={}:{}:{}:{}:{}",
                        link_id_hex,
                        hex::encode(&adv.hash),
                        adv.data_size,
                        adv.transfer_size,
                        adv.num_parts
                    );
                    log::info!(
                        "Resource: hash={}, size={}, parts={}",
                        hex::encode(&adv.hash[..8]),
                        adv.data_size,
                        adv.num_parts
                    );
                }
                Err(e) => {
                    println!(
                        "RESOURCE_ADVERTISEMENT_PARSE_ERROR={}:{}:{:?}",
                        link_id_hex,
                        hex::encode(payload.as_slice()),
                        e
                    );
                    log::error!("Failed to parse resource advertisement: {:?}", e);
                }
            }
        }
        LinkEvent::ResourceData(payload) => {
            log::debug!(
                "Link {}: resource data {} bytes",
                link_id_hex,
                payload.len()
            );
            println!(
                "RESOURCE_DATA={}:{}",
                link_id_hex,
                payload.len()
            );
        }
        LinkEvent::ResourceRequest(payload) => {
            log::debug!(
                "Link {}: resource request {} bytes",
                link_id_hex,
                payload.len()
            );
            println!(
                "RESOURCE_REQUEST={}:{}",
                link_id_hex,
                payload.len()
            );
        }
        LinkEvent::ResourceHashmapUpdate(payload) => {
            log::debug!(
                "Link {}: resource hashmap update {} bytes",
                link_id_hex,
                payload.len()
            );
        }
        LinkEvent::ResourceProof(payload) => {
            log::debug!(
                "Link {}: resource proof {} bytes",
                link_id_hex,
                payload.len()
            );
        }
        LinkEvent::ResourceInitiatorCancel(_) => {
            log::debug!("Link {}: resource initiator cancel", link_id_hex);
        }
        LinkEvent::ResourceReceiverCancel(_) => {
            log::debug!("Link {}: resource receiver cancel", link_id_hex);
        }
        LinkEvent::Closed => {
            println!("LINK_CLOSED={}", link_id_hex);
            log::info!("Link {} closed", link_id_hex);
        }
    }
}
