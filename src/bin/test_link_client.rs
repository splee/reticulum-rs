//! Test helper: Link client that establishes outgoing links
//!
//! This binary connects to a known destination hash and establishes a link.
//! It can send test data and receive responses.
//! Used for integration testing link establishment and data exchange.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rand_core::OsRng;
use reticulum::destination::link::{LinkEvent, LinkStatus};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport, TransportConfig};

/// Test link client for integration testing
#[derive(Parser, Debug)]
#[command(name = "test_link_client")]
#[command(about = "Establish outgoing Reticulum links for testing")]
struct Args {
    /// Destination hash to connect to (hex string)
    #[arg(short, long)]
    destination: Option<String>,

    /// Wait for an announce matching app_name.aspect
    #[arg(long)]
    wait_announce: bool,

    /// Application name to match in announces
    #[arg(short, long, default_value = "test_app")]
    app_name: String,

    /// Aspect to match in announces
    #[arg(short = 'A', long, default_value = "linkserver")]
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

    /// Data to send after link activation (hex string)
    #[arg(long)]
    send_data: Option<String>,

    /// Expected response data (hex string, for verification)
    #[arg(long)]
    expect_response: Option<String>,

    /// Link timeout in seconds
    #[arg(short = 't', long, default_value = "30")]
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

    let exit_code = rt.block_on(async {
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
        let transport = Transport::new(TransportConfig::new("link_client", &identity, false));

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

        // Get destination to connect to
        let dest_desc = if let Some(dest_hex) = &args.destination {
            // Parse destination hash from command line
            let address_hash = match AddressHash::new_from_hex_string(dest_hex) {
                Ok(hash) => hash,
                Err(e) => {
                    log::error!("Invalid destination hash: {:?}", e);
                    println!("STATUS=ERROR:invalid_destination");
                    return 1;
                }
            };

            log::info!("Connecting to destination: {}", dest_hex);

            // We need to wait for an announce to get the full destination info
            log::info!("Waiting for announce from {}", dest_hex);

            let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout);
            let mut announce_rx = transport.recv_announces().await;

            loop {
                if tokio::time::Instant::now() >= deadline {
                    log::error!("Timeout waiting for announce from {}", dest_hex);
                    println!("STATUS=ERROR:announce_timeout");
                    return 1;
                }

                if !running.load(Ordering::SeqCst) {
                    println!("STATUS=INTERRUPTED");
                    return 1;
                }

                tokio::select! {
                    Ok(event) = announce_rx.recv() => {
                        let announced_hash = event.destination.lock().await.desc.address_hash;
                        if announced_hash == address_hash {
                            log::info!("Received announce from target destination");
                            println!("ANNOUNCE_RECEIVED={}", dest_hex);
                            break event.destination.lock().await.desc;
                        } else {
                            log::debug!(
                                "Received announce from different destination: {}",
                                hex::encode(announced_hash.as_slice())
                            );
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        // Continue waiting
                    }
                }
            }
        } else if args.wait_announce {
            // Wait for any announce matching the app/aspect
            log::info!("Waiting for announce from {}.{}", args.app_name, args.aspect);

            let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout);
            let mut announce_rx = transport.recv_announces().await;

            loop {
                if tokio::time::Instant::now() >= deadline {
                    log::error!("Timeout waiting for announce");
                    println!("STATUS=ERROR:announce_timeout");
                    return 1;
                }

                if !running.load(Ordering::SeqCst) {
                    println!("STATUS=INTERRUPTED");
                    return 1;
                }

                tokio::select! {
                    Ok(event) = announce_rx.recv() => {
                        let dest = event.destination.lock().await;
                        log::info!(
                            "Received announce from: {}",
                            hex::encode(dest.desc.address_hash.as_slice())
                        );
                        println!(
                            "ANNOUNCE_RECEIVED={}",
                            hex::encode(dest.desc.address_hash.as_slice())
                        );
                        // Accept first announce we see
                        break dest.desc;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        // Continue waiting
                    }
                }
            }
        } else {
            log::error!("Must specify --destination or --wait-announce");
            println!("STATUS=ERROR:no_destination");
            return 1;
        };

        log::info!(
            "Establishing link to {}",
            hex::encode(dest_desc.address_hash.as_slice())
        );
        println!(
            "LINK_REQUESTING={}",
            hex::encode(dest_desc.address_hash.as_slice())
        );

        // Subscribe to outgoing link events
        let mut link_events = transport.out_link_events();

        // Create link
        let link = transport.link(dest_desc).await;
        let link_id = *link.id();
        let link_id_hex = hex::encode(link_id.as_slice());

        log::info!("Link request sent, waiting for activation...");

        // Wait for link activation
        let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout);
        let mut link_activated = false;

        while tokio::time::Instant::now() < deadline && running.load(Ordering::SeqCst) {
            tokio::select! {
                Ok(event) = link_events.recv() => {
                    if event.id == link_id {
                        match event.event {
                            LinkEvent::Activated => {
                                link_activated = true;
                                println!("LINK_ACTIVATED={}", link_id_hex);
                                log::info!("Link {} activated", link_id_hex);
                                break;
                            }
                            LinkEvent::Closed => {
                                log::error!("Link {} was closed", link_id_hex);
                                println!("STATUS=ERROR:link_closed");
                                return 1;
                            }
                            _ => {}
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Check link status directly
                    if link.status().await == LinkStatus::Active {
                        link_activated = true;
                        println!("LINK_ACTIVATED={}", link_id_hex);
                        log::info!("Link {} activated (from status check)", link_id_hex);
                        break;
                    }
                }
            }
        }

        if !link_activated {
            log::error!("Timeout waiting for link activation");
            println!("STATUS=ERROR:link_timeout");
            return 1;
        }

        // Brief delay to allow RTT packet to be sent (completes Python handshake)
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Send data if configured
        if let Some(data_hex) = &args.send_data {
            let data = match hex::decode(data_hex) {
                Ok(d) => d,
                Err(e) => {
                    log::error!("Invalid send data: {}", e);
                    println!("STATUS=ERROR:invalid_send_data");
                    return 1;
                }
            };

            log::info!("Sending {} bytes on link", data.len());
            transport.send_to_out_links(&dest_desc.address_hash, &data).await;
            println!("DATA_SENT={}:{}", link_id_hex, data.len());
        }

        // Wait for response if expected
        if let Some(expected_hex) = &args.expect_response {
            let expected = match hex::decode(expected_hex) {
                Ok(d) => d,
                Err(e) => {
                    log::error!("Invalid expected response: {}", e);
                    println!("STATUS=ERROR:invalid_expected_response");
                    return 1;
                }
            };

            log::info!("Waiting for response data...");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout);

            while tokio::time::Instant::now() < deadline && running.load(Ordering::SeqCst) {
                tokio::select! {
                    Ok(event) = link_events.recv() => {
                        if event.id == link_id {
                            if let LinkEvent::Data(payload) = event.event {
                                let received = payload.as_slice();
                                println!(
                                    "DATA_RECEIVED={}:{}:{}",
                                    link_id_hex,
                                    received.len(),
                                    hex::encode(received)
                                );
                                log::info!("Received {} bytes: {}", received.len(), hex::encode(received));

                                if received == expected.as_slice() {
                                    println!("RESPONSE_VERIFIED=true");
                                    log::info!("Response matches expected data");
                                } else {
                                    println!("RESPONSE_VERIFIED=false");
                                    log::warn!("Response does not match expected data");
                                    log::warn!("Expected: {}", expected_hex);
                                    log::warn!("Got: {}", hex::encode(received));
                                }
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        // Continue waiting
                    }
                }
            }
        }

        println!("STATUS=SUCCESS");
        log::info!("Link client complete");
        0
    });

    std::process::exit(exit_code);
}
