//! Test helper: Resource client that sends resources over links
//!
//! This binary connects to a known destination and sends a resource.
//! It tests the Rust → Python resource transfer direction.
//! Used for integration testing resource sending.

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
use reticulum::resource::{Resource, ResourceConfig};
use reticulum::transport::{Transport, TransportConfig};
use tokio::sync::Mutex;

/// Test resource client for integration testing
#[derive(Parser, Debug)]
#[command(name = "test_resource_client")]
#[command(about = "Send resources over Reticulum links for testing")]
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

    /// Data to send as resource (hex string)
    #[arg(short = 's', long)]
    send_data: Option<String>,

    /// Timeout in seconds
    #[arg(short = 't', long, default_value = "60")]
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
        let transport = Transport::new(TransportConfig::new("resource_client", &identity, false));

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

            // Wait for an announce to get the full destination info
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

        // Send resource if data is specified
        if let Some(data_hex) = &args.send_data {
            let data = match hex::decode(data_hex) {
                Ok(d) => d,
                Err(e) => {
                    log::error!("Invalid send data: {}", e);
                    println!("STATUS=ERROR:invalid_send_data");
                    return 1;
                }
            };

            log::info!("Creating resource with {} bytes of data", data.len());

            // Create resource
            let mut rng = OsRng;
            let config = ResourceConfig {
                auto_compress: true,
                ..ResourceConfig::default()
            };

            let resource = match Resource::new(&mut rng, &data, config, None, None) {
                Ok(r) => r,
                Err(e) => {
                    log::error!("Failed to create resource: {:?}", e);
                    println!("STATUS=ERROR:resource_creation_failed");
                    return 1;
                }
            };

            let resource_hash_hex = hex::encode(&resource.hash()[..16]);
            println!(
                "RESOURCE_CREATED={}:{}:{}",
                resource_hash_hex,
                resource.total_size(),
                resource.total_parts()
            );
            log::info!(
                "Resource created: hash={}, size={}, parts={}",
                resource_hash_hex,
                resource.total_size(),
                resource.total_parts()
            );

            // Create advertisement
            let advertisement = resource.create_advertisement();
            let adv_data = match advertisement.pack(0) {
                Ok(d) => d,
                Err(e) => {
                    log::error!("Failed to pack advertisement: {:?}", e);
                    println!("STATUS=ERROR:advertisement_pack_failed");
                    return 1;
                }
            };

            log::info!(
                "Sending resource advertisement ({} bytes)",
                adv_data.len()
            );

            // Send advertisement packet
            {
                let link_guard = link.inner().lock().await;
                match link_guard.resource_advertisement_packet(&advertisement, 0) {
                    Ok(packet) => {
                        drop(link_guard);
                        transport.send_packet(packet).await;
                        println!("RESOURCE_ADVERTISED={}", resource_hash_hex);
                        log::info!("Resource advertised");
                    }
                    Err(e) => {
                        log::error!("Failed to create advertisement packet: {:?}", e);
                        println!("STATUS=ERROR:advertisement_send_failed");
                        return 1;
                    }
                }
            }

            // Store resource for handling requests
            let resource = Arc::new(Mutex::new(resource));

            // Wait for resource requests and send parts
            let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout);
            let mut parts_sent = 0usize;
            let mut proof_received = false;
            let total_parts = resource.lock().await.total_parts();

            while tokio::time::Instant::now() < deadline && running.load(Ordering::SeqCst) {
                tokio::select! {
                    Ok(event) = link_events.recv() => {
                        if event.id == link_id {
                            match event.event {
                                LinkEvent::ResourceRequest(payload) => {
                                    let request_data = payload.as_slice();
                                    log::info!(
                                        "Received resource request ({} bytes)",
                                        request_data.len()
                                    );
                                    println!(
                                        "RESOURCE_REQUEST_RECEIVED={}:{}",
                                        resource_hash_hex,
                                        request_data.len()
                                    );

                                    // Handle request
                                    let mut resource_guard = resource.lock().await;
                                    match resource_guard.handle_request(request_data) {
                                        Ok(result) => {
                                            if let Some(ref hmu_data) = result.hashmap_update {
                                                log::info!(
                                                    "Sending hashmap update ({} bytes)",
                                                    hmu_data.len()
                                                );

                                                transport
                                                    .send_resource_hashmap_update(&link_id, hmu_data)
                                                    .await;
                                                println!(
                                                    "RESOURCE_HMU_SENT={}",
                                                    resource_hash_hex,
                                                );
                                            }

                                            // Send requested parts
                                            // Drop resource guard before getting link
                                            let parts_to_send: Vec<_> = result.parts_to_send.iter()
                                                .filter_map(|&idx| resource_guard.get_part_data(idx).map(|d| (idx, d.to_vec())))
                                                .collect();
                                            drop(resource_guard);

                                            for (part_idx, part_data) in parts_to_send {
                                                log::debug!(
                                                    "Sending part {} ({} bytes)",
                                                    part_idx,
                                                    part_data.len()
                                                );

                                                // Create encrypted packet using link
                                                let link_guard = link.inner().lock().await;
                                                match link_guard.resource_data_packet(&part_data) {
                                                    Ok(packet) => {
                                                        drop(link_guard);
                                                        transport.send_packet(packet).await;
                                                        parts_sent += 1;
                                                    }
                                                    Err(e) => {
                                                        log::error!("Failed to create resource data packet: {:?}", e);
                                                    }
                                                }
                                            }

                                            println!(
                                                "RESOURCE_PARTS_SENT={}:{}/{}",
                                                resource_hash_hex, parts_sent, total_parts
                                            );
                                            log::info!(
                                                "Sent parts, total {}/{}",
                                                parts_sent,
                                                total_parts
                                            );
                                        }
                                        Err(e) => {
                                            log::error!("Failed to handle resource request: {:?}", e);
                                        }
                                    }
                                }
                                LinkEvent::ResourceProof(payload) => {
                                    let proof_data = payload.as_slice();
                                    log::info!(
                                        "Received resource proof ({} bytes)",
                                        proof_data.len()
                                    );

                                    let resource_guard = resource.lock().await;
                                    if resource_guard.verify_proof(proof_data) {
                                        proof_received = true;
                                        println!("RESOURCE_PROOF_RECEIVED={}", resource_hash_hex);
                                        log::info!("Resource transfer completed successfully");
                                        break;
                                    } else {
                                        log::error!("Invalid resource proof received");
                                        println!("STATUS=ERROR:invalid_proof");
                                    }
                                }
                                LinkEvent::Closed => {
                                    log::warn!("Link closed during resource transfer");
                                    println!("STATUS=ERROR:link_closed_during_transfer");
                                    return 1;
                                }
                                _ => {}
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        // Continue waiting
                    }
                }
            }

            if proof_received {
                println!("RESOURCE_TRANSFER_COMPLETE={}:{}", resource_hash_hex, parts_sent);
                log::info!("Resource transfer complete: {} parts sent", parts_sent);
            } else {
                log::error!("Timeout waiting for resource proof");
                println!("STATUS=ERROR:resource_timeout");
                return 1;
            }
        } else {
            log::warn!("No data specified to send (use --send-data)");
            println!("STATUS=WARNING:no_data");
        }

        println!("STATUS=SUCCESS");
        log::info!("Resource client complete");
        0
    });

    std::process::exit(exit_code);
}
