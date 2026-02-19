//! Test helper: Resource server that accepts incoming links and completes resource transfers
//!
//! This binary creates a destination, announces it, and listens for incoming links.
//! When resource advertisements are received, it responds with requests and completes
//! the full transfer protocol.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rand_core::OsRng;
use reticulum::destination::link::{LinkEvent, LinkEventData, LinkId};
use reticulum::destination::DestinationName;
#[allow(unused_imports)]
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::resource::{Resource, ResourceAdvertisement};
use reticulum::packet::RETICULUM_MDU;
use reticulum::transport::{Transport, TransportConfig};
use tokio::sync::RwLock;

/// Test resource server for integration testing
#[derive(Parser, Debug)]
#[command(name = "test_resource_server")]
#[command(about = "Listen for incoming Reticulum resources and complete transfers")]
struct Args {
    /// Application name for destination
    #[arg(short, long, default_value = "test_app")]
    app_name: String,

    /// Aspect for destination
    #[arg(short = 'A', long, default_value = "resourceserver")]
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

/// Tracked incoming resource with its link
struct TrackedIncomingResource {
    resource: Resource,
    link_id: LinkId,
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
        let transport = Transport::new(TransportConfig::new("resource_server", &identity, false));

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

        // Track incoming resources by their truncated hash
        let incoming_resources: Arc<RwLock<HashMap<[u8; 16], TrackedIncomingResource>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Track statistics
        let mut link_count = 0u32;
        let mut resource_complete_count = 0u32;

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
            if args.resource_count > 0 && resource_complete_count >= args.resource_count {
                log::info!("Reached resource limit ({}), exiting", args.resource_count);
                println!("STATUS=RESOURCE_LIMIT_REACHED");
                break;
            }

            tokio::select! {
                // Handle link events
                Ok(event) = link_events.recv() => {
                    let completed = handle_link_event(
                        &transport,
                        &event,
                        &incoming_resources,
                        &mut link_count,
                    ).await;
                    if completed {
                        resource_complete_count += 1;
                    }
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
        println!("TOTAL_RESOURCES_COMPLETE={}", resource_complete_count);
        println!("STATUS=SHUTDOWN");
        log::info!(
            "Resource server complete: {} links, {} resources completed",
            link_count,
            resource_complete_count
        );
    });
}

async fn handle_link_event(
    transport: &Transport,
    event: &LinkEventData,
    incoming_resources: &Arc<RwLock<HashMap<[u8; 16], TrackedIncomingResource>>>,
    link_count: &mut u32,
) -> bool {
    let link_id = event.id;
    let link_id_hex = hex::encode(link_id.as_slice());

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
            log::info!(
                "Link {}: resource advertisement {} bytes",
                link_id_hex,
                payload.len()
            );

            // Parse the advertisement
            match ResourceAdvertisement::unpack(payload.as_slice()) {
                Ok(adv) => {
                    println!(
                        "RESOURCE_ADVERTISEMENT={}:{}:{}:{}:{}",
                        link_id_hex,
                        hex::encode(adv.hash),
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

                    // Create an incoming resource from the advertisement
                    // SDU matches plain Reticulum MDU (MTU - header max - IFAC min)
                    let sdu = RETICULUM_MDU;

                    // Debug: Log hashmap and random_hash info
                    log::debug!(
                        "Advertisement: hashmap {} bytes ({} entries), random_hash {:?}",
                        adv.hashmap.len(),
                        adv.hashmap.len() / 4,
                        &adv.random_hash
                    );

                    match Resource::from_advertisement(&adv, sdu) {
                        Ok(mut resource) => {
                            let truncated_hash = *resource.truncated_hash();

                            // Request the first batch of parts
                            if let Some(request_data) = resource.request_next() {
                                log::info!(
                                    "Sending resource request ({} bytes) for hash {}",
                                    request_data.len(),
                                    hex::encode(truncated_hash)
                                );

                                if transport.send_resource_request(&link_id, &request_data).await {
                                    println!(
                                        "RESOURCE_REQUEST_SENT={}:{}",
                                        link_id_hex,
                                        hex::encode(truncated_hash)
                                    );

                                    // Store the resource for tracking
                                    incoming_resources.write().await.insert(
                                        truncated_hash,
                                        TrackedIncomingResource {
                                            resource,
                                            link_id,
                                        },
                                    );
                                } else {
                                    log::error!("Failed to send resource request");
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to create resource from advertisement: {:?}", e);
                        }
                    }
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
            log::info!(
                "Link {}: resource data {} bytes",
                link_id_hex,
                payload.len()
            );

            // Try to find the resource this data belongs to and add the part
            let mut resources = incoming_resources.write().await;
            log::debug!("Have {} tracked resources", resources.len());

            // We need to check all resources to find which one this part belongs to
            let mut completed_hash: Option<[u8; 16]> = None;
            let mut needs_more_request: Option<([u8; 16], Vec<u8>)> = None;

            for (hash, tracked) in resources.iter_mut() {
                log::debug!(
                    "Trying resource {} (link {:?} vs {:?})",
                    hex::encode(hash),
                    tracked.link_id.as_slice(),
                    link_id.as_slice()
                );
                if tracked.link_id == link_id {
                    log::debug!("Calling receive_part on resource {}", hex::encode(hash));
                    if tracked.resource.receive_part(payload.as_slice().to_vec()) {
                        log::debug!(
                            "Received part for resource {}, progress: {}/{}",
                            hex::encode(hash),
                            tracked.resource.progress().processed_parts,
                            tracked.resource.progress().total_parts
                        );

                        println!(
                            "RESOURCE_PART_RECEIVED={}:{}:{}/{}",
                            link_id_hex,
                            hex::encode(hash),
                            tracked.resource.progress().processed_parts,
                            tracked.resource.progress().total_parts
                        );

                        // Check if complete
                        if tracked.resource.is_complete() {
                            completed_hash = Some(*hash);
                        } else {
                            // Request more parts if needed
                            if let Some(request_data) = tracked.resource.request_next() {
                                needs_more_request = Some((*hash, request_data));
                            }
                        }
                        break;
                    }
                }
            }

            // Handle completion
            if let Some(hash) = completed_hash {
                if let Some(tracked) = resources.remove(&hash) {
                    let mut resource = tracked.resource;

                    // Get raw assembled data
                    if let Some(raw_data) = resource.get_raw_assembled_data() {
                        let raw_data_len = raw_data.len();

                        // Decrypt the assembled data using the link's key
                        let decrypted_result = if resource.is_encrypted() {
                            transport.decrypt_with_in_link(&link_id, &raw_data).await
                        } else {
                            Ok(raw_data)
                        };
                        match decrypted_result {
                            Ok(decrypted_data) => {
                                log::debug!(
                                    "Decrypted {} bytes from {} raw bytes, first 20: {:?}",
                                    decrypted_data.len(),
                                    raw_data_len,
                                    &decrypted_data[..std::cmp::min(20, decrypted_data.len())]
                                );
                                // Finalize assembly with decrypted data
                                match resource.finalize_assembly(decrypted_data) {
                                    Ok(data) => {
                                        log::info!(
                                            "Resource {} complete! Received {} bytes",
                                            hex::encode(hash),
                                            data.len()
                                        );
                                        println!(
                                            "RESOURCE_COMPLETE={}:{}:{}",
                                            link_id_hex,
                                            hex::encode(hash),
                                            data.len()
                                        );

                                        // Send proof using the assembled data
                                        // (incoming resources don't have original_data set)
                                        let proof_data = resource.generate_proof_with_data(&data);
                                        if transport.send_resource_proof(&link_id, &proof_data).await {
                                            println!(
                                                "RESOURCE_PROOF_SENT={}:{}",
                                                link_id_hex,
                                                hex::encode(hash)
                                            );
                                        }
                                        return true;
                                    }
                                    Err(e) => {
                                        log::error!("Failed to assemble resource {}: {:?}", hex::encode(hash), e);
                                        println!(
                                            "RESOURCE_ASSEMBLY_ERROR={}:{}:{:?}",
                                            link_id_hex,
                                            hex::encode(hash),
                                            e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Failed to decrypt resource {}: {:?}", hex::encode(hash), e);
                                println!(
                                    "RESOURCE_ASSEMBLY_ERROR={}:{}:DecryptFailed:{:?}",
                                    link_id_hex,
                                    hex::encode(hash),
                                    e
                                );
                            }
                        }
                    } else {
                        log::error!("Failed to get raw assembled data for resource {}", hex::encode(hash));
                        println!(
                            "RESOURCE_ASSEMBLY_ERROR={}:{}:NoRawData",
                            link_id_hex,
                            hex::encode(hash)
                        );
                    }
                }
            }

            // Send request for more parts if needed
            if let Some((hash, request_data)) = needs_more_request {
                log::debug!(
                    "Requesting more parts for resource {}",
                    hex::encode(hash)
                );
                transport.send_resource_request(&link_id, &request_data).await;
            }
        }
        LinkEvent::ResourceHashmapUpdate(payload) => {
            log::debug!(
                "Link {}: resource hashmap update {} bytes",
                link_id_hex,
                payload.len()
            );

            // The hashmap update contains: [resource_hash:16][hashmap_data...]
            if payload.len() < 16 {
                log::error!("Hashmap update too short");
                return false;
            }

            let mut resource_hash = [0u8; 16];
            resource_hash.copy_from_slice(&payload.as_slice()[..16]);
            let hashmap_data = &payload.as_slice()[16..];

            let mut resources = incoming_resources.write().await;
            if let Some(tracked) = resources.get_mut(&resource_hash) {
                // Update the hashmap (segment 0 for now, can be improved)
                tracked.resource.update_hashmap(0, hashmap_data);

                println!(
                    "RESOURCE_HASHMAP_UPDATED={}:{}:{}",
                    link_id_hex,
                    hex::encode(resource_hash),
                    hashmap_data.len()
                );

                // Request more parts now that we have more hashmap
                if let Some(request_data) = tracked.resource.request_next() {
                    transport.send_resource_request(&link_id, &request_data).await;
                }
            }
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
        LinkEvent::Channel(payload) => {
            log::debug!("Link {}: channel data {} bytes", link_id_hex, payload.len());
        }
        LinkEvent::Request(payload) => {
            log::debug!("Link {}: request {} bytes", link_id_hex, payload.len());
        }
        LinkEvent::Response(payload) => {
            log::debug!("Link {}: response {} bytes", link_id_hex, payload.len());
        }
        LinkEvent::Identified(identity) => {
            log::info!("Link {}: remote identified as {}", link_id_hex, identity.address_hash);
            println!("IDENTIFIED={}:{}", link_id_hex, hex::encode(identity.address_hash.as_slice()));
        }
        LinkEvent::Closed => {
            println!("LINK_CLOSED={}", link_id_hex);
            log::info!("Link {} closed", link_id_hex);

            // Clean up any resources associated with this link
            let mut resources = incoming_resources.write().await;
            resources.retain(|_, tracked| tracked.link_id != link_id);
        }
    }

    false
}
