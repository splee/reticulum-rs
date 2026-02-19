//! Listen mode implementation for rncp.
//!
//! This module handles:
//! - Accepting incoming file transfers
//! - Fetch server functionality (serving files to remote clients)
//! - Resource transfer management

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::cli::format::format_hash;
use reticulum::destination::link::{LinkEvent, LinkEventData, LinkId};
use reticulum::destination::DestinationName;
use reticulum::packet::RETICULUM_MDU;
use reticulum::resource::{Resource, ResourceAdvertisement, ResourceConfig};
use reticulum::transport::{Transport, TransportConfig};
use tokio::sync::RwLock;

use crate::common::{TrackedIncomingResource, TrackedOutgoingResource, validate_fetch_path};
use crate::config::{
    get_config_dir, get_identity_path, load_allowed_identities, parse_allowed_from_cli,
    prepare_identity, FetchServerConfig,
};
use crate::metadata::{encode_filename_metadata, extract_filename_and_data, parse_fetch_request};
use crate::protocol::setup_transport_interfaces;
use crate::{APP_NAME, ASPECT_RECEIVE};

/// Response code indicating fetch is not allowed.
const REQ_FETCH_NOT_ALLOWED: u8 = 0xF0;

/// Run rncp in listen mode.
///
/// Accepts incoming file transfers and optionally serves files via fetch requests.
///
/// # Arguments
/// * `matches` - Command line arguments
/// * `timeout` - Operation timeout
/// * `running` - Atomic flag for graceful shutdown
///
/// # Returns
/// Exit code (0 for success, non-zero for errors)
pub async fn run_listen_mode(
    matches: &clap::ArgMatches,
    timeout: Duration,
    running: Arc<AtomicBool>,
) -> i32 {
    // Get config and identity paths
    let config_dir = get_config_dir(matches.get_one::<String>("config").map(|s| s.as_str()));
    let identity_path = get_identity_path(
        &config_dir,
        matches.get_one::<String>("identity").map(|s| s.as_str()),
    );

    // Load or create identity with persistence
    let identity = match prepare_identity(&identity_path) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{}", e);
            return 2;
        }
    };
    log::info!(
        "Identity address hash: {}",
        hex::encode(identity.as_identity().address_hash.as_slice())
    );

    // Create transport
    let transport = Transport::new(TransportConfig::new(APP_NAME, &identity, false));

    // Set up TCP interfaces if specified
    setup_transport_interfaces(
        &transport,
        matches.get_one::<String>("tcp-server").map(|s| s.as_str()),
        matches.get_one::<String>("tcp-client").map(|s| s.as_str()),
    )
    .await;

    // Give interfaces time to connect
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Create destination
    let dest_name = DestinationName::new(APP_NAME, ASPECT_RECEIVE);
    let destination = transport.add_destination(identity.clone(), dest_name).await;

    let dest_hash = destination.lock().await.desc.address_hash;

    // Handle print-identity mode
    if matches.get_flag("print-identity") {
        println!(
            "Identity     : {}",
            hex::encode(identity.as_identity().address_hash.as_slice())
        );
        println!("Listening on : {}", format_hash(dest_hash.as_slice()));
        return 0;
    }

    println!("rncp listening on {}", format_hash(dest_hash.as_slice()));

    // Handle announce interval
    let announce_interval: i32 = matches
        .get_one::<String>("announce")
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);

    // Send initial announce if interval >= 0
    if announce_interval >= 0 {
        transport.send_announce(&destination, None).await;
        log::info!("Sent announce");
    }

    // Output directory
    let output_dir = matches
        .get_one::<String>("save")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let allow_overwrite = matches.get_flag("overwrite");
    let no_auth = matches.get_flag("no-auth");

    // Load allowed identities
    let mut allowed_identity_hashes = load_allowed_identities();

    // Add CLI-specified allowed identities
    let cli_allowed = parse_allowed_from_cli(matches.get_many::<String>("allowed"));
    allowed_identity_hashes.extend(cli_allowed);

    // Warn if no allowed identities and auth is required
    if allowed_identity_hashes.is_empty() && !no_auth {
        println!("Warning: No allowed identities configured, rncp will not accept any files!");
    } else if !allowed_identity_hashes.is_empty() {
        log::info!(
            "Accepting transfers from {} allowed identit{}",
            allowed_identity_hashes.len(),
            if allowed_identity_hashes.len() == 1 {
                "y"
            } else {
                "ies"
            }
        );
    }

    // Fetch server mode
    let allow_fetch = matches.get_flag("allow-fetch");
    let fetch_jail = matches.get_one::<String>("jail").map(|s| {
        let path = PathBuf::from(s);
        std::fs::canonicalize(&path).unwrap_or(path)
    });
    let auto_compress = !matches.get_flag("no-compress");

    // Create fetch server config
    let fetch_config = Arc::new(FetchServerConfig {
        allow_fetch,
        no_auth,
        fetch_jail: fetch_jail.clone(),
        allowed_identity_hashes: allowed_identity_hashes.clone(),
        auto_compress,
    });

    if allow_fetch {
        if let Some(ref jail) = fetch_jail {
            log::info!("Fetch server enabled, restricted to: {}", jail.display());
        } else {
            log::info!("Fetch server enabled (no path restriction)");
        }
    }

    // Subscribe to incoming link events
    let mut link_events = transport.in_link_events();

    // Track incoming resources by their truncated hash
    let incoming_resources: Arc<RwLock<HashMap<[u8; 16], TrackedIncomingResource>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Track outgoing resources for fetch server
    let outgoing_resources: Arc<RwLock<HashMap<[u8; 16], TrackedOutgoingResource>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Set up announce interval for periodic announces
    let announce_duration = if announce_interval > 0 {
        Some(Duration::from_secs(announce_interval as u64))
    } else {
        None
    };
    let mut next_announce = announce_duration.map(|d| tokio::time::Instant::now() + d);

    // Set up timeout
    let deadline = if timeout.as_secs() > 0 {
        Some(tokio::time::Instant::now() + timeout)
    } else {
        None
    };

    log::info!("Waiting for incoming files...");

    while running.load(Ordering::SeqCst) {
        // Check timeout
        if let Some(dl) = deadline {
            if tokio::time::Instant::now() >= dl {
                eprintln!("Timeout waiting for file transfer");
                return 1;
            }
        }

        tokio::select! {
            // Handle link events
            Ok(event) = link_events.recv() => {
                handle_listen_link_event(
                    &transport,
                    &event,
                    &incoming_resources,
                    &outgoing_resources,
                    &output_dir,
                    allow_overwrite,
                    &fetch_config,
                ).await;
            }
            // Send periodic announces
            _ = async {
                if let Some(next) = next_announce {
                    tokio::time::sleep_until(next).await;
                } else {
                    // Sleep forever if no announce interval
                    std::future::pending::<()>().await;
                }
            } => {
                if running.load(Ordering::SeqCst) {
                    transport.send_announce(&destination, None).await;
                    log::info!("Sent periodic announce");
                    if let Some(dur) = announce_duration {
                        next_announce = Some(tokio::time::Instant::now() + dur);
                    }
                }
            }
            // Check for shutdown
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Just checking running flag
            }
        }
    }

    0
}

/// Handle a link event in listen mode.
///
/// Processes incoming link events including:
/// - Link activation
/// - Fetch requests
/// - Resource requests (for outgoing fetch responses)
/// - Resource advertisements (for incoming file transfers)
/// - Resource data (for incoming file transfers)
async fn handle_listen_link_event(
    transport: &Transport,
    event: &LinkEventData,
    incoming_resources: &Arc<RwLock<HashMap<[u8; 16], TrackedIncomingResource>>>,
    outgoing_resources: &Arc<RwLock<HashMap<[u8; 16], TrackedOutgoingResource>>>,
    output_dir: &Path,
    allow_overwrite: bool,
    fetch_config: &Arc<FetchServerConfig>,
) {
    let link_id = event.id;
    let link_id_hex = hex::encode(&link_id.as_slice()[..8]);

    match &event.event {
        LinkEvent::Activated => {
            log::info!("Incoming link {} established", link_id_hex);
        }
        LinkEvent::Request(payload) => {
            // Handle fetch file requests
            handle_fetch_request(
                transport,
                &link_id,
                payload.as_slice(),
                outgoing_resources,
                fetch_config,
            )
            .await;
        }
        LinkEvent::ResourceRequest(payload) => {
            // Handle resource request from fetch client
            handle_outgoing_resource_request(transport, &link_id, payload.as_slice(), outgoing_resources)
                .await;
        }
        LinkEvent::ResourceAdvertisement(payload) => {
            handle_resource_advertisement(
                transport,
                &link_id,
                &link_id_hex,
                payload.as_slice(),
                incoming_resources,
            )
            .await;
        }
        LinkEvent::ResourceData(payload) => {
            handle_resource_data(
                transport,
                &link_id,
                payload.as_slice(),
                incoming_resources,
                output_dir,
                allow_overwrite,
            )
            .await;
        }
        LinkEvent::Closed => {
            log::info!("Link {} closed", link_id_hex);
        }
        _ => {}
    }
}

/// Handle a resource advertisement in listen mode.
async fn handle_resource_advertisement(
    transport: &Transport,
    link_id: &LinkId,
    link_id_hex: &str,
    payload: &[u8],
    incoming_resources: &Arc<RwLock<HashMap<[u8; 16], TrackedIncomingResource>>>,
) {
    log::info!("Resource advertisement received ({} bytes)", payload.len());

    // Parse the advertisement
    match ResourceAdvertisement::unpack(payload) {
        Ok(adv) => {
            log::info!(
                "Resource: hash={}, size={}, parts={}",
                hex::encode(&adv.hash[..8]),
                adv.data_size,
                adv.num_parts
            );

            println!(
                "Starting resource transfer {} from {}",
                hex::encode(&adv.hash[..8]),
                link_id_hex
            );

            // Create an incoming resource from the advertisement
            let sdu = RETICULUM_MDU;
            let has_metadata = adv.flags.has_metadata;

            match Resource::from_advertisement(&adv, sdu) {
                Ok(mut resource) => {
                    let truncated_hash = *resource.truncated_hash();

                    // Request the first batch of parts
                    if let Some(request_data) = resource.request_next() {
                        log::info!("Sending resource request ({} bytes)", request_data.len());

                        if transport
                            .send_resource_request(link_id, &request_data)
                            .await
                        {
                            // Store the resource for tracking
                            incoming_resources.write().await.insert(
                                truncated_hash,
                                TrackedIncomingResource {
                                    resource,
                                    link_id: *link_id,
                                    has_metadata,
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
            log::error!("Failed to parse resource advertisement: {:?}", e);
        }
    }
}

/// Handle incoming resource data in listen mode.
async fn handle_resource_data(
    transport: &Transport,
    link_id: &LinkId,
    payload: &[u8],
    incoming_resources: &Arc<RwLock<HashMap<[u8; 16], TrackedIncomingResource>>>,
    output_dir: &Path,
    allow_overwrite: bool,
) {
    log::debug!("Resource data received ({} bytes)", payload.len());

    let mut resources = incoming_resources.write().await;
    let mut completed_hash: Option<[u8; 16]> = None;
    let mut needs_more_request: Option<([u8; 16], Vec<u8>)> = None;

    for (hash, tracked) in resources.iter_mut() {
        if tracked.link_id == *link_id && tracked.resource.receive_part(payload.to_vec()) {
            let progress = tracked.resource.progress();
            log::info!(
                "Resource progress: {}/{}",
                progress.processed_parts,
                progress.total_parts
            );

            if tracked.resource.is_complete() {
                completed_hash = Some(*hash);
            } else if let Some(request_data) = tracked.resource.request_next() {
                needs_more_request = Some((*hash, request_data));
            }
            break;
        }
    }

    // Handle completion
    if let Some(hash) = completed_hash {
        if let Some(tracked) = resources.remove(&hash) {
            drop(resources); // Release lock before file I/O
            finalize_received_resource(transport, link_id, tracked, &hash, output_dir, allow_overwrite)
                .await;
        }
    } else {
        drop(resources); // Release lock before sending request
    }

    // Request more parts if needed
    if let Some((hash, request_data)) = needs_more_request {
        log::debug!("Requesting more parts for {}", hex::encode(&hash[..8]));
        transport.send_resource_request(link_id, &request_data).await;
    }
}

/// Finalize a completed resource and save to disk.
async fn finalize_received_resource(
    transport: &Transport,
    link_id: &LinkId,
    tracked: TrackedIncomingResource,
    hash: &[u8; 16],
    output_dir: &Path,
    allow_overwrite: bool,
) {
    let mut resource = tracked.resource;
    let has_metadata = tracked.has_metadata;

    // Get raw assembled data
    let Some(raw_data) = resource.get_raw_assembled_data() else {
        log::error!("Failed to get raw assembled data");
        return;
    };

    // Decrypt the assembled data using the link's key
    let decrypted_result = if resource.is_encrypted() {
        transport.decrypt_with_in_link(link_id, &raw_data).await
    } else {
        Ok(raw_data)
    };

    let decrypted_data = match decrypted_result {
        Ok(data) => data,
        Err(e) => {
            log::error!("Failed to decrypt resource: {:?}", e);
            return;
        }
    };

    let assembled_data = match resource.finalize_assembly(decrypted_data) {
        Ok(data) => data,
        Err(e) => {
            log::error!("Failed to finalize assembly: {:?}", e);
            return;
        }
    };

    // Extract filename and actual file data from assembled data
    let (filename_opt, file_data) = extract_filename_and_data(&assembled_data, has_metadata);

    let filename =
        filename_opt.unwrap_or_else(|| format!("received_{}", hex::encode(&hash[..4])));

    println!(
        "Resource {} completed ({} bytes) -> {}",
        hex::encode(&hash[..8]),
        file_data.len(),
        filename
    );

    // Save file
    let mut save_path = output_dir.join(&filename);

    // Handle file conflicts
    if !allow_overwrite {
        let mut counter = 0;
        while save_path.exists() {
            counter += 1;
            save_path = output_dir.join(format!("{}.{}", filename, counter));
        }
    }

    match File::create(&save_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&file_data) {
                log::error!("Failed to write file: {}", e);
            } else {
                println!("Saved to: {}", save_path.display());

                // Send proof using the assembled data
                let proof = resource.generate_proof_with_data(&assembled_data);
                transport.send_resource_proof(link_id, &proof).await;
                log::info!("Sent resource proof");
            }
        }
        Err(e) => {
            log::error!("Failed to create file: {}", e);
        }
    }
}

/// Send a response to a request (for error codes).
async fn send_fetch_response(transport: &Transport, link_id: &LinkId, response: u8) {
    if let Some(link_mutex) = transport.find_in_link(link_id).await {
        let link = link_mutex.lock().await;
        // Response format: single byte error code
        if let Ok(packet) = link.response_packet(&[response]) {
            transport.send_packet(packet).await;
            log::debug!("Sent fetch response: {:#x}", response);
        }
    }
}

/// Handle a fetch file request.
async fn handle_fetch_request(
    transport: &Transport,
    link_id: &LinkId,
    payload: &[u8],
    outgoing_resources: &Arc<RwLock<HashMap<[u8; 16], TrackedOutgoingResource>>>,
    config: &FetchServerConfig,
) {
    let link_id_hex = hex::encode(&link_id.as_slice()[..8]);

    // Check if fetch is enabled
    if !config.allow_fetch {
        log::debug!("Fetch request received but fetch is not enabled");
        send_fetch_response(transport, link_id, REQ_FETCH_NOT_ALLOWED).await;
        return;
    }

    log::info!(
        "Fetch request received on link {} ({} bytes)",
        link_id_hex,
        payload.len()
    );

    // Parse the request
    let file_path_str = match parse_fetch_request(payload) {
        Some(p) => p,
        None => {
            log::warn!("Failed to parse fetch request");
            send_fetch_response(transport, link_id, REQ_FETCH_NOT_ALLOWED).await;
            return;
        }
    };

    log::info!("Fetch request for file: {}", file_path_str);

    // Validate the path
    let file_path = match validate_fetch_path(&file_path_str, config.fetch_jail.as_ref()) {
        Some(p) => p,
        None => {
            log::warn!("Invalid or disallowed fetch path: {}", file_path_str);
            // Send false to indicate file not found
            send_msgpack_false(transport, link_id).await;
            return;
        }
    };

    // Read the file
    let file_data = match std::fs::read(&file_path) {
        Ok(data) => data,
        Err(e) => {
            log::error!("Failed to read file {}: {}", file_path.display(), e);
            send_msgpack_false(transport, link_id).await;
            return;
        }
    };

    log::info!(
        "Sending file {} ({} bytes) to client",
        file_path.display(),
        file_data.len()
    );

    // Create metadata with filename
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let metadata = encode_filename_metadata(filename);

    // Create resource
    let resource_config = ResourceConfig {
        auto_compress: config.auto_compress,
        ..ResourceConfig::default()
    };

    let mut rng = OsRng;
    let resource = match Resource::new(&mut rng, &file_data, resource_config, Some(&metadata)) {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to create resource: {:?}", e);
            return;
        }
    };

    let resource_hash = resource.hash();
    let truncated_hash = *resource.truncated_hash();
    log::info!(
        "Created resource: hash={}, size={}, parts={}",
        hex::encode(&resource_hash[..8]),
        resource.total_size(),
        resource.total_parts()
    );

    // Send resource advertisement
    let advertisement = resource.create_advertisement();
    if let Some(link_mutex) = transport.find_in_link(link_id).await {
        let link_guard = link_mutex.lock().await;
        match link_guard.resource_advertisement_packet(&advertisement, 0) {
            Ok(packet) => {
                drop(link_guard);
                transport.send_packet(packet).await;
                log::info!("Sent resource advertisement for fetch response");

                // Store resource for handling requests
                outgoing_resources.write().await.insert(
                    truncated_hash,
                    TrackedOutgoingResource {
                        resource,
                        link_id: *link_id,
                    },
                );

                // Also send a success response (true = file found, sending resource)
                send_msgpack_true(transport, link_id).await;
            }
            Err(e) => {
                log::error!("Failed to send resource advertisement: {:?}", e);
            }
        }
    }
}

/// Send msgpack false (0xc2) as a response.
async fn send_msgpack_false(transport: &Transport, link_id: &LinkId) {
    if let Some(link_mutex) = transport.find_in_link(link_id).await {
        let link = link_mutex.lock().await;
        // 0xc2 is msgpack false
        if let Ok(packet) = link.response_packet(&[0xc2]) {
            transport.send_packet(packet).await;
        }
    }
}

/// Send msgpack true (0xc3) as a response.
async fn send_msgpack_true(transport: &Transport, link_id: &LinkId) {
    if let Some(link_mutex) = transport.find_in_link(link_id).await {
        let link = link_mutex.lock().await;
        // 0xc3 is msgpack true
        if let Ok(packet) = link.response_packet(&[0xc3]) {
            transport.send_packet(packet).await;
        }
    }
}

/// Handle resource request for outgoing resources (fetch server sending file parts).
async fn handle_outgoing_resource_request(
    transport: &Transport,
    link_id: &LinkId,
    payload: &[u8],
    outgoing_resources: &Arc<RwLock<HashMap<[u8; 16], TrackedOutgoingResource>>>,
) {
    let link_id_hex = hex::encode(&link_id.as_slice()[..8]);
    log::debug!(
        "Resource request received on link {} ({} bytes)",
        link_id_hex,
        payload.len()
    );

    let mut resources = outgoing_resources.write().await;

    // Find a matching resource for this link
    let mut found_resource_hash: Option<[u8; 16]> = None;
    let mut parts_to_send: Vec<(usize, Vec<u8>)> = Vec::new();

    for (hash, tracked) in resources.iter_mut() {
        if tracked.link_id == *link_id {
            match tracked.resource.handle_request(payload) {
                Ok((_wants_more_hashmap, part_indices)) => {
                    // Collect parts to send
                    for &idx in &part_indices {
                        if let Some(data) = tracked.resource.get_part_data(idx) {
                            parts_to_send.push((idx, data.to_vec()));
                        }
                    }
                    found_resource_hash = Some(*hash);
                    break;
                }
                Err(e) => {
                    log::error!("Failed to handle resource request: {:?}", e);
                }
            }
        }
    }

    drop(resources);

    // Send the parts
    if let Some(link_mutex) = transport.find_in_link(link_id).await {
        for (idx, part_data) in parts_to_send {
            let link_guard = link_mutex.lock().await;
            match link_guard.resource_data_packet(&part_data) {
                Ok(packet) => {
                    drop(link_guard);
                    transport.send_packet(packet).await;
                    log::debug!("Sent part {} for fetch response", idx);
                }
                Err(e) => {
                    log::error!("Failed to send resource data packet: {:?}", e);
                    break;
                }
            }
        }
    }

    // Check if resource is complete (all parts sent and proof received)
    // For now, we keep the resource until the link closes
    if let Some(_hash) = found_resource_hash {
        log::debug!("Processed resource request");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_req_fetch_not_allowed_constant() {
        assert_eq!(REQ_FETCH_NOT_ALLOWED, 0xF0);
    }
}
