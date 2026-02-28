//! Fetch mode implementation for rncp.
//!
//! This module handles pulling files from a remote rncp listener.
//! It establishes a link, sends a fetch request, and receives
//! the file as a resource transfer.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reticulum::destination::link::LinkEvent;
use reticulum::hash::AddressHash;
use reticulum::packet::RETICULUM_MDU;
use reticulum::resource::{Resource, ResourceAdvertisement};
use reticulum::transport::{Transport, TransportConfig};

use crate::config::{get_config_dir, get_identity_path, prepare_identity};
use crate::metadata::create_request_data;
use crate::protocol::{
    setup_transport_interfaces, wait_for_announce, wait_for_link_activation, ProtocolError,
};
use crate::APP_NAME;

/// Response code indicating fetch is not allowed.
const REQ_FETCH_NOT_ALLOWED: u8 = 0xF0;

/// Run rncp in fetch mode.
///
/// Fetches a file from a remote rncp listener that has fetch enabled.
///
/// # Arguments
/// * `matches` - Command line arguments
/// * `timeout` - Operation timeout
/// * `running` - Atomic flag for graceful shutdown
///
/// # Returns
/// Exit code (0 for success, non-zero for errors)
pub async fn run_fetch_mode(
    matches: &clap::ArgMatches,
    timeout: Duration,
    running: Arc<AtomicBool>,
) -> i32 {
    let dest_hash_str = matches.get_one::<String>("destination").unwrap();
    let file_path_str = matches.get_one::<String>("file").unwrap();
    let silent = matches.get_flag("silent");

    // Parse destination hash
    let dest_hash = match AddressHash::new_from_hex_string(dest_hash_str) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Invalid destination hash: must be 32 hexadecimal characters");
            log::error!("Invalid destination hash: {:?}", e);
            return 1;
        }
    };

    // Get config and identity paths
    let config_dir = get_config_dir(matches.get_one::<String>("config").map(|s| s.as_str()));
    let identity_path = get_identity_path(
        &config_dir,
        matches.get_one::<String>("identity").map(|s| s.as_str()),
    );

    // Load or create identity
    let identity = match prepare_identity(&identity_path) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{}", e);
            return 2;
        }
    };

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

    // Output directory
    let output_dir = matches
        .get_one::<String>("save")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let allow_overwrite = matches.get_flag("overwrite");

    // Wait for announce from destination
    let mut announce_rx = transport.recv_announces().await;
    let dest_desc = match wait_for_announce(&mut announce_rx, &dest_hash, timeout, &running, silent)
        .await
    {
        Ok(desc) => desc,
        Err(ProtocolError::PathNotFound) => {
            eprintln!("Path not found");
            return 1;
        }
        Err(ProtocolError::Cancelled) => {
            return 1;
        }
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    };

    // Create link
    let mut link_events = transport.out_link_events();
    let link = transport.link(dest_desc).await;
    let link_id = *link.id();

    // Wait for link activation
    if let Err(e) =
        wait_for_link_activation(&link, &link_id, &mut link_events, timeout, &running, silent).await
    {
        match e {
            ProtocolError::LinkClosed => {
                eprintln!("Link establishment failed");
            }
            ProtocolError::Timeout => {
                eprintln!("Link establishment timed out");
            }
            _ => {
                eprintln!("{}", e);
            }
        }
        return 1;
    }

    // Send fetch request
    if !silent {
        println!("Requesting file: {}", file_path_str);
    }

    let request_data = create_request_data("fetch_file", file_path_str.as_bytes());
    if let Err(e) = link.send_request(&request_data).await {
        eprintln!("Failed to send fetch request: {:?}", e);
        return 1;
    }
    log::info!("Sent fetch request");

    // Wait for response and handle resource transfer
    let mut ctx = FetchContext {
        transport: &transport,
        link_events: &mut link_events,
        link_id: &link_id,
        file_path_str,
        output_dir: &output_dir,
        allow_overwrite,
        silent,
        timeout,
        running: &running,
    };
    handle_fetch_response(&mut ctx).await
}

/// Context for a fetch response handler, grouping related parameters.
struct FetchContext<'a> {
    transport: &'a Transport,
    link_events: &'a mut tokio::sync::broadcast::Receiver<reticulum::destination::link::LinkEventData>,
    link_id: &'a reticulum::destination::link::LinkId,
    file_path_str: &'a str,
    output_dir: &'a Path,
    allow_overwrite: bool,
    silent: bool,
    timeout: Duration,
    running: &'a Arc<AtomicBool>,
}

/// Handle the fetch response and resource transfer.
///
/// Waits for the server's response (either error or resource advertisement)
/// and manages the incoming resource transfer.
async fn handle_fetch_response(ctx: &mut FetchContext<'_>) -> i32 {
    // Track incoming resource
    let mut incoming_resource: Option<Resource> = None;
    let mut request_resolved = false;
    let mut request_failed = false;

    let deadline = tokio::time::Instant::now() + ctx.timeout;

    // Wait for response (either error code or resource transfer)
    while tokio::time::Instant::now() < deadline
        && ctx.running.load(Ordering::SeqCst)
        && !request_resolved
    {
        tokio::select! {
            Ok(event) = ctx.link_events.recv() => {
                if event.id == *ctx.link_id {
                    match event.event {
                        LinkEvent::Response(payload) => {
                            if let Some(failed) = handle_response_event(payload.as_slice()) {
                                request_failed = failed;
                                request_resolved = failed;
                            }
                        }
                        LinkEvent::ResourceAdvertisement(payload) => {
                            match handle_advertisement_event(
                                ctx.transport,
                                ctx.link_id,
                                payload.as_slice(),
                                ctx.silent,
                            ).await {
                                Ok(resource) => {
                                    incoming_resource = Some(resource);
                                }
                                Err(_) => {
                                    request_failed = true;
                                    request_resolved = true;
                                }
                            }
                        }
                        LinkEvent::ResourceData(payload) => {
                            if let Some(ref mut resource) = incoming_resource {
                                match handle_data_event(
                                    ctx.transport,
                                    ctx.link_id,
                                    resource,
                                    payload.as_slice(),
                                    ctx.file_path_str,
                                    ctx.output_dir,
                                    ctx.allow_overwrite,
                                ).await {
                                    DataEventResult::Complete => {
                                        request_resolved = true;
                                    }
                                    DataEventResult::Failed => {
                                        request_failed = true;
                                        request_resolved = true;
                                    }
                                    DataEventResult::Continue => {
                                        // Keep receiving data
                                    }
                                }
                            }
                        }
                        LinkEvent::Closed => {
                            log::info!("Link closed");
                            if !request_resolved {
                                eprintln!("Link closed before transfer completed");
                                request_failed = true;
                            }
                            request_resolved = true;
                        }
                        _ => {}
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                // Continue waiting
            }
        }
    }

    if !request_resolved {
        eprintln!("Fetch timed out");
        return 1;
    }

    if request_failed {
        return 1;
    }

    0
}

/// Handle a response event from the fetch request.
///
/// Returns Some(true) if the request failed, Some(false) if it succeeded,
/// or None if the response should be ignored (waiting for resource).
fn handle_response_event(response_data: &[u8]) -> Option<bool> {
    log::info!("Received response ({} bytes)", response_data.len());

    // Check for error codes
    // Response format is msgpack: [request_id, response_data]
    if response_data.len() >= 2 {
        // Simple check for error byte
        if response_data.contains(&REQ_FETCH_NOT_ALLOWED) {
            eprintln!("Fetch not allowed on remote");
            return Some(true);
        } else if response_data.contains(&0xc2) {
            // 0xc2 is msgpack false
            eprintln!("File not found on remote");
            return Some(true);
        }
    }

    None
}

/// Handle a resource advertisement event.
///
/// Creates a resource from the advertisement and requests the first batch of parts.
async fn handle_advertisement_event(
    transport: &Transport,
    link_id: &reticulum::destination::link::LinkId,
    payload: &[u8],
    silent: bool,
) -> Result<Resource, ()> {
    log::info!("Resource advertisement received ({} bytes)", payload.len());

    let adv = match ResourceAdvertisement::unpack(payload) {
        Ok(adv) => adv,
        Err(e) => {
            log::error!("Failed to parse advertisement: {:?}", e);
            return Err(());
        }
    };

    log::info!(
        "Resource: hash={}, size={}, parts={}",
        hex::encode(&adv.hash[..8]),
        adv.data_size,
        adv.num_parts
    );

    if !silent {
        println!("Receiving file ({} bytes)", adv.data_size);
    }

    let sdu = RETICULUM_MDU;
    let mut resource = match Resource::from_advertisement(&adv, sdu) {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to create resource: {:?}", e);
            return Err(());
        }
    };

    // Request first batch of parts
    if let Some(req_data) = resource.request_next() {
        transport.send_resource_request(link_id, &req_data).await;
    }

    Ok(resource)
}

/// Result of handling a resource data event.
enum DataEventResult {
    /// Transfer completed successfully.
    Complete,
    /// Transfer failed.
    Failed,
    /// More data expected.
    Continue,
}

/// Handle incoming resource data.
///
/// Processes the data, requests more parts if needed, and saves the file
/// when complete.
async fn handle_data_event(
    transport: &Transport,
    link_id: &reticulum::destination::link::LinkId,
    resource: &mut Resource,
    payload: &[u8],
    file_path_str: &str,
    output_dir: &Path,
    allow_overwrite: bool,
) -> DataEventResult {
    if !resource.receive_part(payload.to_vec()) {
        return DataEventResult::Continue;
    }

    let progress = resource.progress();
    log::info!(
        "Progress: {}/{}",
        progress.processed_parts,
        progress.total_parts
    );

    if !resource.is_complete() {
        // Request more parts
        if let Some(req_data) = resource.request_next() {
            transport.send_resource_request(link_id, &req_data).await;
        }
        return DataEventResult::Continue;
    }

    // Resource complete - finalize and save
    let Some(raw_data) = resource.get_raw_assembled_data() else {
        log::error!("Failed to get raw assembled data");
        return DataEventResult::Failed;
    };

    let decrypted_result = if resource.is_encrypted() {
        transport.decrypt_with_in_link(link_id, &raw_data).await
    } else {
        Ok(raw_data)
    };

    let decrypted = match decrypted_result {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to decrypt: {:?}", e);
            return DataEventResult::Failed;
        }
    };

    let data = match resource.finalize_assembly(decrypted) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to finalize: {:?}", e);
            return DataEventResult::Failed;
        }
    };

    // Extract filename from metadata or use requested path
    let filename = PathBuf::from(file_path_str)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("fetched_file")
        .to_string();

    let mut save_path = output_dir.join(&filename);

    if !allow_overwrite {
        let mut counter = 0;
        while save_path.exists() {
            counter += 1;
            save_path = output_dir.join(format!("{}.{}", filename, counter));
        }
    }

    match File::create(&save_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&data) {
                eprintln!("Failed to write file: {}", e);
                return DataEventResult::Failed;
            }

            println!("Saved {} ({} bytes)", save_path.display(), data.len());

            // Send proof using assembled data
            let proof = resource.generate_proof_with_data(&data);
            transport.send_resource_proof(link_id, &proof).await;
        }
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
            return DataEventResult::Failed;
        }
    }

    DataEventResult::Complete
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_req_fetch_not_allowed_constant() {
        assert_eq!(REQ_FETCH_NOT_ALLOWED, 0xF0);
    }

    #[test]
    fn test_handle_response_event_not_allowed() {
        // Response containing the not allowed byte
        let response = [0x00, REQ_FETCH_NOT_ALLOWED, 0x00];
        assert_eq!(handle_response_event(&response), Some(true));
    }

    #[test]
    fn test_handle_response_event_not_found() {
        // Response containing msgpack false (0xc2)
        let response = [0x00, 0xc2, 0x00];
        assert_eq!(handle_response_event(&response), Some(true));
    }

    #[test]
    fn test_handle_response_event_success() {
        // Response with success (msgpack true = 0xc3)
        let response = [0x00, 0xc3, 0x00];
        assert_eq!(handle_response_event(&response), None);
    }

    #[test]
    fn test_handle_response_event_empty() {
        // Empty response
        let response = [];
        assert_eq!(handle_response_event(&response), None);
    }

    #[test]
    fn test_filename_extraction_from_path() {
        let file_path_str = "/path/to/file.txt";
        let filename = PathBuf::from(file_path_str)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("fetched_file")
            .to_string();
        assert_eq!(filename, "file.txt");
    }

    #[test]
    fn test_filename_extraction_just_filename() {
        let file_path_str = "file.txt";
        let filename = PathBuf::from(file_path_str)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("fetched_file")
            .to_string();
        assert_eq!(filename, "file.txt");
    }

    #[test]
    fn test_output_dir_default() {
        let output_dir = PathBuf::from(".");
        assert_eq!(output_dir, PathBuf::from("."));
    }

    #[test]
    fn test_save_path_construction() {
        let output_dir = PathBuf::from("/tmp");
        let filename = "test.txt";
        let save_path = output_dir.join(filename);
        assert_eq!(save_path, PathBuf::from("/tmp/test.txt"));
    }

    #[test]
    fn test_save_path_with_counter() {
        let output_dir = PathBuf::from("/tmp");
        let filename = "test.txt";
        let counter = 1;
        let save_path = output_dir.join(format!("{}.{}", filename, counter));
        assert_eq!(save_path, PathBuf::from("/tmp/test.txt.1"));
    }
}
