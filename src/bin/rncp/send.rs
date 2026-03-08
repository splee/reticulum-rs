//! Send mode implementation for rncp.
//!
//! This module handles pushing files to a remote rncp listener.
//! It establishes a link, creates a resource from the file, and
//! transfers it to the destination.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::cli::format::format_hash;
use reticulum::destination::link::LinkEvent;
use reticulum::hash::AddressHash;
use reticulum::resource::ResourceConfig;
use reticulum::transport::{Link, Resource, Transport, TransportConfig};

use crate::config::{get_config_dir, get_identity_path, prepare_identity};
use crate::metadata::encode_filename_metadata;
use crate::progress::TransferProgress;
use crate::protocol::{
    setup_transport_interfaces, wait_for_announce, wait_for_link_activation, ProtocolError,
};
use crate::APP_NAME;

/// Context for sending resource parts in response to requests.
struct SendContext<'a> {
    transport: &'a Transport,
    link: &'a Link,
    link_id: &'a AddressHash,
    resource: &'a Resource,
    progress: &'a mut TransferProgress,
    total_parts: usize,
    parts_sent: &'a mut usize,
}

/// Handle a resource request event by sending requested parts.
///
/// Returns the number of parts sent, or None if the request failed.
async fn handle_resource_request(ctx: &mut SendContext<'_>, payload: &[u8]) -> Option<()> {
    log::info!("Received resource request ({} bytes)", payload.len());

    // Handle request and collect parts to send
    let (parts_to_send, hashmap_update) = {
        match ctx.resource.handle_request(payload) {
            Ok(result) => {
                let parts: Vec<_> = result.parts_to_send
                    .iter()
                    .filter_map(|&idx| {
                        ctx.resource
                            .get_part_data(idx)
                            .map(|d| (idx, d))
                    })
                    .collect();
                (parts, result.hashmap_update)
            }
            Err(e) => {
                log::error!("Failed to handle resource request: {:?}", e);
                return None;
            }
        }
    };

    // Send hashmap update if the receiver needs more hashmap entries
    if let Some(ref hmu_data) = hashmap_update {
        log::info!("Sending hashmap update ({} bytes)", hmu_data.len());
        ctx.transport.send_resource_hashmap_update(ctx.link_id, hmu_data).await;
    }

    // Send requested parts
    for (part_idx, part_data) in parts_to_send {
        let part_size = part_data.len();
        match ctx.link.send_resource_data(&part_data).await {
            Ok(()) => {
                *ctx.parts_sent += 1;

                ctx.progress.update(part_size);
                ctx.progress.display();

                log::debug!(
                    "Sent part {}/{}, total sent: {}",
                    part_idx,
                    ctx.total_parts,
                    *ctx.parts_sent
                );
            }
            Err(e) => {
                log::error!("Failed to send resource data packet: {:?}", e);
            }
        }
    }

    Some(())
}

/// Run rncp in send mode.
///
/// Sends a file to a remote rncp listener at the specified destination.
///
/// # Arguments
/// * `matches` - Command line arguments
/// * `timeout` - Operation timeout
/// * `running` - Atomic flag for graceful shutdown
///
/// # Returns
/// Exit code (0 for success, non-zero for errors)
pub async fn run_send_mode(
    matches: &clap::ArgMatches,
    timeout: Duration,
    running: Arc<AtomicBool>,
) -> i32 {
    let dest_hash_str = matches.get_one::<String>("destination").unwrap();
    let file_path_str = matches.get_one::<String>("file").unwrap();

    // Parse destination hash
    let dest_hash = match AddressHash::new_from_hex_string(dest_hash_str) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!(
                "Invalid destination hash: must be {} hexadecimal characters",
                32
            );
            log::error!("Invalid destination hash: {:?}", e);
            return 1;
        }
    };

    // Read file
    let file_path = PathBuf::from(file_path_str);
    if !file_path.exists() {
        eprintln!("File not found: {}", file_path.display());
        return 1;
    }

    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();

    let mut file = match File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Could not open file: {}", e);
            return 1;
        }
    };

    let mut file_data = Vec::new();
    if let Err(e) = file.read_to_end(&mut file_data) {
        eprintln!("Could not read file: {}", e);
        return 1;
    }

    log::info!("Sending file: {} ({} bytes)", filename, file_data.len());

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

    // Wait for announce from destination
    let mut announce_rx = transport.recv_announces().await;
    let dest_desc = match wait_for_announce(&mut announce_rx, &dest_hash, timeout, &running, false)
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
        wait_for_link_activation(&link, &link_id, &mut link_events, timeout, &running, false).await
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

    // Create metadata with filename
    let metadata = encode_filename_metadata(&filename);

    // Create resource
    let auto_compress = !matches.get_flag("no-compress");
    let config = ResourceConfig {
        auto_compress,
        ..ResourceConfig::default()
    };

    let mut rng = OsRng;
    let resource = match Resource::new(&mut rng, &file_data, config, Some(&metadata), None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to create resource: {:?}", e);
            return 1;
        }
    };

    let resource_hash_hex = hex::encode(&resource.hash()[..8]);
    println!(
        "Advertising file resource ({} parts)",
        resource.total_parts()
    );
    log::info!(
        "Resource created: hash={}, size={}, parts={}",
        resource_hash_hex,
        resource.total_size(),
        resource.total_parts()
    );

    // Create and send advertisement
    let advertisement = resource.create_advertisement();
    if let Err(e) = link.send_resource_advertisement(&advertisement, 0).await {
        eprintln!("Failed to send advertisement: {:?}", e);
        return 1;
    }
    log::info!("Sent resource advertisement");

    // Wait for resource requests and send parts
    let mut transfer_complete = false;
    let total_parts = resource.total_parts();
    let total_size = resource.total_size();
    let transfer_size = resource.progress().transfer_size;
    let mut parts_sent = 0usize;
    let silent = matches.get_flag("silent");
    let show_phy_rates = matches.get_flag("phy-rates");

    // Initialize progress tracker
    let mut progress = TransferProgress::new(total_size, transfer_size, silent, show_phy_rates);

    if !silent {
        println!("Transferring file...");
    }

    let deadline = tokio::time::Instant::now() + timeout;

    while tokio::time::Instant::now() < deadline
        && running.load(Ordering::SeqCst)
        && !transfer_complete
    {
        tokio::select! {
            Ok(event) = link_events.recv() => {
                if event.id == link_id {
                    match event.event {
                        LinkEvent::ResourceRequest(payload) => {
                            let mut send_ctx = SendContext {
                                transport: &transport,
                                link: &link,
                                link_id: &link_id,
                                resource: &resource,
                                progress: &mut progress,
                                total_parts,
                                parts_sent: &mut parts_sent,
                            };
                            handle_resource_request(&mut send_ctx, payload.as_slice())
                            .await;
                        }
                        LinkEvent::ResourceProof(payload) => {
                            log::info!("Received resource proof");

                            if resource.verify_proof(payload.as_slice()) {
                                progress.finish(true);
                                transfer_complete = true;
                            } else {
                                log::warn!("Invalid proof received");
                            }
                        }
                        LinkEvent::Closed => {
                            log::info!("Link closed");
                            if !transfer_complete {
                                progress.finish(false);
                                return 1;
                            }
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

    if !transfer_complete {
        progress.finish(false);
        eprintln!("Transfer timed out");
        return 1;
    }

    if !silent {
        println!(
            "{} copied to {}",
            file_path.display(),
            format_hash(dest_hash.as_slice())
        );
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_file_validation() {
        // Test with non-existent file
        let path = PathBuf::from("/nonexistent/path/file.txt");
        assert!(!path.exists());
    }

    #[test]
    fn test_file_reading() {
        // Create a temporary file
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = b"test content";
        temp_file.write_all(content).unwrap();

        // Read it back
        let mut file = File::open(temp_file.path()).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        assert_eq!(data, content);
    }

    #[test]
    fn test_filename_extraction() {
        let path = PathBuf::from("/path/to/file.txt");
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        assert_eq!(filename, "file.txt");
    }

    #[test]
    fn test_filename_extraction_no_extension() {
        let path = PathBuf::from("/path/to/file");
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        assert_eq!(filename, "file");
    }

    #[test]
    fn test_filename_extraction_fallback() {
        let path = PathBuf::from("/");
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        assert_eq!(filename, "file");
    }
}
