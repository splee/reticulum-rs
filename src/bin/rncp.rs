//! rncp - Reticulum Network Copy
//!
//! File copy utility over Reticulum network using Resource transfers.
//! Compatible with Python rncp.
//!
//! Modes:
//! - Listen mode (`-l`): Accept incoming file transfers
//! - Send mode (default): Push file to remote destination
//! - Fetch mode (`-f`): Pull file from remote listener

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Arg, ArgAction, Command};
use rand_core::OsRng;
use reticulum::destination::link::{LinkEvent, LinkEventData, LinkId, LinkStatus};
use reticulum::destination::DestinationName;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::packet::PACKET_MDU;
use reticulum::hash::Hash;
use reticulum::resource::{Resource, ResourceAdvertisement, ResourceConfig};
use reticulum::transport::{Transport, TransportConfig};
use rmpv::Value;
use tokio::sync::RwLock;

const APP_NAME: &str = "rncp";
const ASPECT_RECEIVE: &str = "receive";
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Spinner characters (matching Python's braille spinner)
const SPINNER_CHARS: &[char] = &['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];

/// Progress tracker for file transfers
struct TransferProgress {
    total_size: usize,
    transferred: usize,
    start_time: std::time::Instant,
    spinner_idx: usize,
    silent: bool,
}

impl TransferProgress {
    fn new(total_size: usize, silent: bool) -> Self {
        Self {
            total_size,
            transferred: 0,
            start_time: std::time::Instant::now(),
            spinner_idx: 0,
            silent,
        }
    }

    fn update(&mut self, bytes: usize) {
        self.transferred += bytes;
        self.spinner_idx = (self.spinner_idx + 1) % SPINNER_CHARS.len();
    }

    fn display(&self) {
        if self.silent {
            return;
        }

        let progress = if self.total_size > 0 {
            (self.transferred as f64 / self.total_size as f64) * 100.0
        } else {
            0.0
        };

        let elapsed = self.start_time.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 {
            self.transferred as f64 / elapsed
        } else {
            0.0
        };

        let spinner = SPINNER_CHARS[self.spinner_idx];

        // Use carriage return to overwrite line
        print!(
            "\r{} {:.1}%  {} / {}  {}/s   ",
            spinner,
            progress,
            size_str(self.transferred as u64, 'B'),
            size_str(self.total_size as u64, 'B'),
            size_str(speed as u64, 'B')
        );
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }

    fn finish(&self, success: bool) {
        if self.silent {
            return;
        }

        let elapsed = self.start_time.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 {
            self.transferred as f64 / elapsed
        } else {
            0.0
        };

        if success {
            println!(
                "\r✓ 100%  {} transferred in {:.1}s ({}/s)   ",
                size_str(self.transferred as u64, 'B'),
                elapsed,
                size_str(speed as u64, 'B')
            );
        } else {
            println!("\r✗ Transfer failed                         ");
        }
    }
}

/// Get the default Reticulum config directory
fn get_config_dir(config_override: Option<&str>) -> PathBuf {
    if let Some(path) = config_override {
        PathBuf::from(path)
    } else {
        // Default: ~/.reticulum
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".reticulum")
    }
}

/// Get the identity file path
fn get_identity_path(config_dir: &Path, identity_override: Option<&str>) -> PathBuf {
    if let Some(path) = identity_override {
        PathBuf::from(path)
    } else {
        config_dir.join("identities").join(APP_NAME)
    }
}

/// Load allowed identity hashes from config files
/// Checks: /etc/rncp/allowed_identities, ~/.config/rncp/allowed_identities, ~/.rncp/allowed_identities
fn load_allowed_identities() -> Vec<[u8; 16]> {
    let mut allowed = Vec::new();
    let allowed_file_name = "allowed_identities";

    // Possible config file locations (in order of precedence)
    let paths = [
        PathBuf::from("/etc/rncp").join(allowed_file_name),
        dirs::home_dir()
            .unwrap_or_default()
            .join(".config/rncp")
            .join(allowed_file_name),
        dirs::home_dir()
            .unwrap_or_default()
            .join(".rncp")
            .join(allowed_file_name),
    ];

    for path in &paths {
        if path.exists() {
            log::info!("Loading allowed identities from {}", path.display());
            if let Ok(contents) = std::fs::read_to_string(path) {
                for line in contents.lines() {
                    let line = line.trim();
                    // Skip comments and empty lines
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    // Parse hex hash (should be 32 hex chars = 16 bytes)
                    if line.len() == 32 {
                        if let Ok(bytes) = hex::decode(line) {
                            if bytes.len() == 16 {
                                let mut hash = [0u8; 16];
                                hash.copy_from_slice(&bytes);
                                allowed.push(hash);
                                log::debug!("Added allowed identity: {}", line);
                            }
                        }
                    }
                }
            }
            break; // Only use first found file
        }
    }

    allowed
}

/// Parse allowed identity hashes from CLI arguments
fn parse_allowed_from_cli(allowed_args: Option<clap::parser::ValuesRef<String>>) -> Vec<[u8; 16]> {
    let mut allowed = Vec::new();

    if let Some(hashes) = allowed_args {
        for hash_str in hashes {
            let hash_str = hash_str.trim();
            if hash_str.len() == 32 {
                if let Ok(bytes) = hex::decode(hash_str) {
                    if bytes.len() == 16 {
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&bytes);
                        allowed.push(hash);
                        log::debug!("Added allowed identity from CLI: {}", hash_str);
                    }
                }
            } else {
                eprintln!("Warning: Invalid identity hash '{}' (must be 32 hex chars)", hash_str);
            }
        }
    }

    allowed
}

/// Load or create an identity, persisting to file
fn prepare_identity(identity_path: &PathBuf) -> Result<PrivateIdentity, Box<dyn std::error::Error>> {
    // Try to load existing identity
    if identity_path.exists() {
        match std::fs::read_to_string(identity_path) {
            Ok(hex_string) => {
                let hex_string = hex_string.trim();
                match PrivateIdentity::new_from_hex_string(hex_string) {
                    Ok(identity) => {
                        log::info!(
                            "Loaded identity from {}",
                            identity_path.display()
                        );
                        return Ok(identity);
                    }
                    Err(e) => {
                        log::error!(
                            "Could not load identity from {}: {:?}",
                            identity_path.display(),
                            e
                        );
                        return Err(format!(
                            "Could not load identity for rncp. The identity file at \"{}\" may be corrupt or unreadable.",
                            identity_path.display()
                        ).into());
                    }
                }
            }
            Err(e) => {
                log::error!("Could not read identity file: {}", e);
                return Err(format!(
                    "Could not read identity file at \"{}\": {}",
                    identity_path.display(),
                    e
                ).into());
            }
        }
    }

    // Create new identity
    log::info!("No valid saved identity found, creating new...");
    let identity = PrivateIdentity::new_from_rand(OsRng);

    // Ensure parent directory exists
    if let Some(parent) = identity_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Save identity
    let hex_string = identity.to_hex_string();
    std::fs::write(identity_path, &hex_string)?;
    log::info!("Saved new identity to {}", identity_path.display());

    Ok(identity)
}

fn main() {
    let matches = Command::new("rncp")
        .version(VERSION)
        .about("Reticulum File Transfer Utility")
        // Positional arguments (matching Python)
        .arg(
            Arg::new("file")
                .help("file to be transferred")
                .index(1),
        )
        .arg(
            Arg::new("destination")
                .help("hexadecimal hash of the receiver")
                .index(2),
        )
        // Config options
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("path")
                .help("path to alternative Reticulum config directory"),
        )
        .arg(
            Arg::new("identity")
                .short('i')
                .value_name("identity")
                .help("path to identity to use"),
        )
        // Verbosity (matching Python: -v for verbose, -q for quiet)
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .help("increase verbosity"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(ArgAction::Count)
                .help("decrease verbosity"),
        )
        .arg(
            Arg::new("silent")
                .short('S')
                .long("silent")
                .action(ArgAction::SetTrue)
                .help("disable transfer progress output"),
        )
        // Mode flags
        .arg(
            Arg::new("listen")
                .short('l')
                .long("listen")
                .action(ArgAction::SetTrue)
                .help("listen for incoming transfer requests"),
        )
        .arg(
            Arg::new("fetch")
                .short('f')
                .long("fetch")
                .action(ArgAction::SetTrue)
                .help("fetch file from remote listener instead of sending"),
        )
        // Transfer options
        .arg(
            Arg::new("no-compress")
                .short('C')
                .long("no-compress")
                .action(ArgAction::SetTrue)
                .help("disable automatic compression"),
        )
        .arg(
            Arg::new("timeout")
                .short('w')
                .value_name("seconds")
                .help("sender timeout before giving up")
                .default_value("120"),
        )
        .arg(
            Arg::new("phy-rates")
                .short('P')
                .long("phy-rates")
                .action(ArgAction::SetTrue)
                .help("display physical layer transfer rates"),
        )
        // Fetch server options
        .arg(
            Arg::new("allow-fetch")
                .short('F')
                .long("allow-fetch")
                .action(ArgAction::SetTrue)
                .help("allow authenticated clients to fetch files"),
        )
        .arg(
            Arg::new("jail")
                .short('j')
                .long("jail")
                .value_name("path")
                .help("restrict fetch requests to specified path"),
        )
        // Save options
        .arg(
            Arg::new("save")
                .short('s')
                .long("save")
                .value_name("path")
                .help("save received files in specified path"),
        )
        .arg(
            Arg::new("overwrite")
                .short('O')
                .long("overwrite")
                .action(ArgAction::SetTrue)
                .help("allow overwriting received files, instead of adding postfix"),
        )
        // Announce options
        .arg(
            Arg::new("announce")
                .short('b')
                .value_name("seconds")
                .help("announce interval, 0 to only announce at startup")
                .default_value("-1"),
        )
        // Authentication options
        .arg(
            Arg::new("allowed")
                .short('a')
                .value_name("allowed_hash")
                .action(ArgAction::Append)
                .help("allow this identity (or add in ~/.rncp/allowed_identities)"),
        )
        .arg(
            Arg::new("no-auth")
                .short('n')
                .long("no-auth")
                .action(ArgAction::SetTrue)
                .help("accept requests from anyone"),
        )
        .arg(
            Arg::new("print-identity")
                .short('p')
                .long("print-identity")
                .action(ArgAction::SetTrue)
                .help("print identity and destination info and exit"),
        )
        // TCP interface (for testing without full Reticulum config)
        .arg(
            Arg::new("tcp-client")
                .long("tcp-client")
                .value_name("HOST:PORT")
                .help("connect to TCP interface"),
        )
        .arg(
            Arg::new("tcp-server")
                .long("tcp-server")
                .value_name("HOST:PORT")
                .help("listen on TCP interface"),
        )
        .get_matches();

    // Calculate log level from verbosity/quietness (matching Python: base level 3)
    let verbose_count = matches.get_count("verbose") as i32;
    let quiet_count = matches.get_count("quiet") as i32;
    let target_level = 3 + verbose_count - quiet_count;
    let log_filter = match target_level {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "info",
        4 => "debug",
        _ if target_level < 0 => "off",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_filter)).init();

    // Get timeout
    let timeout_secs: u64 = matches
        .get_one::<String>("timeout")
        .unwrap()
        .parse()
        .unwrap_or(120);
    let timeout = Duration::from_secs(timeout_secs);

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
        // Determine mode
        let listen_mode = matches.get_flag("listen") || matches.get_flag("print-identity");
        let fetch_mode = matches.get_flag("fetch");
        let has_file = matches.get_one::<String>("file").is_some();
        let has_dest = matches.get_one::<String>("destination").is_some();

        if listen_mode {
            run_listen_mode(&matches, timeout, running).await
        } else if fetch_mode {
            if has_dest && has_file {
                run_fetch_mode(&matches, timeout, running).await
            } else {
                println!();
                print_help();
                println!();
                0
            }
        } else if has_dest && has_file {
            run_send_mode(&matches, timeout, running).await
        } else {
            println!();
            print_help();
            println!();
            0
        }
    });

    std::process::exit(exit_code);
}

/// Print usage help (matching Python's format)
fn print_help() {
    eprintln!("Usage: rncp [OPTIONS] [FILE] [DESTINATION]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  rncp -l                     Listen for incoming files");
    eprintln!("  rncp file.txt <dest_hash>   Send file to destination");
    eprintln!("  rncp -f path <dest_hash>    Fetch file from remote");
    eprintln!();
    eprintln!("Run 'rncp --help' for full options.");
}

/// Format bytes as pretty hex (matching Python's RNS.prettyhexrep)
fn pretty_hex(bytes: &[u8]) -> String {
    format!("<{}>", hex::encode(bytes))
}

/// Format file size with appropriate unit (matching Python's size_str)
#[allow(dead_code)]
fn size_str(num: u64, suffix: char) -> String {
    let mut num = num as f64;
    if suffix == 'b' {
        num *= 8.0;
    }
    let units = ['K', 'M', 'G', 'T', 'P', 'E', 'Z'];

    if num < 1000.0 {
        return format!("{:.0} {}", num, suffix.to_ascii_uppercase());
    }

    for unit in units {
        num /= 1000.0;
        if num < 1000.0 {
            return format!("{:.2} {}{}", num, unit, suffix.to_ascii_uppercase());
        }
    }

    format!("{:.2} Y{}", num, suffix.to_ascii_uppercase())
}

/// Tracked incoming resource with its link
struct TrackedIncomingResource {
    resource: Resource,
    link_id: LinkId,
    has_metadata: bool,
}

/// Tracked outgoing resource for fetch server
struct TrackedOutgoingResource {
    resource: Resource,
    link_id: LinkId,
}

/// Path hash for "fetch_file" request handler (pre-computed truncated hash)
fn fetch_file_path_hash() -> [u8; 10] {
    truncated_hash(b"fetch_file")
}

/// Configuration for listen mode fetch server
struct FetchServerConfig {
    allow_fetch: bool,
    #[allow(dead_code)]
    no_auth: bool,
    fetch_jail: Option<PathBuf>,
    #[allow(dead_code)]
    allowed_identity_hashes: Vec<[u8; 16]>,
    auto_compress: bool,
}

/// Listen mode - accept incoming file transfers
async fn run_listen_mode(
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
    let mut transport = Transport::new(TransportConfig::new(APP_NAME, &identity, false));

    // Set up TCP interfaces if specified
    if let Some(server_addr) = matches.get_one::<String>("tcp-server") {
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

    if let Some(client_addr) = matches.get_one::<String>("tcp-client") {
        log::info!("Connecting TCP client to {}", client_addr);
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(client_addr), TcpClient::spawn);
    }

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
        println!("Listening on : {}", pretty_hex(dest_hash.as_slice()));
        return 0;
    }

    println!("rncp listening on {}", pretty_hex(dest_hash.as_slice()));

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
            if allowed_identity_hashes.len() == 1 { "y" } else { "ies" }
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

/// Handle a link event in listen mode
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
            ).await;
        }
        LinkEvent::ResourceRequest(payload) => {
            // Handle resource request from fetch client
            handle_outgoing_resource_request(
                transport,
                &link_id,
                payload.as_slice(),
                outgoing_resources,
            ).await;
        }
        LinkEvent::ResourceAdvertisement(payload) => {
            log::info!(
                "Resource advertisement received ({} bytes)",
                payload.len()
            );

            // Parse the advertisement
            match ResourceAdvertisement::unpack(payload.as_slice()) {
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
                    let sdu = PACKET_MDU - 64;
                    let has_metadata = adv.flags.has_metadata;

                    match Resource::from_advertisement(&adv, sdu) {
                        Ok(mut resource) => {
                            let truncated_hash = *resource.truncated_hash();

                            // Request the first batch of parts
                            if let Some(request_data) = resource.request_next() {
                                log::info!(
                                    "Sending resource request ({} bytes)",
                                    request_data.len()
                                );

                                if transport.send_resource_request(&link_id, &request_data).await {
                                    // Store the resource for tracking
                                    incoming_resources.write().await.insert(
                                        truncated_hash,
                                        TrackedIncomingResource {
                                            resource,
                                            link_id,
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
        LinkEvent::ResourceData(payload) => {
            log::debug!("Resource data received ({} bytes)", payload.len());

            let mut resources = incoming_resources.write().await;
            let mut completed_hash: Option<[u8; 16]> = None;
            let mut needs_more_request: Option<([u8; 16], Vec<u8>)> = None;

            for (hash, tracked) in resources.iter_mut() {
                if tracked.link_id == link_id
                    && tracked.resource.receive_part(payload.as_slice().to_vec()) {
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
                    let mut resource = tracked.resource;
                    let has_metadata = tracked.has_metadata;

                    // Get raw assembled data
                    if let Some(raw_data) = resource.get_raw_assembled_data() {
                        // Decrypt the assembled data using the link's key
                        let decrypted_result = if resource.is_encrypted() {
                            transport.decrypt_with_in_link(&link_id, &raw_data).await
                        } else {
                            Ok(raw_data)
                        };

                        match decrypted_result {
                            Ok(decrypted_data) => {
                                match resource.finalize_assembly(decrypted_data) {
                                    Ok(assembled_data) => {
                                        // Extract filename and actual file data from assembled data
                                        let (filename_opt, file_data) = extract_filename_and_data(
                                            &assembled_data,
                                            has_metadata
                                        );

                                        let filename = filename_opt.unwrap_or_else(|| format!(
                                            "received_{}",
                                            hex::encode(&hash[..4])
                                        ));

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
                                                save_path = output_dir.join(format!(
                                                    "{}.{}",
                                                    filename, counter
                                                ));
                                            }
                                        }

                                        match File::create(&save_path) {
                                            Ok(mut file) => {
                                                if let Err(e) = file.write_all(&file_data) {
                                                    log::error!(
                                                        "Failed to write file: {}",
                                                        e
                                                    );
                                                } else {
                                                    println!(
                                                        "Saved to: {}",
                                                        save_path.display()
                                                    );

                                                    // Send proof using the assembled data
                                                    let proof = resource.generate_proof_with_data(&assembled_data);
                                                    transport
                                                        .send_resource_proof(&link_id, &proof)
                                                        .await;
                                                    log::info!("Sent resource proof");
                                                }
                                            }
                                            Err(e) => {
                                                log::error!(
                                                    "Failed to create file: {}",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::error!("Failed to finalize assembly: {:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Failed to decrypt resource: {:?}", e);
                            }
                        }
                    } else {
                        log::error!("Failed to get raw assembled data");
                    }
                }
            }

            // Request more parts if needed
            if let Some((hash, request_data)) = needs_more_request {
                log::debug!(
                    "Requesting more parts for {}",
                    hex::encode(&hash[..8])
                );
                transport.send_resource_request(&link_id, &request_data).await;
            }
        }
        LinkEvent::Closed => {
            log::info!("Link {} closed", link_id_hex);
        }
        _ => {}
    }
}

/// Extract filename from resource data
/// The assembled data may contain metadata with a 3-byte length prefix:
/// [len_high, len_mid, len_low, ...metadata..., ...actual_data...]
/// Metadata format (msgpack): {"name": <bytes>}
/// Returns (filename_option, actual_data_without_metadata)
fn extract_filename_and_data(data: &[u8], has_metadata: bool) -> (Option<String>, Vec<u8>) {
    if !has_metadata || data.len() < 4 {
        return (None, data.to_vec());
    }

    // Extract metadata length (3-byte big-endian)
    let meta_len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

    if data.len() < 3 + meta_len {
        log::debug!("Data too short for metadata of length {}", meta_len);
        return (None, data.to_vec());
    }

    let metadata = &data[3..3 + meta_len];
    let actual_data = data[3 + meta_len..].to_vec();

    // Parse msgpack metadata
    let filename = parse_metadata_filename(metadata);

    (filename, actual_data)
}

/// Parse msgpack metadata and extract the "name" field
fn parse_metadata_filename(metadata: &[u8]) -> Option<String> {
    let value = rmpv::decode::read_value(&mut &metadata[..]).ok()?;

    // Look for "name" key in the map
    match value {
        Value::Map(entries) => {
            for (key, val) in entries {
                let key_str = match key {
                    Value::String(s) => s.as_str().map(|s| s.to_string()),
                    Value::Binary(b) => String::from_utf8(b.clone()).ok(),
                    _ => None,
                };

                if key_str.as_deref() == Some("name") {
                    // Extract filename from value
                    let filename = match val {
                        Value::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                        Value::String(s) => s.as_str().unwrap_or("").to_string(),
                        _ => continue,
                    };

                    // Sanitize: only keep the basename to prevent path traversal
                    let basename = std::path::Path::new(&filename)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("received_file")
                        .to_string();

                    return Some(basename);
                }
            }
            None
        }
        _ => None,
    }
}

/// Parse a fetch_file request and extract the file path
/// Request format (msgpack): [timestamp: f64, path_hash: bin10, data: bin]
fn parse_fetch_request(payload: &[u8]) -> Option<String> {
    let value = rmpv::decode::read_value(&mut &payload[..]).ok()?;

    let arr = match value {
        Value::Array(a) if a.len() >= 3 => a,
        _ => return None,
    };

    // Verify this is a fetch_file request by checking path hash
    let expected_hash = fetch_file_path_hash();
    let path_hash = match &arr[1] {
        Value::Binary(b) if b.len() == 10 => b.as_slice(),
        _ => return None,
    };

    if path_hash != expected_hash {
        log::debug!(
            "Request path hash mismatch: expected {}, got {}",
            hex::encode(expected_hash),
            hex::encode(path_hash)
        );
        return None;
    }

    // Extract file path from data field
    let file_path = match &arr[2] {
        Value::Binary(b) => String::from_utf8_lossy(b).to_string(),
        Value::String(s) => s.as_str().unwrap_or("").to_string(),
        _ => return None,
    };

    Some(file_path)
}

/// Validate a file path against the fetch jail
fn validate_fetch_path(path_str: &str, jail: Option<&PathBuf>) -> Option<PathBuf> {
    // Expand and canonicalize the path
    let expanded = if path_str.starts_with('~') {
        dirs::home_dir()
            .map(|h| h.join(&path_str[2..]))
            .unwrap_or_else(|| PathBuf::from(path_str))
    } else {
        PathBuf::from(path_str)
    };

    // If there's a jail, handle paths relative to it
    let file_path = if let Some(jail) = jail {
        // Strip jail prefix if present, then join with jail
        let stripped = if path_str.starts_with(jail.to_str().unwrap_or("")) {
            PathBuf::from(path_str.strip_prefix(jail.to_str().unwrap_or("")).unwrap_or(path_str).trim_start_matches('/'))
        } else {
            expanded.clone()
        };

        let joined = jail.join(&stripped);

        // Canonicalize to resolve symlinks
        match std::fs::canonicalize(&joined) {
            Ok(canonical) => {
                // Verify the resolved path is still within jail
                if canonical.starts_with(jail) {
                    canonical
                } else {
                    log::warn!(
                        "Fetch request for {} resolved to {} which is outside jail {}",
                        path_str,
                        canonical.display(),
                        jail.display()
                    );
                    return None;
                }
            }
            Err(e) => {
                log::debug!("Failed to canonicalize path {}: {}", joined.display(), e);
                return None;
            }
        }
    } else {
        // No jail, just use the expanded path
        match std::fs::canonicalize(&expanded) {
            Ok(canonical) => canonical,
            Err(_) => expanded,
        }
    };

    // Verify the file exists
    if !file_path.is_file() {
        log::debug!("Requested file does not exist: {}", file_path.display());
        return None;
    }

    Some(file_path)
}

/// Send a response to a request (for error codes)
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

/// Handle a fetch file request
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

    log::info!("Fetch request received on link {} ({} bytes)", link_id_hex, payload.len());

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
            if let Some(link_mutex) = transport.find_in_link(link_id).await {
                let link = link_mutex.lock().await;
                // Encode msgpack false (0xc2)
                if let Ok(packet) = link.response_packet(&[0xc2]) {
                    transport.send_packet(packet).await;
                }
            }
            return;
        }
    };

    // Read the file
    let file_data = match std::fs::read(&file_path) {
        Ok(data) => data,
        Err(e) => {
            log::error!("Failed to read file {}: {}", file_path.display(), e);
            if let Some(link_mutex) = transport.find_in_link(link_id).await {
                let link = link_mutex.lock().await;
                if let Ok(packet) = link.response_packet(&[0xc2]) {
                    transport.send_packet(packet).await;
                }
            }
            return;
        }
    };

    log::info!("Sending file {} ({} bytes) to client", file_path.display(), file_data.len());

    // Create metadata with filename (msgpack format matching Python)
    let filename = file_path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();

    // Create metadata (msgpack format matching Python)
    // Python uses: {"name": filename.encode("utf-8")} - note: bytes value, not string
    let mut metadata = Vec::new();
    metadata.push(0x81); // fixmap with 1 element
    metadata.push(0xa4); // fixstr with 4 chars ("name" key is a string)
    metadata.extend_from_slice(b"name");
    // Value is bytes (bin format), not string
    let name_bytes = filename.as_bytes();
    if name_bytes.len() < 256 {
        metadata.push(0xc4); // bin 8
        metadata.push(name_bytes.len() as u8);
    } else {
        metadata.push(0xc5); // bin 16
        metadata.push((name_bytes.len() >> 8) as u8);
        metadata.push(name_bytes.len() as u8);
    }
    metadata.extend_from_slice(name_bytes);

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
                if let Some(link_mutex) = transport.find_in_link(link_id).await {
                    let link = link_mutex.lock().await;
                    // Encode msgpack true (0xc3)
                    if let Ok(packet) = link.response_packet(&[0xc3]) {
                        transport.send_packet(packet).await;
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to send resource advertisement: {:?}", e);
            }
        }
    }
}

/// Handle resource request for outgoing resources (fetch server sending file parts)
async fn handle_outgoing_resource_request(
    transport: &Transport,
    link_id: &LinkId,
    payload: &[u8],
    outgoing_resources: &Arc<RwLock<HashMap<[u8; 16], TrackedOutgoingResource>>>,
) {
    let link_id_hex = hex::encode(&link_id.as_slice()[..8]);
    log::debug!("Resource request received on link {} ({} bytes)", link_id_hex, payload.len());

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

/// Send mode - send a file to a remote destination
async fn run_send_mode(
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
    if let Some(server_addr) = matches.get_one::<String>("tcp-server") {
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

    if let Some(client_addr) = matches.get_one::<String>("tcp-client") {
        log::info!("Connecting TCP client to {}", client_addr);
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(client_addr), TcpClient::spawn);
    }

    // Give interfaces time to connect
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Wait for announce from destination
    println!(
        "Path to {} requested",
        pretty_hex(dest_hash.as_slice())
    );

    let deadline = tokio::time::Instant::now() + timeout;
    let mut announce_rx = transport.recv_announces().await;
    let mut dest_desc = None;

    while tokio::time::Instant::now() < deadline && running.load(Ordering::SeqCst) {
        tokio::select! {
            Ok(event) = announce_rx.recv() => {
                let announced_hash = event.destination.lock().await.desc.address_hash;
                if announced_hash == dest_hash {
                    log::info!("Received announce from target destination");
                    dest_desc = Some(event.destination.lock().await.desc);
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Continue waiting
            }
        }
    }

    let dest_desc = match dest_desc {
        Some(d) => d,
        None => {
            eprintln!("Path not found");
            return 1;
        }
    };

    // Create link
    println!(
        "Establishing link with {}",
        pretty_hex(dest_hash.as_slice())
    );

    let mut link_events = transport.out_link_events();
    let link = transport.link(dest_desc).await;
    let link_id = *link.lock().await.id();
    let link_id_hex = hex::encode(&link_id.as_slice()[..8]);

    // Wait for link activation
    let mut link_activated = false;
    while tokio::time::Instant::now() < deadline && running.load(Ordering::SeqCst) {
        tokio::select! {
            Ok(event) = link_events.recv() => {
                if event.id == link_id {
                    match event.event {
                        LinkEvent::Activated => {
                            link_activated = true;
                            log::info!("Link {} activated", link_id_hex);
                            break;
                        }
                        LinkEvent::Closed => {
                            eprintln!("Link establishment failed");
                            return 1;
                        }
                        _ => {}
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if link.lock().await.status() == LinkStatus::Active {
                    link_activated = true;
                    log::info!("Link {} activated", link_id_hex);
                    break;
                }
            }
        }
    }

    if !link_activated {
        eprintln!("Link establishment timed out");
        return 1;
    }

    // Create metadata (msgpack format matching Python)
    // Python uses: {"name": filename.encode("utf-8")} - note: bytes value, not string
    let mut metadata = Vec::new();
    metadata.push(0x81); // fixmap with 1 element
    metadata.push(0xa4); // fixstr with 4 chars ("name" key is a string)
    metadata.extend_from_slice(b"name");
    // Value is bytes (bin format), not string
    let name_bytes = filename.as_bytes();
    if name_bytes.len() < 256 {
        metadata.push(0xc4); // bin 8
        metadata.push(name_bytes.len() as u8);
    } else {
        metadata.push(0xc5); // bin 16
        metadata.push((name_bytes.len() >> 8) as u8);
        metadata.push(name_bytes.len() as u8);
    }
    metadata.extend_from_slice(name_bytes);

    // Create resource
    let auto_compress = !matches.get_flag("no-compress");
    let config = ResourceConfig {
        auto_compress,
        ..ResourceConfig::default()
    };

    let mut rng = OsRng;
    let resource = match Resource::new(&mut rng, &file_data, config, Some(&metadata)) {
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
    {
        let link_guard = link.lock().await;
        match link_guard.resource_advertisement_packet(&advertisement, 0) {
            Ok(packet) => {
                drop(link_guard);
                transport.send_packet(packet).await;
                log::info!("Sent resource advertisement");
            }
            Err(e) => {
                eprintln!("Failed to send advertisement: {:?}", e);
                return 1;
            }
        }
    }

    // Store resource for handling requests
    let resource = Arc::new(tokio::sync::Mutex::new(resource));

    // Wait for resource requests and send parts
    let mut transfer_complete = false;
    let total_parts = resource.lock().await.total_parts();
    let total_size = resource.lock().await.total_size();
    let mut parts_sent = 0usize;
    let silent = matches.get_flag("silent");

    // Initialize progress tracker
    let mut progress = TransferProgress::new(total_size, silent);

    if !silent {
        println!("Transferring file...");
    }

    while tokio::time::Instant::now() < deadline
        && running.load(Ordering::SeqCst)
        && !transfer_complete
    {
        tokio::select! {
            Ok(event) = link_events.recv() => {
                if event.id == link_id {
                    match event.event {
                        LinkEvent::ResourceRequest(payload) => {
                            log::info!(
                                "Received resource request ({} bytes)",
                                payload.len()
                            );

                            let mut resource_guard = resource.lock().await;
                            match resource_guard.handle_request(payload.as_slice()) {
                                Ok((_wants_more_hashmap, part_indices)) => {
                                    // Collect parts to send
                                    let parts_to_send: Vec<_> = part_indices
                                        .iter()
                                        .filter_map(|&idx| {
                                            resource_guard
                                                .get_part_data(idx)
                                                .map(|d| (idx, d.to_vec()))
                                        })
                                        .collect();
                                    drop(resource_guard);

                                    // Send requested parts
                                    for (part_idx, part_data) in parts_to_send {
                                        let part_size = part_data.len();
                                        let link_guard = link.lock().await;
                                        match link_guard.resource_data_packet(&part_data) {
                                            Ok(packet) => {
                                                drop(link_guard);
                                                transport.send_packet(packet).await;
                                                parts_sent += 1;

                                                // Update progress
                                                progress.update(part_size);
                                                progress.display();

                                                log::debug!(
                                                    "Sent part {}/{}, total sent: {}",
                                                    part_idx,
                                                    total_parts,
                                                    parts_sent
                                                );
                                            }
                                            Err(e) => {
                                                log::error!(
                                                    "Failed to create resource data packet: {:?}",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!("Failed to handle resource request: {:?}", e);
                                }
                            }
                        }
                        LinkEvent::ResourceProof(payload) => {
                            log::info!("Received resource proof");

                            let resource_guard = resource.lock().await;
                            if resource_guard.verify_proof(payload.as_slice()) {
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
            pretty_hex(dest_hash.as_slice())
        );
    }

    0
}

/// Response codes from fetch requests (matching Python)
const REQ_FETCH_NOT_ALLOWED: u8 = 0xF0;

/// Create a truncated hash (10 bytes) of data, matching Python's Identity.truncated_hash
fn truncated_hash(data: &[u8]) -> [u8; 10] {
    let full_hash = Hash::new_from_slice(data);
    let mut truncated = [0u8; 10];
    truncated.copy_from_slice(&full_hash.as_bytes()[..10]);
    truncated
}

/// Create a msgpack-encoded request packet data
/// Format: [timestamp, path_hash, request_data]
fn create_request_data(path: &str, data: &[u8]) -> Vec<u8> {
    let path_hash = truncated_hash(path.as_bytes());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    // Manually encode msgpack array
    // Format: [timestamp (float64), path_hash (bin 10), data (bin)]
    let mut result = Vec::new();

    // Array with 3 elements (fixarray)
    result.push(0x93);

    // Timestamp as float64
    result.push(0xcb);
    result.extend_from_slice(&timestamp.to_be_bytes());

    // Path hash as bin 8 (10 bytes)
    result.push(0xc4);
    result.push(10);
    result.extend_from_slice(&path_hash);

    // Data as bin 8 or bin 16
    if data.len() < 256 {
        result.push(0xc4);
        result.push(data.len() as u8);
    } else {
        result.push(0xc5);
        result.extend_from_slice(&(data.len() as u16).to_be_bytes());
    }
    result.extend_from_slice(data);

    result
}

/// Fetch mode - pull a file from a remote listener
async fn run_fetch_mode(
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
    if let Some(server_addr) = matches.get_one::<String>("tcp-server") {
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

    if let Some(client_addr) = matches.get_one::<String>("tcp-client") {
        log::info!("Connecting TCP client to {}", client_addr);
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(client_addr), TcpClient::spawn);
    }

    // Give interfaces time to connect
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Output directory
    let output_dir = matches
        .get_one::<String>("save")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let allow_overwrite = matches.get_flag("overwrite");

    // Wait for announce from destination
    if !silent {
        println!(
            "Path to {} requested",
            pretty_hex(dest_hash.as_slice())
        );
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let mut announce_rx = transport.recv_announces().await;
    let mut dest_desc = None;

    while tokio::time::Instant::now() < deadline && running.load(Ordering::SeqCst) {
        tokio::select! {
            Ok(event) = announce_rx.recv() => {
                let announced_hash = event.destination.lock().await.desc.address_hash;
                if announced_hash == dest_hash {
                    log::info!("Received announce from target destination");
                    dest_desc = Some(event.destination.lock().await.desc);
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Continue waiting
            }
        }
    }

    let dest_desc = match dest_desc {
        Some(d) => d,
        None => {
            eprintln!("Path not found");
            return 1;
        }
    };

    // Create link
    if !silent {
        println!(
            "Establishing link with {}",
            pretty_hex(dest_hash.as_slice())
        );
    }

    let mut link_events = transport.out_link_events();
    let link = transport.link(dest_desc).await;
    let link_id = *link.lock().await.id();
    let link_id_hex = hex::encode(&link_id.as_slice()[..8]);

    // Wait for link activation
    let mut link_activated = false;
    while tokio::time::Instant::now() < deadline && running.load(Ordering::SeqCst) {
        tokio::select! {
            Ok(event) = link_events.recv() => {
                if event.id == link_id {
                    match event.event {
                        LinkEvent::Activated => {
                            link_activated = true;
                            log::info!("Link {} activated", link_id_hex);
                            break;
                        }
                        LinkEvent::Closed => {
                            eprintln!("Link establishment failed");
                            return 1;
                        }
                        _ => {}
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if link.lock().await.status() == LinkStatus::Active {
                    link_activated = true;
                    log::info!("Link {} activated", link_id_hex);
                    break;
                }
            }
        }
    }

    if !link_activated {
        eprintln!("Link establishment timed out");
        return 1;
    }

    // Send fetch request
    if !silent {
        println!("Requesting file: {}", file_path_str);
    }

    let request_data = create_request_data("fetch_file", file_path_str.as_bytes());
    {
        let link_guard = link.lock().await;
        match link_guard.request_packet(&request_data) {
            Ok(packet) => {
                drop(link_guard);
                transport.send_packet(packet).await;
                log::info!("Sent fetch request");
            }
            Err(e) => {
                eprintln!("Failed to send fetch request: {:?}", e);
                return 1;
            }
        }
    }

    // Track incoming resource
    let mut incoming_resource: Option<Resource> = None;
    let mut request_resolved = false;
    let mut request_failed = false;

    // Wait for response (either error code or resource transfer)
    while tokio::time::Instant::now() < deadline
        && running.load(Ordering::SeqCst)
        && !request_resolved
    {
        tokio::select! {
            Ok(event) = link_events.recv() => {
                if event.id == link_id {
                    match event.event {
                        LinkEvent::Response(payload) => {
                            // Parse response - could be error code
                            let response_data = payload.as_slice();
                            log::info!("Received response ({} bytes)", response_data.len());

                            // Check for error codes
                            // Response format is msgpack: [request_id, response_data]
                            if response_data.len() >= 2 {
                                // Simple check for error byte
                                if response_data.contains(&REQ_FETCH_NOT_ALLOWED) {
                                    eprintln!("Fetch not allowed on remote");
                                    request_failed = true;
                                    request_resolved = true;
                                } else if response_data.contains(&0xc2) {
                                    // 0xc2 is msgpack false
                                    eprintln!("File not found on remote");
                                    request_failed = true;
                                    request_resolved = true;
                                }
                            }
                        }
                        LinkEvent::ResourceAdvertisement(payload) => {
                            log::info!(
                                "Resource advertisement received ({} bytes)",
                                payload.len()
                            );

                            match ResourceAdvertisement::unpack(payload.as_slice()) {
                                Ok(adv) => {
                                    log::info!(
                                        "Resource: hash={}, size={}, parts={}",
                                        hex::encode(&adv.hash[..8]),
                                        adv.data_size,
                                        adv.num_parts
                                    );

                                    if !silent {
                                        println!(
                                            "Receiving file ({} bytes)",
                                            adv.data_size
                                        );
                                    }

                                    let sdu = PACKET_MDU - 64;
                                    match Resource::from_advertisement(&adv, sdu) {
                                        Ok(mut resource) => {
                                            // Request first batch of parts
                                            if let Some(req_data) = resource.request_next() {
                                                transport.send_resource_request(&link_id, &req_data).await;
                                            }
                                            incoming_resource = Some(resource);
                                        }
                                        Err(e) => {
                                            log::error!("Failed to create resource: {:?}", e);
                                            request_failed = true;
                                            request_resolved = true;
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!("Failed to parse advertisement: {:?}", e);
                                }
                            }
                        }
                        LinkEvent::ResourceData(payload) => {
                            if let Some(ref mut resource) = incoming_resource {
                                if resource.receive_part(payload.as_slice().to_vec()) {
                                    let progress = resource.progress();
                                    log::info!(
                                        "Progress: {}/{}",
                                        progress.processed_parts,
                                        progress.total_parts
                                    );

                                    if resource.is_complete() {
                                        // Resource complete - finalize and save
                                        if let Some(raw_data) = resource.get_raw_assembled_data() {
                                            let decrypted_result = if resource.is_encrypted() {
                                                transport.decrypt_with_in_link(&link_id, &raw_data).await
                                            } else {
                                                Ok(raw_data)
                                            };

                                            match decrypted_result {
                                                Ok(decrypted) => {
                                                    match resource.finalize_assembly(decrypted) {
                                                        Ok(data) => {
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
                                                                    save_path = output_dir.join(format!(
                                                                        "{}.{}",
                                                                        filename, counter
                                                                    ));
                                                                }
                                                            }

                                                            match File::create(&save_path) {
                                                                Ok(mut file) => {
                                                                    if let Err(e) = file.write_all(&data) {
                                                                        eprintln!("Failed to write file: {}", e);
                                                                        request_failed = true;
                                                                    } else {
                                                                        println!(
                                                                            "Saved {} ({} bytes)",
                                                                            save_path.display(),
                                                                            data.len()
                                                                        );

                                                                        // Send proof using assembled data
                                                                        let proof = resource.generate_proof_with_data(&data);
                                                                        transport.send_resource_proof(&link_id, &proof).await;
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    eprintln!("Failed to create file: {}", e);
                                                                    request_failed = true;
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            eprintln!("Failed to finalize: {:?}", e);
                                                            request_failed = true;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    eprintln!("Failed to decrypt: {:?}", e);
                                                    request_failed = true;
                                                }
                                            }
                                        }
                                        request_resolved = true;
                                    } else if let Some(req_data) = resource.request_next() {
                                        transport.send_resource_request(&link_id, &req_data).await;
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
