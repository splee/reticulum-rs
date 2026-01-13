//! Reticulum Network Status
//!
//! Display network status, interfaces, paths, and links. This utility connects
//! to a running Reticulum instance (or initializes its own) to display network
//! status information.

use std::fs;
use std::io::{self, Read as IoRead, Write as IoWrite};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest as Sha2Digest};

use reticulum::config::{LogLevel, ReticulumConfig};
use reticulum::destination::{DestinationName, SingleOutputDestination};
use reticulum::destination::link::{LinkEvent, LinkStatus};
use reticulum::destination::request::RequestRouter;
use reticulum::hash::{AddressHash, Hash};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::ipc::addr::{IpcListener, ListenerAddr};
use reticulum::ipc::{LocalClientInterface, LocalServerInterface};
use reticulum::logging;
use reticulum::rpc::RpcClient;
use reticulum::transport::{Transport, TransportConfig};

/// Interface mode constants matching Python implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum InterfaceMode {
    #[default]
    Full = 0x00,
    AccessPoint = 0x01,
    PointToPoint = 0x02,
    Roaming = 0x03,
    Boundary = 0x04,
    Gateway = 0x05,
}


impl InterfaceMode {
    /// Convert mode to display string
    pub fn as_str(&self) -> &'static str {
        match self {
            InterfaceMode::Full => "Full",
            InterfaceMode::AccessPoint => "Access Point",
            InterfaceMode::PointToPoint => "Point-to-Point",
            InterfaceMode::Roaming => "Roaming",
            InterfaceMode::Boundary => "Boundary",
            InterfaceMode::Gateway => "Gateway",
        }
    }
}

impl From<u8> for InterfaceMode {
    fn from(value: u8) -> Self {
        match value {
            0x01 => InterfaceMode::AccessPoint,
            0x02 => InterfaceMode::PointToPoint,
            0x03 => InterfaceMode::Roaming,
            0x04 => InterfaceMode::Boundary,
            0x05 => InterfaceMode::Gateway,
            _ => InterfaceMode::Full,
        }
    }
}

/// Statistics for a single interface
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceStats {
    /// Full interface name (e.g., "TCPInterface[hostname:port]")
    pub name: String,
    /// Short interface name
    pub short_name: String,
    /// Interface hash (hex string)
    pub hash: String,
    /// Interface type name
    #[serde(rename = "type")]
    pub interface_type: String,
    /// Bytes received
    pub rxb: u64,
    /// Bytes transmitted
    pub txb: u64,
    /// Current receive speed (bytes/sec)
    #[serde(default)]
    pub rxs: f64,
    /// Current transmit speed (bytes/sec)
    #[serde(default)]
    pub txs: f64,
    /// Interface online status
    pub status: bool,
    /// Interface mode
    pub mode: u8,
    /// Number of connected clients (for server interfaces)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<u32>,
    /// Interface bitrate in bits per second
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitrate: Option<u64>,
    /// Incoming announce frequency
    #[serde(default)]
    pub incoming_announce_frequency: f64,
    /// Outgoing announce frequency
    #[serde(default)]
    pub outgoing_announce_frequency: f64,
    /// Number of held announces
    #[serde(default)]
    pub held_announces: u32,
    /// Number of queued announces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announce_queue: Option<u32>,
    /// IFAC signature (for access controlled interfaces)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_signature: Option<String>,
    /// IFAC size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_size: Option<u8>,
    /// IFAC network name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_netname: Option<String>,
    /// Parent interface name (for derived interfaces)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_interface_name: Option<String>,
    /// Parent interface hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_interface_hash: Option<String>,
    /// Autoconnect source interface name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autoconnect_source: Option<String>,
    /// Number of reachable peers (for mesh interfaces)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<u32>,
    /// I2P connectable status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i2p_connectable: Option<bool>,
    /// I2P Base32 address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i2p_b32: Option<String>,
    /// I2P tunnel state description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnelstate: Option<String>,
    /// Short-term airtime percentage (15s)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub airtime_short: Option<f32>,
    /// Long-term airtime percentage (1h)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub airtime_long: Option<f32>,
    /// Short-term channel load percentage (15s)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_load_short: Option<f32>,
    /// Long-term channel load percentage (1h)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_load_long: Option<f32>,
    /// Noise floor in dBm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noise_floor: Option<i32>,
    /// Interference level in dBm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interference: Option<i32>,
    /// Timestamp of last interference detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interference_last_ts: Option<f64>,
    /// dBm of last interference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interference_last_dbm: Option<i32>,
    /// CPU temperature in Celsius
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_temp: Option<f32>,
    /// CPU load percentage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_load: Option<f32>,
    /// Memory load percentage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_load: Option<f32>,
    /// Battery percentage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub battery_percent: Option<u8>,
    /// Battery state string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub battery_state: Option<String>,
    /// Switch ID (hex string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub switch_id: Option<String>,
    /// Via switch ID (hex string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_switch_id: Option<String>,
    /// Endpoint ID (hex string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
}

/// Overall network statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkStats {
    /// List of interface statistics
    pub interfaces: Vec<InterfaceStats>,
    /// Total bytes received
    pub rxb: u64,
    /// Total bytes transmitted
    pub txb: u64,
    /// Current total receive speed (bytes/sec)
    #[serde(default)]
    pub rxs: f64,
    /// Current total transmit speed (bytes/sec)
    #[serde(default)]
    pub txs: f64,
    /// Transport identity hash (if transport enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_id: Option<String>,
    /// Network identity hash (if transport enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    /// Transport uptime in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_uptime: Option<f64>,
    /// Probe responder destination hash (if enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_responder: Option<String>,
    /// Resident set size (memory usage in bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss: Option<u64>,
}

/// Discovered interface information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveredInterface {
    pub name: String,
    #[serde(rename = "type")]
    pub interface_type: String,
    pub status: String,
    pub transport: bool,
    pub hops: u8,
    pub discovered: f64,
    pub last_heard: f64,
    pub value: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sf: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cr: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modulation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachable_on: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_entry: Option<String>,
}

/// Sorting field options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Rate,
    Traffic,
    Rx,
    Tx,
    Rxs,
    Txs,
    Announces,
    Arx,
    Atx,
    Held,
}

impl SortField {
    /// Parse a string into a sort field
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rate" | "bitrate" => Some(SortField::Rate),
            "traffic" => Some(SortField::Traffic),
            "rx" => Some(SortField::Rx),
            "tx" => Some(SortField::Tx),
            "rxs" => Some(SortField::Rxs),
            "txs" => Some(SortField::Txs),
            "announces" | "announce" => Some(SortField::Announces),
            "arx" => Some(SortField::Arx),
            "atx" => Some(SortField::Atx),
            "held" => Some(SortField::Held),
            _ => None,
        }
    }
}

/// Reticulum Network Status CLI
#[derive(Parser, Debug)]
#[command(name = "rnstatus")]
#[command(author = "Reticulum Network Stack")]
#[command(version)]
#[command(about = "Display Reticulum network status", long_about = None)]
struct Args {
    /// Path to alternative Reticulum config directory
    #[arg(long, value_name = "DIR")]
    config: Option<PathBuf>,

    /// Show all interfaces (including hidden ones like LocalInterface)
    #[arg(short, long)]
    all: bool,

    /// Show announce statistics
    #[arg(short = 'A', long = "announce-stats")]
    announce_stats: bool,

    /// Show link statistics
    #[arg(short = 'l', long = "link-stats")]
    link_stats: bool,

    /// Display traffic totals
    #[arg(short = 't', long = "totals")]
    totals: bool,

    /// Sort interfaces by field [rate, traffic, rx, tx, rxs, txs, announces, arx, atx, held]
    #[arg(short = 's', long, value_name = "FIELD")]
    sort: Option<String>,

    /// Reverse sorting order
    #[arg(short = 'r', long)]
    reverse: bool,

    /// Output in JSON format
    #[arg(short, long)]
    json: bool,

    /// Transport identity hash of remote instance to get status from
    #[arg(short = 'R', value_name = "HASH")]
    remote: Option<String>,

    /// Path to identity used for remote management
    #[arg(short = 'i', value_name = "PATH")]
    identity: Option<PathBuf>,

    /// Timeout before giving up on remote queries (seconds)
    #[arg(short = 'w', value_name = "SECONDS", default_value = "15")]
    timeout: f64,

    /// List discovered interfaces
    #[arg(short = 'd', long = "discovered")]
    discovered: bool,

    /// Show details and config entries for discovered interfaces
    #[arg(short = 'D')]
    discovered_details: bool,

    /// Continuously monitor status
    #[arg(short = 'm', long = "monitor")]
    monitor: bool,

    /// Refresh interval for monitor mode in seconds
    #[arg(short = 'I', long = "monitor-interval", value_name = "SECONDS", default_value = "1.0")]
    monitor_interval: f64,

    /// Increase verbosity (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Only display interfaces with names including this filter
    #[arg(value_name = "FILTER")]
    filter: Option<String>,
}

fn main() {
    let args = Args::parse();

    // Determine log level from verbosity flags
    let log_level = match args.verbose {
        0 => LogLevel::Warning,
        1 => LogLevel::Notice,
        2 => LogLevel::Info,
        3 => LogLevel::Debug,
        _ => LogLevel::Verbose,
    };

    // Initialize logging
    logging::init_with_level(log_level);

    // Load configuration
    let config = match ReticulumConfig::load(args.config.clone()) {
        Ok(cfg) => cfg,
        Err(e) => {
            if !args.json {
                eprintln!("Failed to load configuration: {}", e);
            }
            std::process::exit(1);
        }
    };

    // Set up signal handler for monitor mode
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .ok();

    // Handle discovered interfaces mode
    if args.discovered || args.discovered_details {
        show_discovered_interfaces(&args, &config);
        return;
    }

    // Run in monitor mode or single-shot
    if args.monitor {
        run_monitor_mode(&args, &config, running);
    } else {
        run_once(&args, &config);
    }
}

/// Run status display once
fn run_once(args: &Args, config: &ReticulumConfig) {
    if args.remote.is_some() {
        show_remote_status(args, config);
    } else {
        show_local_status(args, config);
    }
}

/// Run in continuous monitor mode
fn run_monitor_mode(args: &Args, config: &ReticulumConfig, running: Arc<AtomicBool>) {
    let interval = Duration::from_secs_f64(args.monitor_interval);

    while running.load(Ordering::SeqCst) {
        // Clear screen (ANSI escape sequence)
        print!("\x1B[H\x1B[2J");
        io::stdout().flush().ok();

        if args.remote.is_some() {
            show_remote_status(args, config);
        } else {
            show_local_status(args, config);
        }

        // Sleep for interval, checking for shutdown periodically
        let start = Instant::now();
        while running.load(Ordering::SeqCst) && start.elapsed() < interval {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Show status from local/shared Reticulum instance
///
/// Requires a running rnsd daemon to query. This matches Python behavior where
/// rnstatus sets `require_shared_instance=True` and fails if no daemon is available.
fn show_local_status(args: &Args, config: &ReticulumConfig) {
    // Try to connect to shared instance - require it to be running
    let stats = match get_shared_instance_stats(config) {
        Ok(stats) => stats,
        Err(_) => {
            // Match Python behavior: fail if no shared instance available
            if args.json {
                output_json_error("no_shared_instance", "No shared RNS instance available to get status from");
            } else {
                println!();
                println!("No shared RNS instance available to get status from");
                println!();
            }
            std::process::exit(1);
        }
    };

    // Get link count if requested
    let link_count = if args.link_stats {
        get_link_count(config).ok()
    } else {
        None
    };

    display_stats(args, &stats, link_count);
}

/// Show status from remote transport instance
fn show_remote_status(args: &Args, config: &ReticulumConfig) {
    let transport_hash_str = args.remote.as_ref().unwrap();

    // Create a tokio runtime for async operations
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create runtime: {}", e);
            std::process::exit(20);
        }
    };

    let exit_code = rt.block_on(async {
        show_remote_status_async(args, config, transport_hash_str).await
    });

    std::process::exit(exit_code);
}

/// Async implementation of remote status query.
async fn show_remote_status_async(args: &Args, config: &ReticulumConfig, transport_hash_str: &str) -> i32 {
    let timeout_duration = Duration::from_secs_f64(args.timeout);

    // Parse the transport identity hash
    let transport_identity_hash = match parse_transport_hash(transport_hash_str) {
        Ok(hash) => hash,
        Err(e) => {
            if args.json {
                output_json_error("invalid_hash", &e);
            } else {
                eprintln!("Error: {}", e);
            }
            return 1;
        }
    };

    // Load management identity if specified
    let management_identity = if let Some(ref identity_path) = args.identity {
        match load_identity(identity_path) {
            Ok(id) => Some(id),
            Err(e) => {
                if args.json {
                    output_json_error("identity_error", &e);
                } else {
                    eprintln!("Error loading identity: {}", e);
                }
                return 2;
            }
        }
    } else {
        // Create an ephemeral identity for connection
        Some(PrivateIdentity::new_from_rand(OsRng))
    };

    // Compute the management destination hash
    let mgmt_dest_hash = compute_management_destination_hash(&transport_identity_hash);

    if !args.json {
        println!("Querying remote transport <{}>", transport_hash_str);
        println!("Management destination: <{}>", hex::encode(mgmt_dest_hash.as_slice()));
        println!();
    }

    // Create transport and interfaces
    let transport = create_client_transport(config).await;

    // Request path to the management destination
    if !args.json {
        print!("Requesting path... ");
        io::stdout().flush().ok();
    }

    transport.request_path(&mgmt_dest_hash, None).await;

    let path_found = wait_for_path(&transport, &mgmt_dest_hash, timeout_duration).await;
    if !path_found {
        if args.json {
            output_json_error("path_not_found", "Could not find path to remote transport");
        } else {
            println!("not found");
            eprintln!("Could not find path to remote transport.");
            eprintln!("Make sure the transport is running and reachable.");
        }
        return 10;
    }

    if !args.json {
        println!("OK");
    }

    // Wait for announce to get identity
    tokio::time::sleep(Duration::from_millis(500)).await;

    let remote_identity = match transport.recall_identity(&mgmt_dest_hash).await {
        Some(id) => id,
        None => {
            if args.json {
                output_json_error("no_identity", "Could not recall remote identity");
            } else {
                eprintln!("Error: Could not recall remote identity");
            }
            return 11;
        }
    };

    // Create destination descriptor for link establishment
    let dest_name = DestinationName::new("rnstransport", "remote.management");
    let dest_desc = SingleOutputDestination::new(remote_identity, dest_name);

    // Establish link
    if !args.json {
        print!("Establishing link... ");
        io::stdout().flush().ok();
    }

    let link = transport.link(dest_desc.desc).await;

    // Wait for link activation
    let mut out_link_events = transport.out_link_events();
    let deadline = tokio::time::Instant::now() + timeout_duration;

    loop {
        if tokio::time::Instant::now() >= deadline {
            if args.json {
                output_json_error("link_timeout", "Could not establish link to remote transport");
            } else {
                println!("timeout");
                eprintln!("Could not establish link to remote transport.");
            }
            return 12;
        }

        let status = link.lock().await.status();
        if status == LinkStatus::Active {
            if !args.json {
                println!("OK");
            }
            break;
        }

        tokio::select! {
            Ok(_event) = out_link_events.recv() => {
                // Link events are handled internally
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if !args.json {
                    print!(".");
                    io::stdout().flush().ok();
                }
            }
        }
    }

    // Identify with management identity (if we have one)
    if let Some(ref mgmt_id) = management_identity {
        if !args.json {
            print!("Identifying... ");
            io::stdout().flush().ok();
        }

        let identify_packet = {
            let link_guard = link.lock().await;
            match link_guard.identify(mgmt_id) {
                Ok(pkt) => pkt,
                Err(e) => {
                    if args.json {
                        output_json_error("identify_error", &format!("{:?}", e));
                    } else {
                        println!("error");
                        eprintln!("Could not create identify packet: {:?}", e);
                    }
                    return 13;
                }
            }
        };

        transport.send_packet(identify_packet).await;

        // Give server time to process identity
        tokio::time::sleep(Duration::from_millis(300)).await;

        if !args.json {
            println!("OK");
        }
    }

    // Send status request
    if !args.json {
        print!("Requesting status... ");
        io::stdout().flush().ok();
    }

    let request_data = build_status_request(args.link_stats);
    let request_packet = {
        let link_guard = link.lock().await;
        match link_guard.request_packet(&request_data) {
            Ok(pkt) => pkt,
            Err(e) => {
                if args.json {
                    output_json_error("request_error", &format!("{:?}", e));
                } else {
                    println!("error");
                    eprintln!("Could not create request packet: {:?}", e);
                }
                return 14;
            }
        }
    };

    transport.send_packet(request_packet).await;

    // Wait for response
    let response_deadline = tokio::time::Instant::now() + timeout_duration;

    let response_data = loop {
        if tokio::time::Instant::now() >= response_deadline {
            if args.json {
                output_json_error("response_timeout", "No response received from remote transport");
            } else {
                println!("timeout");
                eprintln!("No response received from remote transport.");
            }
            return 15;
        }

        tokio::select! {
            Ok(event) = out_link_events.recv() => {
                if let LinkEvent::Response(payload) = &event.event {
                    if !args.json {
                        println!("OK");
                    }
                    break payload.as_slice().to_vec();
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if !args.json {
                    print!(".");
                    io::stdout().flush().ok();
                }
            }
        }
    };

    // Parse and display response
    if !args.json {
        println!();
    }

    match parse_status_response(&response_data) {
        Ok((interfaces, link_count)) => {
            display_remote_status(args, transport_hash_str, &interfaces, link_count);
            0
        }
        Err(e) => {
            if args.json {
                output_json_error("parse_error", &e);
            } else {
                eprintln!("Error parsing response: {}", e);
            }
            16
        }
    }
}

/// Parse a transport identity hash from hex string.
fn parse_transport_hash(hash_str: &str) -> Result<[u8; 16], String> {
    let clean = hash_str
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim_start_matches('/')
        .trim_end_matches('/');

    if clean.len() != 32 {
        return Err(format!(
            "Invalid transport hash length: expected 32 hex characters, got {}",
            clean.len()
        ));
    }

    let bytes = hex::decode(clean)
        .map_err(|_| "Invalid hexadecimal string".to_string())?;

    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Load a private identity from a file.
///
/// Uses binary format (64 bytes) which is compatible with Python.
fn load_identity(path: &PathBuf) -> Result<PrivateIdentity, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|mut f| f.read_to_end(&mut bytes))
        .map_err(|e| format!("Could not read identity file: {}", e))?;

    // Binary format: 64 bytes (Python-compatible)
    if bytes.len() != 64 {
        return Err(format!(
            "Invalid identity file: expected 64 bytes, got {} bytes",
            bytes.len()
        ));
    }

    PrivateIdentity::new_from_bytes(&bytes)
        .map_err(|e| format!("Invalid identity format: {:?}", e))
}

/// Compute the management destination hash from a transport identity hash.
fn compute_management_destination_hash(transport_identity_hash: &[u8; 16]) -> AddressHash {
    // Name hash for "rnstransport.remote.management"
    let name = DestinationName::new("rnstransport", "remote.management");
    let name_hash = name.as_name_hash_slice();

    // Destination hash = truncated(sha256(name_hash || identity_hash))
    let mut hasher = Sha256::new();
    hasher.update(name_hash);
    hasher.update(transport_identity_hash);
    let result = hasher.finalize();

    AddressHash::new_from_hash(&Hash::new(result.into()))
}

/// Create a client transport matching Python's require_shared_instance=False behavior.
///
/// Order of operations (matching Python Reticulum.py lines 373-435):
/// 1. Try to become the shared instance (start LocalServerInterface)
/// 2. If that fails (daemon already running), connect as client via LocalClientInterface
/// 3. If both fail, become standalone (just load network interfaces)
async fn create_client_transport(config: &ReticulumConfig) -> Transport {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport_config = TransportConfig::new("rnstatus", &identity, false);
    let transport = Transport::new(transport_config);

    let socket_dir = config.paths.config_dir.join("sockets");
    if let Err(e) = std::fs::create_dir_all(&socket_dir) {
        log::warn!("Failed to create socket directory: {}", e);
    }

    let local_addr = ListenerAddr::default_transport(
        "default",
        &socket_dir,
        config.shared_instance_port,
    );

    // Step 1: Try to become the shared instance (start LocalServerInterface)
    // This will fail if another daemon is already running on this socket
    let became_shared_instance = try_become_shared_instance(
        &transport,
        local_addr.clone(),
        config,
    ).await;

    if became_shared_instance {
        log::info!("Started as shared instance, serving other clients");
        return transport;
    }

    // Step 2: Daemon exists, connect as client via LocalClientInterface
    log::info!("Connecting to existing daemon via LocalClientInterface");

    transport
        .iface_manager()
        .lock()
        .await
        .spawn(
            LocalClientInterface::new(local_addr.clone()),
            LocalClientInterface::spawn,
        );

    // Give LocalClientInterface time to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    transport
}

/// Try to start as a shared instance by binding LocalServerInterface.
/// Returns true if successful (we became the shared instance).
/// Returns false if binding fails (another daemon is running).
async fn try_become_shared_instance(
    transport: &Transport,
    local_addr: ListenerAddr,
    config: &ReticulumConfig,
) -> bool {
    // Try to bind to the socket - this will fail if daemon is already running
    match IpcListener::bind(&local_addr).await {
        Ok(_listener) => {
            // We successfully bound - we are the shared instance
            // Drop the listener so LocalServerInterface can bind it
            drop(_listener);

            // Start LocalServerInterface to serve other clients
            transport
                .iface_manager()
                .lock()
                .await
                .spawn(
                    LocalServerInterface::new(local_addr, transport.iface_manager()),
                    LocalServerInterface::spawn,
                );

            // Load network interfaces from config (matching Python's __start_local_interface)
            spawn_network_interfaces(transport, config).await;

            // Give interfaces time to connect
            tokio::time::sleep(Duration::from_millis(500)).await;

            true
        }
        Err(e) => {
            log::debug!("Could not bind LocalServerInterface: {} - daemon likely running", e);
            false
        }
    }
}

/// Spawn network interfaces from configuration.
async fn spawn_network_interfaces(transport: &Transport, config: &ReticulumConfig) {
    for iface_config in config.interface_configs() {
        if !iface_config.enabled {
            continue;
        }

        match iface_config.interface_type.as_str() {
            "TCPClientInterface" | "tcp_client" => {
                if let Some(ref target) = iface_config.target_host {
                    let port = iface_config.target_port.unwrap_or(4242);
                    let addr = format!("{}:{}", target, port);
                    log::info!("Starting TCPClientInterface: {}", addr);
                    transport
                        .iface_manager()
                        .lock()
                        .await
                        .spawn(TcpClient::new(&addr), TcpClient::spawn);
                }
            }
            "TCPServerInterface" | "tcp_server" => {
                // Skip server interfaces for rnstatus - we only need outbound connectivity
                log::debug!("Skipping TCPServerInterface for rnstatus transport");
            }
            _ => {
                log::debug!("Skipping unsupported interface type: {}", iface_config.interface_type);
            }
        }
    }
}

/// Wait for a path to be established.
async fn wait_for_path(transport: &Transport, dest_hash: &AddressHash, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;

    while tokio::time::Instant::now() < deadline {
        if transport.has_path(dest_hash).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    false
}

/// Build a status request packet data.
fn build_status_request(include_link_stats: bool) -> Vec<u8> {
    // Request format: [timestamp, path_hash("/status"), [include_link_stats]]
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    let path_hash = RequestRouter::path_hash("/status");

    // Build the request data payload
    let mut data_payload = Vec::new();
    rmpv::encode::write_value(&mut data_payload, &rmpv::Value::Array(vec![
        rmpv::Value::Boolean(include_link_stats),
    ])).unwrap();

    // Build the full request
    let request = rmpv::Value::Array(vec![
        rmpv::Value::F64(timestamp),
        rmpv::Value::Binary(path_hash.to_vec()),
        rmpv::Value::Binary(data_payload),
    ]);

    let mut packed = Vec::new();
    rmpv::encode::write_value(&mut packed, &request).unwrap();
    packed
}

/// Parse a status response.
fn parse_status_response(data: &[u8]) -> Result<(Vec<RemoteInterfaceStats>, Option<u64>), String> {
    // Response format: [request_id, response_data]
    // where response_data is [interface_stats_obj, link_count?]
    // and interface_stats_obj is {"interfaces": [...], "rxb": ..., "txb": ..., ...} (Python format)
    // or just an array of interfaces (Rust format)
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(data))
        .map_err(|e| format!("Failed to decode response: {}", e))?;

    let arr = value.as_array().ok_or("Response is not an array")?;
    if arr.len() < 2 {
        return Err("Response too short".to_string());
    }

    // Second element is the actual response data
    let response_data = &arr[1];

    // Parse the response data (which may be binary/msgpack encoded or directly an array)
    let inner = if let Some(bytes) = response_data.as_slice() {
        rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
            .map_err(|e| format!("Failed to decode inner response: {}", e))?
    } else {
        response_data.clone()
    };

    let inner_arr = inner.as_array().ok_or("Inner response is not an array")?;
    if inner_arr.is_empty() {
        return Ok((vec![], None));
    }

    // Parse interface stats - handle both Python (map with "interfaces" key) and Rust (direct array) formats
    let interfaces = if let Some(stats_map) = inner_arr[0].as_map() {
        // Python format: {"interfaces": [...], "rxb": ..., "txb": ..., ...}
        let iface_arr = stats_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("interfaces"))
            .and_then(|(_, v)| v.as_array());
        if let Some(arr) = iface_arr {
            arr.iter().filter_map(parse_remote_interface).collect()
        } else {
            vec![]
        }
    } else if let Some(iface_arr) = inner_arr[0].as_array() {
        // Rust format: direct array of interfaces
        iface_arr.iter().filter_map(parse_remote_interface).collect()
    } else {
        vec![]
    };

    // Parse link count if present
    let link_count = if inner_arr.len() > 1 {
        inner_arr[1].as_u64()
    } else {
        None
    };

    Ok((interfaces, link_count))
}

/// Remote interface statistics from response.
#[derive(Debug, Clone)]
struct RemoteInterfaceStats {
    name: String,
    interface_type: String,
    online: bool,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// Parse a single interface from the response.
fn parse_remote_interface(value: &rmpv::Value) -> Option<RemoteInterfaceStats> {
    let map = value.as_map()?;

    let get_str = |key: &str| -> Option<String> {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .and_then(|(_, v)| v.as_str().map(|s| s.to_string()))
    };

    let get_bool = |key: &str| -> bool {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .and_then(|(_, v)| v.as_bool())
            .unwrap_or(false)
    };

    let get_u64 = |key: &str| -> u64 {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .and_then(|(_, v)| v.as_u64())
            .unwrap_or(0)
    };

    // Python uses "status" for online state, Rust uses "online"
    let online = get_bool("online") || get_bool("status");

    // Python uses "name" for full interface name, "short_name" for just the name
    let name = get_str("short_name").or_else(|| get_str("name"))?;

    Some(RemoteInterfaceStats {
        name,
        interface_type: get_str("type").unwrap_or_default(),
        online,
        rx_bytes: get_u64("rxb"),
        tx_bytes: get_u64("txb"),
    })
}

/// Display the remote status.
fn display_remote_status(
    args: &Args,
    transport_hash: &str,
    interfaces: &[RemoteInterfaceStats],
    link_count: Option<u64>,
) {
    if args.json {
        let mut obj = serde_json::Map::new();
        obj.insert("transport_hash".to_string(), serde_json::Value::String(transport_hash.to_string()));

        let iface_arr: Vec<serde_json::Value> = interfaces.iter().map(|iface| {
            let mut m = serde_json::Map::new();
            m.insert("name".to_string(), serde_json::Value::String(iface.name.clone()));
            m.insert("type".to_string(), serde_json::Value::String(iface.interface_type.clone()));
            m.insert("online".to_string(), serde_json::Value::Bool(iface.online));
            m.insert("rx_bytes".to_string(), serde_json::Value::Number(iface.rx_bytes.into()));
            m.insert("tx_bytes".to_string(), serde_json::Value::Number(iface.tx_bytes.into()));
            serde_json::Value::Object(m)
        }).collect();

        obj.insert("interfaces".to_string(), serde_json::Value::Array(iface_arr));

        if let Some(count) = link_count {
            obj.insert("link_count".to_string(), serde_json::Value::Number(count.into()));
        }

        println!("{}", serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap());
    } else {
        println!("Remote Transport Status: <{}>", transport_hash);
        println!();

        if interfaces.is_empty() {
            println!("  No interface statistics available");
        } else {
            println!("  Interfaces:");
            for iface in interfaces {
                let status = if iface.online { "Online" } else { "Offline" };
                println!("    {} [{}] - {}", iface.name, iface.interface_type, status);
                println!("      RX: {} bytes, TX: {} bytes", iface.rx_bytes, iface.tx_bytes);
            }
        }

        if let Some(count) = link_count {
            println!();
            println!("  Active links: {}", count);
        }
    }
}

/// Output a JSON error message.
fn output_json_error(error_type: &str, message: &str) {
    let mut obj = serde_json::Map::new();
    obj.insert("error".to_string(), serde_json::Value::String(error_type.to_string()));
    obj.insert("message".to_string(), serde_json::Value::String(message.to_string()));
    println!("{}", serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap());
}

/// Show discovered interfaces
fn show_discovered_interfaces(args: &Args, config: &ReticulumConfig) {
    // Query daemon for discovered interfaces via RPC
    let socket_dir = config.paths.config_dir.join("sockets");
    let rpc_addr = ListenerAddr::default_rpc("default", &socket_dir, config.control_port);
    let client = RpcClient::new(rpc_addr);

    // Use tokio runtime to make async RPC call
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create runtime: {}", e);
            return;
        }
    };

    let discovered: Vec<DiscoveredInterface> = rt.block_on(async {
        // Try to get interfaces from daemon
        match client.get_discovered_interfaces().await {
            Ok(rpc_interfaces) => {
                // Convert RPC entries to our local format
                rpc_interfaces
                    .into_iter()
                    .map(|entry| DiscoveredInterface {
                        name: entry.name,
                        interface_type: entry.interface_type,
                        status: entry.status,
                        transport: entry.transport,
                        hops: entry.hops,
                        discovered: entry.discovered,
                        last_heard: entry.last_heard,
                        value: entry.value,
                        latitude: entry.latitude,
                        longitude: entry.longitude,
                        height: entry.height,
                        transport_id: entry.transport_id,
                        network_id: entry.network_id,
                        frequency: entry.frequency,
                        bandwidth: entry.bandwidth,
                        sf: entry.sf,
                        cr: entry.cr,
                        modulation: entry.modulation,
                        reachable_on: entry.reachable_on,
                        port: entry.port,
                        config_entry: entry.config_entry,
                    })
                    .collect()
            }
            Err(_) => {
                // Daemon not running or no interfaces discovered
                Vec::new()
            }
        }
    });

    if args.json {
        println!("{}", serde_json::to_string_pretty(&discovered).unwrap());
        return;
    }

    println!();

    if discovered.is_empty() {
        println!("No discovered interfaces.");
        println!();
        return;
    }

    // Filter by name if filter provided
    let filtered: Vec<_> = if let Some(ref filter) = args.filter {
        discovered
            .iter()
            .filter(|i| i.name.to_lowercase().contains(&filter.to_lowercase()))
            .collect()
    } else {
        discovered.iter().collect()
    };

    if args.discovered_details {
        // Detailed view
        for (idx, iface) in filtered.iter().enumerate() {
            if idx > 0 {
                println!("\n{}\n", "=".repeat(32));
            }

            if let Some(ref network_id) = iface.network_id {
                if iface.transport_id.as_ref() != Some(network_id) {
                    println!("Network   ID : {}", network_id);
                }
            }
            if let Some(ref transport_id) = iface.transport_id {
                println!("Transport ID : {}", transport_id);
            }

            println!("Name         : {}", iface.name);
            println!("Type         : {}", iface.interface_type);
            println!("Status       : {}", format_status(&iface.status));
            println!(
                "Transport    : {}",
                if iface.transport { "Enabled" } else { "Disabled" }
            );
            println!(
                "Distance     : {} hop{}",
                iface.hops,
                if iface.hops == 1 { "" } else { "s" }
            );
            println!("Discovered   : {} ago", pretty_time(iface.discovered));
            println!("Last Heard   : {} ago", pretty_time(iface.last_heard));

            if let (Some(lat), Some(lon)) = (iface.latitude, iface.longitude) {
                let height_str = iface
                    .height
                    .map(|h| format!(", {}m h", h))
                    .unwrap_or_default();
                println!("Location     : {:.4}, {:.4}{}", lat, lon, height_str);
            } else {
                println!("Location     : Unknown");
            }

            if let Some(freq) = iface.frequency {
                println!("Frequency    : {} Hz", format_with_commas(freq));
            }
            if let Some(bw) = iface.bandwidth {
                println!("Bandwidth    : {} Hz", format_with_commas(bw));
            }
            if let Some(sf) = iface.sf {
                println!("Sprd. Factor : {}", sf);
            }
            if let Some(cr) = iface.cr {
                println!("Coding Rate  : {}", cr);
            }
            if let Some(ref modulation) = iface.modulation {
                println!("Modulation   : {}", modulation);
            }
            if let (Some(ref addr), Some(port)) = (&iface.reachable_on, iface.port) {
                println!("Address      : {}:{}", addr, port);
            }

            println!("Stamp Value  : {}", iface.value);

            if let Some(ref config_entry) = iface.config_entry {
                println!("\nConfiguration Entry:");
                for line in config_entry.lines() {
                    println!("  {}", line);
                }
            }
        }
    } else {
        // Table view
        println!(
            "{:<25} {:<12} {:<12} {:<12} {:<8} {:<15}",
            "Name", "Type", "Status", "Last Heard", "Value", "Location"
        );
        println!("{}", "-".repeat(89));

        for iface in filtered {
            let name = if iface.name.len() > 24 {
                format!("{}…", &iface.name[..24])
            } else {
                iface.name.clone()
            };

            let if_type = iface.interface_type.replace("Interface", "");
            let status_display = format_status(&iface.status);

            let last_heard = format_time_ago(iface.last_heard);

            let location = if let (Some(lat), Some(lon)) = (iface.latitude, iface.longitude) {
                format!("{:.4}, {:.4}", lat, lon)
            } else {
                "N/A".to_string()
            };

            println!(
                "{:<25} {:<12} {:<12} {:<12} {:<8} {:<15}",
                name, if_type, status_display, last_heard, iface.value, location
            );
        }
    }

    println!();
}

/// Try to connect to shared instance and get stats via RPC
fn get_shared_instance_stats(config: &ReticulumConfig) -> Result<NetworkStats, String> {
    // Create RPC client with appropriate address for this platform
    let socket_dir = config.paths.config_dir.join("sockets");
    let rpc_addr = ListenerAddr::default_rpc("default", &socket_dir, config.control_port);

    let client = RpcClient::new(rpc_addr);

    // Use tokio runtime to make async RPC call
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create runtime: {}", e))?;

    rt.block_on(async {
        // First check if daemon is running
        if !client.is_daemon_running().await {
            return Err("No daemon running".to_string());
        }

        // Get interface stats from daemon
        let iface_stats = client
            .get_interface_stats()
            .await
            .map_err(|e| format!("Failed to get interface stats: {}", e))?;

        // Convert RPC interface stats to our local format
        let interfaces: Vec<InterfaceStats> = iface_stats
            .into_iter()
            .map(|s| InterfaceStats {
                name: s.name.clone(),
                short_name: s.name.clone(),
                hash: String::new(),
                interface_type: s.interface_type,
                rxb: s.rx_bytes,
                txb: s.tx_bytes,
                status: s.online,
                mode: InterfaceMode::Full as u8,
                bitrate: s.bitrate,
                ..Default::default()
            })
            .collect();

        Ok(NetworkStats {
            interfaces,
            ..Default::default()
        })
    })
}

/// Get link count from shared instance via RPC
fn get_link_count(config: &ReticulumConfig) -> Result<u32, String> {
    // Create RPC client with appropriate address for this platform
    let socket_dir = config.paths.config_dir.join("sockets");
    let rpc_addr = ListenerAddr::default_rpc("default", &socket_dir, config.control_port);

    let client = RpcClient::new(rpc_addr);

    // Use tokio runtime to make async RPC call
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create runtime: {}", e))?;

    rt.block_on(async {
        let count = client
            .get_link_count()
            .await
            .map_err(|e| format!("Failed to get link count: {}", e))?;

        Ok(count as u32)
    })
}

/// Display the network statistics
fn display_stats(args: &Args, stats: &NetworkStats, link_count: Option<u32>) {
    if args.json {
        display_json(stats, link_count);
        return;
    }

    // Sort interfaces if requested
    let mut interfaces: Vec<_> = stats.interfaces.iter().collect();
    if let Some(ref sort_field) = args.sort {
        if let Some(field) = SortField::parse(sort_field) {
            sort_interfaces(&mut interfaces, field, args.reverse);
        }
    }

    // Filter interfaces
    let interfaces: Vec<_> = interfaces
        .into_iter()
        .filter(|iface| should_display_interface(iface, args))
        .collect();

    if interfaces.is_empty() && stats.transport_id.is_none() {
        println!();
        println!("No shared RNS instance available to get status from");
        println!();
        return;
    }

    // Display each interface
    for iface in &interfaces {
        display_interface(iface, args);
    }

    // Display link stats if requested
    let mut link_str = String::new();
    if let Some(count) = link_count {
        if args.link_stats {
            let entry_word = if count == 1 { "entry" } else { "entries" };
            if stats.transport_id.is_some() {
                link_str = format!(", {} {} in link table", count, entry_word);
            } else {
                link_str = format!(" {} {} in link table", count, entry_word);
            }
        }
    }

    // Display traffic totals if requested
    if args.totals {
        let rx_str = format!("↓{}", pretty_size(stats.rxb));
        let tx_str = format!("↑{}", pretty_size(stats.txb));

        let rx_speed = pretty_speed(stats.rxs).to_string();
        let tx_speed = pretty_speed(stats.txs).to_string();

        // Pad to align
        let max_len = rx_str.len().max(tx_str.len());
        let rx_padded = format!("{:width$}", rx_str, width = max_len);
        let tx_padded = format!("{:width$}", tx_str, width = max_len);

        println!();
        println!(" Totals       : {}  {}", tx_padded, tx_speed);
        println!("                {}  {}", rx_padded, rx_speed);
    }

    // Display transport info
    if let Some(ref transport_id) = stats.transport_id {
        println!();
        println!(" Transport Instance {} running", pretty_hex(transport_id));

        if let Some(ref network_id) = stats.network_id {
            println!(" Network Identity   {}", pretty_hex(network_id));
        }

        if let Some(ref probe_responder) = stats.probe_responder {
            println!(
                " Probe responder at {} active",
                pretty_hex(probe_responder)
            );
        }

        if let Some(uptime) = stats.transport_uptime {
            println!(" Uptime is {}{}", pretty_time(uptime), link_str);
        }
    } else if !link_str.is_empty() {
        println!();
        println!("{}", link_str);
    }

    println!();
}

/// Display stats as JSON
fn display_json(stats: &NetworkStats, _link_count: Option<u32>) {
    match serde_json::to_string_pretty(stats) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize to JSON: {}", e),
    }
}

/// Check if an interface should be displayed based on filters
fn should_display_interface(iface: &InterfaceStats, args: &Args) -> bool {
    // Check name filter
    if let Some(ref filter) = args.filter {
        if !iface.name.to_lowercase().contains(&filter.to_lowercase()) {
            return false;
        }
    }

    // Unless --all is set, hide certain interface types
    if !args.all {
        let name = &iface.name;
        if name.starts_with("LocalInterface[")
            || name.starts_with("TCPInterface[Client")
            || name.starts_with("BackboneInterface[Client on")
            || name.starts_with("AutoInterfacePeer[")
            || name.starts_with("WeaveInterfacePeer[")
            || name.starts_with("I2PInterfacePeer[Connected peer")
        {
            return false;
        }

        // Hide non-connectable I2P interfaces
        if name.starts_with("I2PInterface[") {
            if let Some(connectable) = iface.i2p_connectable {
                if !connectable {
                    return false;
                }
            }
        }
    }

    true
}

/// Sort interfaces by the specified field
fn sort_interfaces(interfaces: &mut Vec<&InterfaceStats>, field: SortField, reverse: bool) {
    interfaces.sort_by(|a, b| {
        let cmp = match field {
            SortField::Rate => a.bitrate.unwrap_or(0).cmp(&b.bitrate.unwrap_or(0)),
            SortField::Traffic => (a.rxb + a.txb).cmp(&(b.rxb + b.txb)),
            SortField::Rx => a.rxb.cmp(&b.rxb),
            SortField::Tx => a.txb.cmp(&b.txb),
            SortField::Rxs => a.rxs.partial_cmp(&b.rxs).unwrap_or(std::cmp::Ordering::Equal),
            SortField::Txs => a.txs.partial_cmp(&b.txs).unwrap_or(std::cmp::Ordering::Equal),
            SortField::Announces => (a.incoming_announce_frequency + a.outgoing_announce_frequency)
                .partial_cmp(&(b.incoming_announce_frequency + b.outgoing_announce_frequency))
                .unwrap_or(std::cmp::Ordering::Equal),
            SortField::Arx => a
                .incoming_announce_frequency
                .partial_cmp(&b.incoming_announce_frequency)
                .unwrap_or(std::cmp::Ordering::Equal),
            SortField::Atx => a
                .outgoing_announce_frequency
                .partial_cmp(&b.outgoing_announce_frequency)
                .unwrap_or(std::cmp::Ordering::Equal),
            SortField::Held => a.held_announces.cmp(&b.held_announces),
        };

        if reverse {
            cmp
        } else {
            cmp.reverse()
        }
    });
}

/// Display a single interface's statistics
fn display_interface(iface: &InterfaceStats, args: &Args) {
    println!();
    println!(" {}", iface.name);

    // Autoconnect source
    if let Some(ref source) = iface.autoconnect_source {
        println!("    Source    : Auto-connect via <{}>", source);
    }

    // Network name (IFAC)
    if let Some(ref netname) = iface.ifac_netname {
        println!("    Network   : {}", netname);
    }

    // Status
    let status_str = if iface.status { "Up" } else { "Down" };
    println!("    Status    : {}", status_str);

    // Clients
    if let Some(clients) = iface.clients {
        let clients_string = if iface.name.starts_with("Shared Instance[") {
            let cnum = clients.saturating_sub(1);
            let spec = if cnum == 1 { "program" } else { "programs" };
            format!("Serving   : {} {}", cnum, spec)
        } else if iface.name.starts_with("I2PInterface[") {
            if iface.i2p_connectable == Some(true) {
                let spec = if clients == 1 {
                    "connected I2P endpoint"
                } else {
                    "connected I2P endpoints"
                };
                format!("Peers     : {} {}", clients, spec)
            } else {
                String::new()
            }
        } else {
            format!("Clients   : {}", clients)
        };

        if !clients_string.is_empty() {
            println!("    {}", clients_string);
        }
    }

    // Mode (skip for certain interface types)
    if !iface.name.starts_with("Shared Instance[")
        && !iface.name.starts_with("TCPInterface[Client")
        && !iface.name.starts_with("LocalInterface[")
    {
        let mode = InterfaceMode::from(iface.mode);
        println!("    Mode      : {}", mode.as_str());
    }

    // Bitrate
    if let Some(bitrate) = iface.bitrate {
        println!("    Rate      : {}", speed_str(bitrate as f64));
    }

    // Noise floor and interference
    if let Some(noise_floor) = iface.noise_floor {
        let interference_str = if let Some(interference) = iface.interference {
            if interference != 0 {
                format!("\n    Intrfrnc. : {} dBm", interference)
            } else if let (Some(ts), Some(dbm)) =
                (iface.interference_last_ts, iface.interference_last_dbm)
            {
                let ago = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64() - ts)
                    .unwrap_or(0.0);
                format!(
                    "\n    Intrfrnc. : {} dBm {} ago",
                    dbm,
                    pretty_time(ago)
                )
            } else {
                ", no interference".to_string()
            }
        } else {
            String::new()
        };
        println!("    Noise Fl. : {} dBm{}", noise_floor, interference_str);
    }

    // CPU info
    if let Some(cpu_load) = iface.cpu_load {
        println!("    CPU load  : {} %", cpu_load);
    }
    if let Some(cpu_temp) = iface.cpu_temp {
        println!("    CPU temp  : {}°C", cpu_temp);
    }
    if let Some(mem_load) = iface.mem_load {
        println!("    Mem usage : {} %", mem_load);
    }

    // Battery
    if let (Some(percent), Some(ref state)) = (iface.battery_percent, &iface.battery_state) {
        println!("    Battery   : {}% ({})", percent, state);
    }

    // Airtime
    if let (Some(short), Some(long)) = (iface.airtime_short, iface.airtime_long) {
        println!("    Airtime   : {}% (15s), {}% (1h)", short, long);
    }

    // Channel load
    if let (Some(short), Some(long)) = (iface.channel_load_short, iface.channel_load_long) {
        println!("    Ch. Load  : {}% (15s), {}% (1h)", short, long);
    }

    // Switch/Endpoint IDs
    if let Some(ref switch_id) = iface.switch_id {
        println!("    Switch ID : {}", switch_id);
    }
    if let Some(ref endpoint_id) = iface.endpoint_id {
        println!("    Endpoint  : {}", endpoint_id);
    }
    if let Some(ref via_switch_id) = iface.via_switch_id {
        println!("    Via       : {}", via_switch_id);
    }

    // Peers
    if let Some(peers) = iface.peers {
        println!("    Peers     : {} reachable", peers);
    }

    // I2P tunnel state
    if let Some(ref tunnelstate) = iface.tunnelstate {
        println!("    I2P       : {}", tunnelstate);
    }

    // IFAC info
    if let Some(ref sig) = iface.ifac_signature {
        let sigstr = if sig.len() > 10 {
            format!("<…{}>", &sig[sig.len() - 10..])
        } else {
            format!("<{}>", sig)
        };
        let size_bits = iface.ifac_size.unwrap_or(0) as u32 * 8;
        println!("    Access    : {}-bit IFAC by {}", size_bits, sigstr);
    }

    // I2P B32
    if let Some(ref b32) = iface.i2p_b32 {
        println!("    I2P B32   : {}", b32);
    }

    // Announce stats (if -A flag)
    if args.announce_stats {
        if let Some(queue) = iface.announce_queue {
            if queue > 0 {
                let word = if queue == 1 { "announce" } else { "announces" };
                println!("    Queued    : {} {}", queue, word);
            }
        }

        if iface.held_announces > 0 {
            let word = if iface.held_announces == 1 {
                "announce"
            } else {
                "announces"
            };
            println!("    Held      : {} {}", iface.held_announces, word);
        }

        println!(
            "    Announces : {}↑",
            pretty_frequency(iface.outgoing_announce_frequency)
        );
        println!(
            "                {}↓",
            pretty_frequency(iface.incoming_announce_frequency)
        );
    }

    // Traffic
    let rx_str = format!("↓{}", pretty_size(iface.rxb));
    let tx_str = format!("↑{}", pretty_size(iface.txb));

    // Pad to align
    let max_len = rx_str.len().max(tx_str.len());
    let rx_padded = format!("{:width$}", rx_str, width = max_len);
    let tx_padded = format!("{:width$}", tx_str, width = max_len);

    let rx_speed = pretty_speed(iface.rxs);
    let tx_speed = pretty_speed(iface.txs);

    println!("    Traffic   : {}  {}", tx_padded, tx_speed);
    println!("                {}  {}", rx_padded, rx_speed);
}

// ============================================================================
// Formatting utilities
// ============================================================================

/// Format bytes as human-readable size
fn pretty_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["", "K", "M", "G", "T", "P", "E", "Z"];
    let mut size = bytes as f64;

    for unit in UNITS {
        if size.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{:.0} B", size)
            } else {
                format!("{:.2} {}B", size, unit)
            };
        }
        size /= 1000.0;
    }

    format!("{:.2} YB", size)
}

/// Format speed in bytes/sec as human-readable
fn pretty_speed(bytes_per_sec: f64) -> String {
    const UNITS: &[&str] = &["", "K", "M", "G", "T", "P", "E", "Z"];
    let mut speed = bytes_per_sec;

    for unit in UNITS {
        if speed.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{:.0} B/s", speed)
            } else {
                format!("{:.2} {}B/s", speed, unit)
            };
        }
        speed /= 1000.0;
    }

    format!("{:.2} YB/s", speed)
}

/// Format bitrate in bits/sec as human-readable
fn speed_str(bits_per_sec: f64) -> String {
    const UNITS: &[&str] = &["", "k", "M", "G", "T", "P", "E", "Z"];
    let mut speed = bits_per_sec;

    for unit in UNITS {
        if speed.abs() < 1000.0 {
            return format!("{:.2} {}bps", speed, unit);
        }
        speed /= 1000.0;
    }

    format!("{:.2} Ybps", speed)
}

/// Format frequency as human-readable
fn pretty_frequency(freq: f64) -> String {
    if freq < 0.001 {
        return "never".to_string();
    }

    let period = 1.0 / freq;
    if period < 60.0 {
        format!("{:.1}/s", freq)
    } else if period < 3600.0 {
        format!("{:.1}/min", freq * 60.0)
    } else if period < 86400.0 {
        format!("{:.1}/h", freq * 3600.0)
    } else {
        format!("{:.2}/day", freq * 86400.0)
    }
}

/// Format seconds as human-readable time
fn pretty_time(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{:.0}s", seconds)
    } else if seconds < 3600.0 {
        let mins = seconds / 60.0;
        format!("{:.0}m", mins)
    } else if seconds < 86400.0 {
        let hours = seconds / 3600.0;
        format!("{:.1}h", hours)
    } else if seconds < 604800.0 {
        let days = seconds / 86400.0;
        format!("{:.1}d", days)
    } else {
        let weeks = seconds / 604800.0;
        format!("{:.1}w", weeks)
    }
}

/// Format time ago from current time
fn format_time_ago(last_heard: f64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let diff = now - last_heard;

    if diff < 60.0 {
        "Just now".to_string()
    } else if diff < 3600.0 {
        format!("{}m ago", (diff / 60.0) as i32)
    } else if diff < 86400.0 {
        format!("{}h ago", (diff / 3600.0) as i32)
    } else {
        format!("{}d ago", (diff / 86400.0) as i32)
    }
}

/// Format status string with indicator
fn format_status(status: &str) -> String {
    match status {
        "available" => "✓ Available".to_string(),
        "unknown" => "? Unknown".to_string(),
        "stale" => "× Stale".to_string(),
        _ => status.to_string(),
    }
}

/// Format a hex string with angle brackets
fn pretty_hex(hex: &str) -> String {
    format!("<{}>", hex)
}

/// Format a number with comma separators (e.g., 1000000 -> "1,000,000")
fn format_with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
