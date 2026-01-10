//! Reticulum Network Status
//!
//! Display network status, interfaces, paths, and links. This utility connects
//! to a running Reticulum instance (or initializes its own) to display network
//! status information.

use std::io::{self, Write as IoWrite};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use serde::{Deserialize, Serialize};

use reticulum::config::{LogLevel, ReticulumConfig};
use reticulum::logging;

/// Interface mode constants matching Python implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum InterfaceMode {
    Full = 0x00,
    AccessPoint = 0x01,
    PointToPoint = 0x02,
    Roaming = 0x03,
    Boundary = 0x04,
    Gateway = 0x05,
}

impl Default for InterfaceMode {
    fn default() -> Self {
        InterfaceMode::Full
    }
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
    pub fn from_str(s: &str) -> Option<Self> {
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
fn show_local_status(args: &Args, config: &ReticulumConfig) {
    // Try to connect to shared instance first
    let stats = match get_shared_instance_stats(config) {
        Ok(stats) => stats,
        Err(_) => {
            // Fall back to standalone status
            get_standalone_stats(config)
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
fn show_remote_status(args: &Args, _config: &ReticulumConfig) {
    let remote_hash = args.remote.as_ref().unwrap();

    if args.json {
        let mut error_obj = serde_json::Map::new();
        error_obj.insert(
            "error".to_string(),
            serde_json::Value::String("not_implemented".to_string()),
        );
        error_obj.insert(
            "message".to_string(),
            serde_json::Value::String("Remote status queries not yet fully implemented".to_string()),
        );
        error_obj.insert(
            "destination".to_string(),
            serde_json::Value::String(remote_hash.clone()),
        );
        println!("{}", serde_json::to_string_pretty(&error_obj).unwrap());
    } else {
        eprintln!("Remote status queries require establishing a link to the remote transport instance.");
        eprintln!("Destination: {}", remote_hash);
        eprintln!();
        eprintln!("This feature requires:");
        eprintln!("  - Path to the remote transport instance");
        eprintln!("  - Valid management identity (-i flag)");
        eprintln!();
        eprintln!("Remote status queries will be available in a future version.");
    }
    std::process::exit(12);
}

/// Show discovered interfaces
fn show_discovered_interfaces(args: &Args, _config: &ReticulumConfig) {
    // For now, return empty list - discovery system would populate this
    let discovered: Vec<DiscoveredInterface> = Vec::new();

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

/// Try to connect to shared instance and get stats
fn get_shared_instance_stats(config: &ReticulumConfig) -> Result<NetworkStats, String> {
    // Try to connect to shared instance via RPC
    // For now, we'll use a simplified approach - attempt TCP connection to shared instance port
    use std::net::TcpStream;

    let addr = format!("127.0.0.1:{}", config.shared_instance_port);

    let _stream = TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        std::time::Duration::from_secs(2),
    )
    .map_err(|e| format!("Failed to connect to shared instance: {}", e))?;

    // The Python implementation uses multiprocessing.connection which has its own protocol
    // For now, we'll return an error and fall back to standalone mode
    Err("Shared instance RPC protocol not yet implemented".to_string())
}

/// Get stats in standalone mode (no shared instance)
fn get_standalone_stats(config: &ReticulumConfig) -> NetworkStats {
    let mut stats = NetworkStats::default();

    // Build interface stats from configuration
    for iface_config in config.interface_configs() {
        let if_stats = InterfaceStats {
            name: format!("{}[{}]", iface_config.interface_type, iface_config.name),
            short_name: iface_config.name.clone(),
            hash: format!("{:016x}", hash_string(&iface_config.name)),
            interface_type: iface_config.interface_type.clone(),
            status: iface_config.enabled,
            mode: InterfaceMode::Full as u8,
            bitrate: iface_config.bitrate,
            ..Default::default()
        };
        stats.interfaces.push(if_stats);
    }

    stats
}

/// Get link count from shared instance
fn get_link_count(_config: &ReticulumConfig) -> Result<u32, String> {
    // Would query shared instance for link count
    Err("Link count not available in standalone mode".to_string())
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
        if let Some(field) = SortField::from_str(sort_field) {
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

        let rx_speed = format!("{}", pretty_speed(stats.rxs));
        let tx_speed = format!("{}", pretty_speed(stats.txs));

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

/// Format a hex string with pretty separators
fn pretty_hex(hex: &str) -> String {
    if hex.len() >= 32 {
        format!("<{}>", hex)
    } else {
        format!("<{}>", hex)
    }
}

/// Simple string hash for generating deterministic hashes
fn hash_string(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
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
