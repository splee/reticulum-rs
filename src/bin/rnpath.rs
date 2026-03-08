//! Reticulum Path Management Utility
//!
//! Display and manage paths, announce rates, and blackhole entries.
//! This utility connects to the Reticulum network to query and modify
//! path information.

use std::io::{self, Write as IoWrite};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use rand_core::OsRng;
use serde::Serialize;

use std::fs;

use reticulum::cli::format::{format_hash_hex, format_time, format_time_ago};
use reticulum::cli::hash::parse_destination;
use reticulum::config::{LogLevel, ReticulumConfig};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::ipc::addr::ListenerAddr;
use reticulum::logging;
use reticulum::remote_client::{
    self, RemoteClient, RemoteClientConfig, BLACKHOLE_INFO_ASPECT, REMOTE_MANAGEMENT_ASPECT,
};
use reticulum::rpc::RpcClient;
use reticulum::stamper::Stamper;
use reticulum::transport::{Transport, TransportConfig};
use reticulum::transport::blackhole::BlackholeManager;

/// Reticulum Path Management Utility
#[derive(Parser, Debug)]
#[command(name = "rnpath")]
#[command(author = "Reticulum Network Stack")]
#[command(version)]
#[command(about = "Reticulum path management utility", long_about = None)]
struct Args {
    /// Path to alternative Reticulum config directory
    #[arg(long, value_name = "DIR")]
    config: Option<PathBuf>,

    /// Show all known paths in the path table
    #[arg(short = 't', long)]
    table: bool,

    /// Maximum hops to filter path table by
    #[arg(short = 'm', long = "max", value_name = "HOPS")]
    max_hops: Option<u8>,

    /// Show announce rate info
    #[arg(short = 'r', long)]
    rates: bool,

    /// Remove the path to a destination
    #[arg(short = 'd', long)]
    drop: bool,

    /// Drop all queued announces
    #[arg(short = 'D', long = "drop-announces")]
    drop_announces: bool,

    /// Drop all paths via specified transport instance
    #[arg(short = 'x', long = "drop-via")]
    drop_via: bool,

    /// Timeout in seconds (for path requests)
    #[arg(short = 'w', default_value = "60")]
    timeout: u64,

    /// List blackholed identities
    #[arg(short = 'b', long)]
    blackholed: bool,

    /// Blackhole an identity
    #[arg(short = 'B', long)]
    blackhole: bool,

    /// Remove an identity from blackhole
    #[arg(short = 'U', long)]
    unblackhole: bool,

    /// Duration of blackhole enforcement in hours
    #[arg(long, value_name = "HOURS")]
    duration: Option<f64>,

    /// Reason for blackholing identity
    #[arg(long, value_name = "REASON")]
    reason: Option<String>,

    /// Output in JSON format
    #[arg(short = 'j', long)]
    json: bool,

    /// Increase verbosity (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Transport identity hash of remote instance to manage
    #[arg(short = 'R', value_name = "HASH")]
    remote: Option<String>,

    /// Path to identity used for remote management authentication
    #[arg(short = 'i', value_name = "PATH")]
    identity: Option<PathBuf>,

    /// Timeout for remote queries (seconds)
    #[arg(short = 'W', value_name = "SECONDS", default_value = "15.0")]
    remote_timeout: f64,

    /// View published blackhole list for remote transport instance
    #[arg(short = 'p', long = "blackholed-list")]
    remote_blackholed_list: bool,

    /// Destination hash (required for some operations)
    destination: Option<String>,

    /// Filter for list views
    list_filter: Option<String>,
}

/// Path table entry for JSON output
#[derive(Debug, Clone, Serialize)]
struct PathTableJsonEntry {
    hash: String,
    timestamp: f64,
    via: String,
    hops: u8,
    expires: f64,
    interface: String,
}

/// Rate table entry for JSON output
#[derive(Debug, Clone, Serialize)]
struct RateTableJsonEntry {
    hash: String,
    last: f64,
    rate_violations: u32,
    blocked_until: f64,
    timestamps: Vec<f64>,
}

/// Blackhole entry for JSON output
#[derive(Debug, Clone, Serialize)]
struct BlackholeJsonEntry {
    hash: String,
    until: Option<f64>,
    reason: Option<String>,
}

#[tokio::main]
async fn main() {
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
            std::process::exit(20);
        }
    };

    // Dispatch to appropriate handler
    // Check for remote mode first
    let exit_code = if args.remote.is_some() {
        // Remote mode - query remote transport instance
        if args.remote_blackholed_list {
            handle_remote_blackholed_list(&args, &config).await
        } else if args.table {
            handle_remote_path_table(&args, &config).await
        } else if args.rates {
            handle_remote_rate_table(&args, &config).await
        } else if args.blackholed {
            // Python line 134: unsupported in remote mode
            if !args.json {
                println!("Listing blackholed identities on remote instances not yet implemented");
            }
            255
        } else if args.blackhole {
            // Python line 208: unsupported in remote mode
            if !args.json {
                println!("Blackholing identity on remote instances not yet implemented");
            }
            255
        } else if args.unblackhole {
            // Python line 227: unsupported in remote mode (same message as blackhole)
            if !args.json {
                println!("Blackholing identity on remote instances not yet implemented");
            }
            255
        } else if args.drop_announces {
            // Python line 382: unsupported in remote mode
            if !args.json {
                println!("Dropping announce queues on remote instances not yet implemented");
            }
            255
        } else if args.drop {
            // Python line 392: unsupported in remote mode
            if !args.json {
                println!("Dropping path on remote instances not yet implemented");
            }
            255
        } else if args.drop_via {
            // Python line 413: unsupported in remote mode (note: "yet not" is intentional)
            if !args.json {
                println!("Dropping all paths via specific transport instance on remote instances yet not implemented");
            }
            255
        } else if args.destination.is_some() {
            // Python line 434: unsupported in remote mode
            if !args.json {
                println!("Requesting paths on remote instances not implemented");
            }
            255
        } else {
            // No operation specified for remote mode
            if !args.json {
                eprintln!("Remote mode requires -t (table), -r (rates), or -p (blackholed-list).");
            }
            1
        }
    } else if args.blackholed {
        handle_blackholed_list(&args, &config).await
    } else if args.blackhole {
        handle_blackhole(&args, &config).await
    } else if args.unblackhole {
        handle_unblackhole(&args, &config).await
    } else if args.table {
        handle_path_table(&args, &config).await
    } else if args.rates {
        handle_rate_table(&args, &config).await
    } else if args.drop_announces {
        handle_drop_announces(&args, &config).await
    } else if args.drop {
        handle_drop_path(&args, &config).await
    } else if args.drop_via {
        handle_drop_via(&args, &config).await
    } else if args.destination.is_some() {
        handle_path_request(&args, &config).await
    } else {
        // No operation specified
        if !args.json {
            eprintln!("No operation specified. Use --help for usage.");
        }
        1
    };

    std::process::exit(exit_code);
}

/// Create a transport instance for querying
async fn create_transport(_config: &ReticulumConfig) -> Transport {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport_config = TransportConfig::new("rnpath", &identity, false);
    Transport::new(transport_config)
}

/// Create an RPC client for daemon communication with authentication.
///
/// Returns None if the daemon identity cannot be loaded.
fn create_rpc_client(config: &ReticulumConfig) -> Option<RpcClient> {
    let socket_dir = config.paths.config_dir.join("sockets");
    let rpc_addr = ListenerAddr::default_rpc("default", &socket_dir, config.control_port);

    // Compute RPC key
    let rpc_key = if let Some(ref key) = config.rpc_key {
        key.clone()
    } else {
        // Load daemon identity to derive key
        let identity_file = config.paths.identity_path.join("daemon_identity");
        if !identity_file.exists() {
            log::debug!("Daemon identity file not found: {:?}", identity_file);
            return None;
        }

        let identity_bytes = match fs::read(&identity_file) {
            Ok(bytes) if bytes.len() == 64 => bytes,
            Ok(_) => {
                log::debug!("Invalid daemon identity file length");
                return None;
            }
            Err(e) => {
                log::debug!("Failed to read daemon identity: {}", e);
                return None;
            }
        };

        // Derive RPC key: full_hash(private_key_bytes)
        Stamper::full_hash(&identity_bytes).to_vec()
    };

    Some(RpcClient::new(rpc_addr, rpc_key))
}

/// Check if a daemon is running
#[allow(dead_code)]
async fn is_daemon_running(config: &ReticulumConfig) -> bool {
    if let Some(client) = create_rpc_client(config) {
        client.is_daemon_running().await
    } else {
        false
    }
}

/// Handle path table display (-t)
async fn handle_path_table(args: &Args, config: &ReticulumConfig) -> i32 {
    // Try RPC first if daemon is running
    let rpc_paths = if let Some(client) = create_rpc_client(config) {
        client
            .get_path_table(args.max_hops.map(|h| h as u32))
            .await
            .ok()
    } else {
        None
    };

    // Convert RPC paths to internal format or fall back to transport
    let paths = if let Some(rpc_paths) = rpc_paths {
        // Convert from RPC format
        rpc_paths
            .into_iter()
            .map(|p| reticulum::transport::path_table::PathInfo {
                destination: p.destination_hash,
                next_hop: p.via.unwrap_or_default(),
                hops: p.hops as u8,
                timestamp: 0.0,
                expires: Some(p.expires),
                interface_hash: p.interface,
            })
            .collect()
    } else {
        // Fall back to local transport
        let transport = create_transport(config).await;
        transport.get_path_table(args.max_hops).await
    };

    // Filter by destination if provided
    let paths: Vec<_> = if let Some(ref dest_str) = args.destination {
        if let Ok(dest_hash) = parse_destination(dest_str) {
            let dest_hex = format_hash_hex(&dest_hash);
            paths
                .into_iter()
                .filter(|p| p.destination == dest_hex)
                .collect()
        } else {
            paths
        }
    } else {
        paths
    };

    if args.json {
        let json_entries: Vec<PathTableJsonEntry> = paths
            .iter()
            .map(|p| PathTableJsonEntry {
                hash: p.destination.clone(),
                timestamp: p.timestamp,
                via: p.next_hop.clone(),
                hops: p.hops,
                expires: p.expires.unwrap_or(0.0),
                interface: p.interface_hash.clone(),
            })
            .collect();

        println!("{}", serde_json::to_string_pretty(&json_entries).unwrap());
        return 0;
    }

    if paths.is_empty() {
        println!();
        println!("No paths in table");
        println!();
        return 1;
    }

    println!();
    for path in &paths {
        let hop_str = if path.hops == 1 { "hop" } else { "hops" };
        let expires_str = timestamp_str(path.expires.unwrap_or(0.0));

        println!(
            "<{}> is {} {} away via <{}> on <{}> expires {}",
            path.destination,
            path.hops,
            hop_str,
            path.next_hop,
            path.interface_hash,
            expires_str
        );
    }
    println!();

    0
}

/// Handle rate table display (-r)
async fn handle_rate_table(args: &Args, config: &ReticulumConfig) -> i32 {
    let transport = create_transport(config).await;

    // Get rate table
    let rates = transport.get_rate_table().await;

    // Filter by destination if provided
    let rates: Vec<_> = if let Some(ref dest_str) = args.destination {
        if let Ok(dest_hash) = parse_destination(dest_str) {
            let dest_hex = format_hash_hex(&dest_hash);
            rates
                .into_iter()
                .filter(|r| r.destination == dest_hex)
                .collect()
        } else {
            rates
        }
    } else {
        rates
    };

    if args.json {
        let json_entries: Vec<RateTableJsonEntry> = rates
            .iter()
            .map(|r| RateTableJsonEntry {
                hash: r.destination.clone(),
                last: r.last_announce.unwrap_or(0.0),
                rate_violations: r.violations,
                blocked_until: r.blocked_until.unwrap_or(0.0),
                timestamps: r.timestamps.clone(),
            })
            .collect();

        println!("{}", serde_json::to_string_pretty(&json_entries).unwrap());
        return 0;
    }

    if rates.is_empty() {
        println!();
        println!("No information available");
        println!();
        return 1;
    }

    println!();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    for rate in &rates {
        // Use format_time_ago for last heard, matching Python's pretty_date
        let last_str = if let Some(last) = rate.last_announce {
            format_time_ago(last)
        } else {
            "never".to_string()
        };

        // Calculate hourly rate
        let hour_rate = calculate_hourly_rate(&rate.timestamps, now);
        let span_str = calculate_span_str(&rate.timestamps);

        // Format rate: integer when whole, otherwise up to 3 decimal places
        let rate_str = if hour_rate.fract() == 0.0 {
            format!("{}", hour_rate as i64)
        } else {
            format!("{:.3}", hour_rate).trim_end_matches('0').to_string()
        };

        let mut suffix = String::new();

        // Rate violations
        if rate.violations > 0 {
            let plural = if rate.violations == 1 { "" } else { "s" };
            suffix.push_str(&format!(", {} active rate violation{}", rate.violations, plural));
        }

        // Blocked status: "new announces allowed in {time}"
        if let Some(blocked_until) = rate.blocked_until {
            if blocked_until > now {
                // Python uses pretty_date(2*now - until) to show remaining time
                let remaining_ts = 2.0 * now - blocked_until;
                suffix.push_str(&format!(
                    ", new announces allowed in {}",
                    format_time_ago(remaining_ts)
                ));
            }
        }

        println!(
            "<{}> last heard {} ago, {} announces/hour in the last {}{}",
            rate.destination,
            last_str,
            rate_str,
            span_str,
            suffix
        );
    }
    println!();

    0
}

/// Handle path request (default mode)
async fn handle_path_request(args: &Args, config: &ReticulumConfig) -> i32 {
    let dest_str = args.destination.as_ref().unwrap();
    let dest_hash = match parse_destination(dest_str) {
        Ok(hash) => hash,
        Err(e) => {
            if !args.json {
                eprintln!("Error: {}", e);
            }
            return 20;
        }
    };

    let transport = create_transport(config).await;
    let timeout = Duration::from_secs(args.timeout);

    if !args.json {
        print!("Path request to {} ", pretty_hash(&dest_hash));
        io::stdout().flush().ok();
    }

    // Check if path already exists
    if transport.has_path(&dest_hash).await {
        return display_path_result(&transport, &dest_hash, args).await;
    }

    // Send a path request to the network
    transport.request_path(&dest_hash, None).await;

    // Spinner animation characters (matching Python)
    let spinner = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];
    let mut spinner_idx = 0;
    let start = Instant::now();

    // Poll for path with timeout
    while start.elapsed() < timeout {
        if transport.has_path(&dest_hash).await {
            if !args.json {
                print!("\r                                                       \r");
            }
            return display_path_result(&transport, &dest_hash, args).await;
        }

        if !args.json {
            print!("\r{} ", spinner[spinner_idx % spinner.len()]);
            io::stdout().flush().ok();
            spinner_idx += 1;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Timeout - no path found
    if args.json {
        let mut error_obj = serde_json::Map::new();
        error_obj.insert(
            "error".to_string(),
            serde_json::Value::String("path_not_found".to_string()),
        );
        error_obj.insert(
            "destination".to_string(),
            serde_json::Value::String(format_hash_hex(&dest_hash)),
        );
        println!("{}", serde_json::to_string_pretty(&error_obj).unwrap());
    } else {
        print!("\r                                                       \r");
        println!("Path not found");
    }

    12 // Path request timeout exit code
}

/// Display path result after finding a path
async fn display_path_result(transport: &Transport, dest_hash: &AddressHash, args: &Args) -> i32 {
    let hops = transport.hops_to(dest_hash).await.unwrap_or(0);
    let next_hop = transport.get_next_hop(dest_hash).await;
    let iface = transport.get_next_hop_iface(dest_hash).await;

    if args.json {
        let mut result = serde_json::Map::new();
        result.insert(
            "destination".to_string(),
            serde_json::Value::String(format_hash_hex(dest_hash)),
        );
        result.insert("hops".to_string(), serde_json::Value::Number(hops.into()));
        if let Some(ref nh) = next_hop {
            result.insert(
                "next_hop".to_string(),
                serde_json::Value::String(format_hash_hex(nh)),
            );
        }
        if let Some(ref i) = iface {
            result.insert(
                "interface".to_string(),
                serde_json::Value::String(format_hash_hex(i)),
            );
        }
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        let hop_str = if hops == 1 { "hop" } else { "hops" };
        let next_hop_str = next_hop
            .map(|h| pretty_hash(&h))
            .unwrap_or_else(|| "unknown".to_string());
        let iface_str = iface
            .map(|h| pretty_hash(&h))
            .unwrap_or_else(|| "unknown".to_string());

        println!(
            "Path found, destination {} is {} {} away via {} on {}",
            pretty_hash(dest_hash),
            hops,
            hop_str,
            next_hop_str,
            iface_str
        );
    }

    0
}

/// Handle drop path (-d)
async fn handle_drop_path(args: &Args, config: &ReticulumConfig) -> i32 {
    let dest_str = match &args.destination {
        Some(d) => d,
        None => {
            if !args.json {
                eprintln!("Error: Destination hash required for drop operation");
            }
            return 20;
        }
    };

    let dest_hash = match parse_destination(dest_str) {
        Ok(hash) => hash,
        Err(e) => {
            if !args.json {
                eprintln!("Error: {}", e);
            }
            return 20;
        }
    };

    // Try RPC first if daemon is running
    let success = if let Some(client) = create_rpc_client(config) {
        match client.drop_path(dest_hash.as_slice()).await {
            Ok(()) => true,
            Err(_) => {
                // Fall back to local transport
                let transport = create_transport(config).await;
                transport.drop_path(&dest_hash).await
            }
        }
    } else {
        // Fall back to local transport
        let transport = create_transport(config).await;
        transport.drop_path(&dest_hash).await
    };

    if success {
        if !args.json {
            println!("Dropped path to {}", pretty_hash(&dest_hash));
        }
        0
    } else {
        if !args.json {
            println!("Unable to drop path to {}. Does it exist?", pretty_hash(&dest_hash));
        }
        1
    }
}

/// Handle drop via (-x)
async fn handle_drop_via(args: &Args, config: &ReticulumConfig) -> i32 {
    let transport_str = match &args.destination {
        Some(d) => d,
        None => {
            if !args.json {
                eprintln!("Error: Transport hash required for drop-via operation");
            }
            return 20;
        }
    };

    let transport_hash = match parse_destination(transport_str) {
        Ok(hash) => hash,
        Err(e) => {
            if !args.json {
                eprintln!("Error: {}", e);
            }
            return 20;
        }
    };

    // Try RPC first if daemon is running
    let rpc_success = if let Some(client) = create_rpc_client(config) {
        client.drop_all_via(transport_hash.as_slice()).await.is_ok()
    } else {
        false
    };

    if !rpc_success {
        // Fall back to local transport
        let transport = create_transport(config).await;
        let count = transport.drop_via(&transport_hash).await;
        if count == 0 {
            if !args.json {
                println!(
                    "Unable to drop paths via {}. Does the transport instance exist?",
                    pretty_hash(&transport_hash)
                );
            }
            return 1;
        }
        if !args.json {
            println!("Dropped all paths via {}", pretty_hash(&transport_hash));
        }
    } else if !args.json {
        println!("Dropped all paths via {}", pretty_hash(&transport_hash));
    }

    0
}

/// Handle drop announces (-D)
async fn handle_drop_announces(args: &Args, config: &ReticulumConfig) -> i32 {
    // RPC doesn't have a dedicated drop_announce_queues method yet,
    // so we always use local transport
    let transport = create_transport(config).await;
    transport.drop_announce_queues().await;

    if !args.json {
        println!("Dropping announce queues on all interfaces...");
    }

    0
}

/// Handle blackholed list (-b)
async fn handle_blackholed_list(args: &Args, config: &ReticulumConfig) -> i32 {
    // Load blackhole manager from file
    let blackhole_path = config.paths.blackhole_path.join("blackhole.txt");
    let blackhole_path_str = blackhole_path.to_string_lossy();
    let manager = BlackholeManager::with_file(&blackhole_path_str);

    let hashes = manager.list();

    // Filter if filter argument provided
    let hashes: Vec<_> = if let Some(ref filter) = args.list_filter {
        let filter_lower = filter.to_lowercase();
        hashes
            .into_iter()
            .filter(|hash| format_hash_hex(hash).to_lowercase().contains(&filter_lower))
            .collect()
    } else {
        hashes
    };

    if args.json {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let json_entries: Vec<BlackholeJsonEntry> = hashes
            .iter()
            .map(|hash| {
                let entry = manager.get(hash);
                let until = entry.as_ref().and_then(|e| {
                    e.expires_at.map(|exp| {
                        let remaining = exp.saturating_duration_since(std::time::Instant::now());
                        now + remaining.as_secs_f64()
                    })
                });
                let reason = entry.as_ref().and_then(|e| e.reason.clone());

                BlackholeJsonEntry {
                    hash: format_hash_hex(hash),
                    until,
                    reason,
                }
            })
            .collect();

        println!("{}", serde_json::to_string_pretty(&json_entries).unwrap());
        return 0;
    }

    if hashes.is_empty() {
        println!();
        println!("No blackholed identities");
        println!();
        return 0;
    }

    println!();
    for hash in &hashes {
        let entry = manager.get(hash);
        let until_str = if let Some(ref e) = entry {
            if let Some(exp) = e.expires_at {
                let remaining = exp.saturating_duration_since(std::time::Instant::now());
                format!("for {}", format_time(remaining.as_secs_f64()))
            } else {
                "indefinitely".to_string()
            }
        } else {
            "indefinitely".to_string()
        };

        let reason_str = entry
            .as_ref()
            .and_then(|e| e.reason.as_ref())
            .map(|r| {
                let truncated = if r.len() > 64 { &r[..64] } else { r.as_str() };
                format!(" ({})", truncated)
            })
            .unwrap_or_default();

        println!(
            "{} blackholed {}{}",
            pretty_hash(hash),
            until_str,
            reason_str
        );
    }
    println!();

    0
}

/// Handle blackhole add (-B)
async fn handle_blackhole(args: &Args, config: &ReticulumConfig) -> i32 {
    let identity_str = match &args.destination {
        Some(d) => d,
        None => {
            if !args.json {
                eprintln!("Error: Identity hash required for blackhole operation");
            }
            return 20;
        }
    };

    let identity_hash = match parse_destination(identity_str) {
        Ok(hash) => hash,
        Err(e) => {
            if !args.json {
                eprintln!("Error: {}", e);
            }
            return 20;
        }
    };

    // Load blackhole manager
    let blackhole_path = config.paths.blackhole_path.join("blackhole.txt");
    let blackhole_path_str = blackhole_path.to_string_lossy();
    let manager = BlackholeManager::with_file(&blackhole_path_str);

    if manager.is_blackholed(&identity_hash) {
        if !args.json {
            println!("Identity {} already blackholed", format_hash_hex(&identity_hash));
        }
        return 0;
    }

    // Add to blackhole with or without expiry
    if let Some(hours) = args.duration {
        let duration = Duration::from_secs_f64(hours * 3600.0);
        manager.add_temporary(identity_hash, duration);
    } else {
        manager.add(identity_hash);
    }

    // Save to file
    let _ = manager.save();

    if !args.json {
        println!("Blackholed identity {}", format_hash_hex(&identity_hash));
    }

    0
}

/// Handle unblackhole (-U)
async fn handle_unblackhole(args: &Args, config: &ReticulumConfig) -> i32 {
    let identity_str = match &args.destination {
        Some(d) => d,
        None => {
            if !args.json {
                eprintln!("Error: Identity hash required for unblackhole operation");
            }
            return 20;
        }
    };

    let identity_hash = match parse_destination(identity_str) {
        Ok(hash) => hash,
        Err(e) => {
            if !args.json {
                eprintln!("Error: {}", e);
            }
            return 20;
        }
    };

    // Load blackhole manager
    let blackhole_path = config.paths.blackhole_path.join("blackhole.txt");
    let blackhole_path_str = blackhole_path.to_string_lossy();
    let manager = BlackholeManager::with_file(&blackhole_path_str);

    if manager.remove(&identity_hash).is_some() {
        // Save after removing
        let _ = manager.save();
        if !args.json {
            println!("Lifted blackhole for identity {}", format_hash_hex(&identity_hash));
        }
        0
    } else {
        if !args.json {
            println!("Identity {} not blackholed", format_hash_hex(&identity_hash));
        }
        1
    }
}

// =============================================================================
// Remote management handlers
// =============================================================================

/// Handle remote path table query (-R with -t)
async fn handle_remote_path_table(args: &Args, config: &ReticulumConfig) -> i32 {
    let transport_hash_str = args.remote.as_ref().unwrap();

    if !args.json {
        println!("Querying remote transport <{}>", transport_hash_str);
    }

    // Parse transport hash
    let transport_hash = match remote_client::parse_transport_hash(transport_hash_str) {
        Ok(hash) => hash,
        Err(e) => {
            if !args.json {
                eprintln!("Error: {}", e);
            }
            return 1;
        }
    };

    // Load identity if specified
    let identity = if let Some(ref path) = args.identity {
        match remote_client::load_identity(path) {
            Ok(id) => Some(id),
            Err(e) => {
                if !args.json {
                    eprintln!("Error loading identity: {}", e);
                }
                return 2;
            }
        }
    } else {
        Some(PrivateIdentity::new_from_rand(OsRng))
    };

    // Create transport and client
    let transport = remote_client::create_client_transport(config, "rnpath").await;
    let client_config = RemoteClientConfig {
        timeout: Duration::from_secs_f64(args.remote_timeout),
        identity,
    };
    let client = RemoteClient::new(transport, client_config);

    if !args.json {
        print!("Establishing link... ");
        io::stdout().flush().ok();
    }

    // Connect to remote management destination
    let link = match client.connect(REMOTE_MANAGEMENT_ASPECT, &transport_hash).await {
        Ok(link) => {
            if !args.json {
                println!("OK");
            }
            link
        }
        Err(e) => {
            if !args.json {
                println!("failed");
                eprintln!("Error: {}", e);
            }
            return 10;
        }
    };

    if !args.json {
        print!("Requesting path table... ");
        io::stdout().flush().ok();
    }

    // Build request data: ["table", nil, max_hops]
    let request_data = build_path_request("table", args.max_hops);

    // Send request
    match client.request(&link, "/path", &request_data).await {
        Ok(response) => {
            if !args.json {
                println!("OK");
                println!();
            }

            // Parse and display response
            match parse_path_table_response(&response) {
                Ok(entries) => {
                    display_path_table(args, &entries);
                    0
                }
                Err(e) => {
                    if !args.json {
                        eprintln!("Error parsing response: {}", e);
                    }
                    16
                }
            }
        }
        Err(e) => {
            if !args.json {
                println!("failed");
                eprintln!("Error: {}", e);
            }
            15
        }
    }
}

/// Handle remote rate table query (-R with -r)
async fn handle_remote_rate_table(args: &Args, config: &ReticulumConfig) -> i32 {
    let transport_hash_str = args.remote.as_ref().unwrap();

    if !args.json {
        println!("Querying remote transport <{}>", transport_hash_str);
    }

    // Parse transport hash
    let transport_hash = match remote_client::parse_transport_hash(transport_hash_str) {
        Ok(hash) => hash,
        Err(e) => {
            if !args.json {
                eprintln!("Error: {}", e);
            }
            return 1;
        }
    };

    // Load identity if specified
    let identity = if let Some(ref path) = args.identity {
        match remote_client::load_identity(path) {
            Ok(id) => Some(id),
            Err(e) => {
                if !args.json {
                    eprintln!("Error loading identity: {}", e);
                }
                return 2;
            }
        }
    } else {
        Some(PrivateIdentity::new_from_rand(OsRng))
    };

    // Create transport and client
    let transport = remote_client::create_client_transport(config, "rnpath").await;
    let client_config = RemoteClientConfig {
        timeout: Duration::from_secs_f64(args.remote_timeout),
        identity,
    };
    let client = RemoteClient::new(transport, client_config);

    if !args.json {
        print!("Establishing link... ");
        io::stdout().flush().ok();
    }

    // Connect to remote management destination
    let link = match client.connect(REMOTE_MANAGEMENT_ASPECT, &transport_hash).await {
        Ok(link) => {
            if !args.json {
                println!("OK");
            }
            link
        }
        Err(e) => {
            if !args.json {
                println!("failed");
                eprintln!("Error: {}", e);
            }
            return 10;
        }
    };

    if !args.json {
        print!("Requesting rate table... ");
        io::stdout().flush().ok();
    }

    // Build request data: ["rates"]
    let request_data = build_path_request("rates", None);

    // Send request
    match client.request(&link, "/path", &request_data).await {
        Ok(response) => {
            if !args.json {
                println!("OK");
                println!();
            }

            // Parse and display response
            match parse_rate_table_response(&response) {
                Ok(entries) => {
                    display_rate_table(args, &entries);
                    0
                }
                Err(e) => {
                    if !args.json {
                        eprintln!("Error parsing response: {}", e);
                    }
                    16
                }
            }
        }
        Err(e) => {
            if !args.json {
                println!("failed");
                eprintln!("Error: {}", e);
            }
            15
        }
    }
}

/// Handle remote blackhole list query (-R with -p)
async fn handle_remote_blackholed_list(args: &Args, config: &ReticulumConfig) -> i32 {
    let transport_hash_str = args.remote.as_ref().unwrap();

    if !args.json {
        println!("Querying remote transport <{}>", transport_hash_str);
    }

    // Parse transport hash
    let transport_hash = match remote_client::parse_transport_hash(transport_hash_str) {
        Ok(hash) => hash,
        Err(e) => {
            if !args.json {
                eprintln!("Error: {}", e);
            }
            return 1;
        }
    };

    // Blackhole info destination is public (ALLOW_ALL), no identity needed
    // But we still need a temporary identity for the link handshake
    let identity = Some(PrivateIdentity::new_from_rand(OsRng));

    // Create transport and client
    let transport = remote_client::create_client_transport(config, "rnpath").await;
    let client_config = RemoteClientConfig {
        timeout: Duration::from_secs_f64(args.remote_timeout),
        identity,
    };
    let client = RemoteClient::new(transport, client_config);

    if !args.json {
        print!("Establishing link... ");
        io::stdout().flush().ok();
    }

    // Connect to blackhole info destination (public, not management)
    let link = match client.connect(BLACKHOLE_INFO_ASPECT, &transport_hash).await {
        Ok(link) => {
            if !args.json {
                println!("OK");
            }
            link
        }
        Err(e) => {
            if !args.json {
                println!("failed");
                eprintln!("Error: {}", e);
            }
            return 10;
        }
    };

    if !args.json {
        print!("Requesting blackhole list... ");
        io::stdout().flush().ok();
    }

    // Build request data (empty for /list)
    let request_data = {
        let value = rmpv::Value::Nil;
        let mut packed = Vec::new();
        rmpv::encode::write_value(&mut packed, &value).unwrap();
        packed
    };

    // Send request
    match client.request(&link, "/list", &request_data).await {
        Ok(response) => {
            if !args.json {
                println!("OK");
                println!();
            }

            // Parse and display response
            match parse_blackhole_list_response(&response) {
                Ok(entries) => {
                    display_blackhole_list(args, &entries);
                    0
                }
                Err(e) => {
                    if !args.json {
                        eprintln!("Error parsing response: {}", e);
                    }
                    16
                }
            }
        }
        Err(e) => {
            if !args.json {
                println!("failed");
                eprintln!("Error: {}", e);
            }
            15
        }
    }
}

/// Build a /path request payload
fn build_path_request(command: &str, max_hops: Option<u8>) -> Vec<u8> {
    let mut arr = vec![rmpv::Value::String(command.into())];

    // Add nil for destination_hash (no filter)
    arr.push(rmpv::Value::Nil);

    // Add max_hops if specified
    if let Some(hops) = max_hops {
        arr.push(rmpv::Value::Integer(hops.into()));
    }

    let value = rmpv::Value::Array(arr);
    let mut packed = Vec::new();
    rmpv::encode::write_value(&mut packed, &value).unwrap();
    packed
}

/// Remote path entry from response
#[derive(Debug, Clone)]
struct RemotePathEntry {
    hash: String,
    timestamp: f64,
    via: String,
    hops: u8,
    expires: Option<f64>,
    interface: String,
}

/// Remote rate entry from response
#[derive(Debug, Clone)]
struct RemoteRateEntry {
    hash: String,
    last: Option<f64>,
    rate_violations: u32,
    blocked_until: Option<f64>,
    timestamps: Vec<f64>,
}

/// Parse path table response from remote
fn parse_path_table_response(data: &[u8]) -> Result<Vec<RemotePathEntry>, String> {
    // Response format: [request_id, response_data]
    // where response_data is an array of path entries
    let response_data = remote_client::parse_response(data)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&response_data))
        .map_err(|e| format!("Failed to decode inner response: {}", e))?;

    let arr = value.as_array().ok_or("Response is not an array")?;

    let mut entries = Vec::new();
    for item in arr {
        if let Some(entry) = parse_remote_path_entry(item) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Parse a single path entry from response
fn parse_remote_path_entry(value: &rmpv::Value) -> Option<RemotePathEntry> {
    let map = value.as_map()?;

    let get_str = |key: &str| -> Option<String> {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .and_then(|(_, v)| v.as_str().map(|s| s.to_string()))
    };

    let get_f64 = |key: &str| -> Option<f64> {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .and_then(|(_, v)| v.as_f64())
    };

    let get_u8 = |key: &str| -> Option<u8> {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .and_then(|(_, v)| v.as_u64().map(|n| n as u8))
    };

    Some(RemotePathEntry {
        hash: get_str("hash")?,
        timestamp: get_f64("timestamp").unwrap_or(0.0),
        via: get_str("via").unwrap_or_default(),
        hops: get_u8("hops").unwrap_or(0),
        expires: get_f64("expires"),
        interface: get_str("interface").unwrap_or_default(),
    })
}

/// Parse rate table response from remote
fn parse_rate_table_response(data: &[u8]) -> Result<Vec<RemoteRateEntry>, String> {
    let response_data = remote_client::parse_response(data)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&response_data))
        .map_err(|e| format!("Failed to decode inner response: {}", e))?;

    let arr = value.as_array().ok_or("Response is not an array")?;

    let mut entries = Vec::new();
    for item in arr {
        if let Some(entry) = parse_remote_rate_entry(item) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Parse a single rate entry from response
fn parse_remote_rate_entry(value: &rmpv::Value) -> Option<RemoteRateEntry> {
    let map = value.as_map()?;

    let get_str = |key: &str| -> Option<String> {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .and_then(|(_, v)| v.as_str().map(|s| s.to_string()))
    };

    let get_f64_opt = |key: &str| -> Option<f64> {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .and_then(|(_, v)| if v.is_nil() { None } else { v.as_f64() })
    };

    let get_u32 = |key: &str| -> u32 {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .and_then(|(_, v)| v.as_u64())
            .map(|n| n as u32)
            .unwrap_or(0)
    };

    let get_timestamps = |key: &str| -> Vec<f64> {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .and_then(|(_, v)| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_f64()).collect())
            .unwrap_or_default()
    };

    Some(RemoteRateEntry {
        hash: get_str("hash")?,
        last: get_f64_opt("last"),
        rate_violations: get_u32("rate_violations"),
        blocked_until: get_f64_opt("blocked_until"),
        timestamps: get_timestamps("timestamps"),
    })
}

/// Remote blackhole entry from response
#[derive(Debug, Clone)]
struct RemoteBlackholeEntry {
    hash: String,
    source: String,
    until: Option<f64>,
    reason: Option<String>,
}

/// Parse blackhole list response from remote
///
/// Response format (Python-compatible dict):
/// {
///   identity_hash_bytes: {
///     "source": source_hash_bytes,
///     "until": f64 or nil,
///     "reason": string or nil
///   },
///   ...
/// }
fn parse_blackhole_list_response(data: &[u8]) -> Result<Vec<RemoteBlackholeEntry>, String> {
    let response_data = remote_client::parse_response(data)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&response_data))
        .map_err(|e| format!("Failed to decode inner response: {}", e))?;

    let map = value.as_map().ok_or("Response is not a map")?;

    let mut entries = Vec::new();
    for (key, entry_value) in map {
        // Key is identity hash (binary)
        let hash = if let Some(bytes) = key.as_slice() {
            hex::encode(bytes)
        } else if let Some(s) = key.as_str() {
            s.to_string()
        } else {
            continue;
        };

        // Value is a map with source, until, reason
        if let Some(entry_map) = entry_value.as_map() {
            let get_bin = |key_name: &str| -> Option<String> {
                entry_map.iter()
                    .find(|(k, _)| k.as_str() == Some(key_name))
                    .and_then(|(_, v)| v.as_slice().map(hex::encode))
            };

            let get_f64_opt = |key_name: &str| -> Option<f64> {
                entry_map.iter()
                    .find(|(k, _)| k.as_str() == Some(key_name))
                    .and_then(|(_, v)| if v.is_nil() { None } else { v.as_f64() })
            };

            let get_str_opt = |key_name: &str| -> Option<String> {
                entry_map.iter()
                    .find(|(k, _)| k.as_str() == Some(key_name))
                    .and_then(|(_, v)| if v.is_nil() { None } else { v.as_str().map(|s| s.to_string()) })
            };

            entries.push(RemoteBlackholeEntry {
                hash,
                source: get_bin("source").unwrap_or_default(),
                until: get_f64_opt("until"),
                reason: get_str_opt("reason"),
            });
        }
    }

    Ok(entries)
}

/// Display blackhole list entries
fn display_blackhole_list(args: &Args, entries: &[RemoteBlackholeEntry]) {
    use std::time::{SystemTime, UNIX_EPOCH};

    if args.json {
        let json_entries: Vec<BlackholeJsonEntry> = entries
            .iter()
            .map(|e| BlackholeJsonEntry {
                hash: e.hash.clone(),
                until: e.until,
                reason: e.reason.clone(),
            })
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&json_entries) {
            println!("{}", json);
        }
        return;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    if entries.is_empty() {
        println!("No blackholed identity data available");
        return;
    }

    for entry in entries {
        // Show remaining duration, matching Python's "for {prettytime(remaining)}"
        let until_str = if let Some(until) = entry.until {
            let remaining = (until - now).max(0.0);
            format!("for {}", format_time(remaining))
        } else {
            "indefinitely".to_string()
        };

        // Truncate reason at 64 chars with ellipsis, matching Python's rmlen=64
        let reason_str = entry.reason.as_ref()
            .map(|r| {
                let truncated = if r.len() > 64 {
                    format!("{}…", &r[..63])
                } else {
                    r.clone()
                };
                format!(" ({})", truncated)
            })
            .unwrap_or_default();

        // Show source as "by <SOURCE>", matching Python line 190
        let source_str = if !entry.source.is_empty() {
            format!(" by <{}>", &entry.source)
        } else {
            String::new()
        };

        println!(
            "<{}> blackholed {}{}{}",
            entry.hash,
            until_str,
            reason_str,
            source_str,
        );
    }
}

/// Display path table entries (reused for both local and remote)
fn display_path_table(args: &Args, entries: &[RemotePathEntry]) {
    use std::time::{SystemTime, UNIX_EPOCH};

    if args.json {
        let json_entries: Vec<PathTableJsonEntry> = entries
            .iter()
            .map(|e| PathTableJsonEntry {
                hash: e.hash.clone(),
                timestamp: e.timestamp,
                via: e.via.clone(),
                hops: e.hops,
                expires: e.expires.unwrap_or(0.0),
                interface: e.interface.clone(),
            })
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&json_entries) {
            println!("{}", json);
        }
        return;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    if entries.is_empty() {
        println!("No paths in table");
        return;
    }

    println!("Path Table:");
    for entry in entries {
        let expires_in = entry.expires.map(|e| e - now).unwrap_or(0.0);
        let expires_str = if expires_in > 0.0 {
            format!(" expires {}", format_time(expires_in))
        } else {
            String::new()
        };

        println!(
            "  <{}> {} hop{} via <{}>{} [{}]",
            entry.hash,
            entry.hops,
            if entry.hops == 1 { "" } else { "s" },
            entry.via,
            expires_str,
            entry.interface,
        );
    }
}

/// Display rate table entries (reused for both local and remote)
fn display_rate_table(args: &Args, entries: &[RemoteRateEntry]) {
    use std::time::{SystemTime, UNIX_EPOCH};

    if args.json {
        let json_entries: Vec<RateTableJsonEntry> = entries
            .iter()
            .map(|e| RateTableJsonEntry {
                hash: e.hash.clone(),
                last: e.last.unwrap_or(0.0),
                rate_violations: e.rate_violations,
                blocked_until: e.blocked_until.unwrap_or(0.0),
                timestamps: e.timestamps.clone(),
            })
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&json_entries) {
            println!("{}", json);
        }
        return;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    if entries.is_empty() {
        println!("No information available");
        return;
    }

    for entry in entries {
        let rate = calculate_hourly_rate(&entry.timestamps, now);
        let span = calculate_span_str(&entry.timestamps);

        // Format rate: integer when whole, otherwise up to 3 decimal places (trim trailing zeros)
        let rate_str = if rate.fract() == 0.0 {
            format!("{}", rate as i64)
        } else {
            format!("{:.3}", rate).trim_end_matches('0').to_string()
        };

        // Use format_time_ago for last heard, matching Python's pretty_date
        let last_str = entry.last
            .map(|ts| format_time_ago(ts))
            .unwrap_or_else(|| "never".to_string());

        // Rate violations suffix
        let rv_str = if entry.rate_violations > 0 {
            let plural = if entry.rate_violations == 1 { "" } else { "s" };
            format!(", {} active rate violation{}", entry.rate_violations, plural)
        } else {
            String::new()
        };

        // Blocked status: "new announces allowed in {time}"
        let blocked_str = if let Some(until) = entry.blocked_until {
            if until > now {
                // Python uses pretty_date(2*now - until) to show remaining time
                let remaining_ts = 2.0 * now - until;
                format!(", new announces allowed in {}", format_time_ago(remaining_ts))
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        println!(
            "<{}> last heard {} ago, {} announces/hour in the last {}{}{}",
            entry.hash,
            last_str,
            rate_str,
            span,
            rv_str,
            blocked_str,
        );
    }
}

// =============================================================================
// Formatting utilities
// =============================================================================

/// Format an AddressHash as a pretty hex string with angle brackets
fn pretty_hash(hash: &AddressHash) -> String {
    format!("<{}>", format_hash_hex(hash))
}

/// Format a Unix timestamp as a human-readable string
fn timestamp_str(ts: f64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    if ts <= 0.0 {
        return "unknown".to_string();
    }

    let diff = ts - now;
    if diff > 0.0 {
        format!("in {}", format_time(diff))
    } else {
        format!("{} ago", format_time(-diff))
    }
}

/// Calculate hourly announce rate from timestamps.
///
/// Matches Python's algorithm: uses ALL timestamps, enforces minimum 1-hour span,
/// and rounds to 3 decimal places.
fn calculate_hourly_rate(timestamps: &[f64], now: f64) -> f64 {
    if timestamps.is_empty() {
        return 0.0;
    }
    let first_ts = timestamps[0];
    let span = (now - first_ts).max(3600.0);
    let span_hours = span / 3600.0;
    let rate = timestamps.len() as f64 / span_hours;
    (rate * 1000.0).round() / 1000.0
}

/// Calculate the time span string for rate display.
///
/// Matches Python: `pretty_date(int(entry["timestamps"][0]))`.
fn calculate_span_str(timestamps: &[f64]) -> String {
    if timestamps.is_empty() {
        return "0 seconds".to_string();
    }
    format_time_ago(timestamps[0])
}
