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

use reticulum::config::{LogLevel, ReticulumConfig};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::ipc::addr::ListenerAddr;
use reticulum::logging;
use reticulum::rpc::RpcClient;
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
    let exit_code = if args.blackholed {
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

/// Parse a destination hash string
fn parse_destination(dest_str: &str) -> Result<AddressHash, String> {
    // Remove any / prefix/suffix if present
    let clean = dest_str
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim_start_matches('/')
        .trim_end_matches('/');

    // Validate length (should be 32 hex chars = 16 bytes)
    if clean.len() != 32 {
        return Err(format!(
            "Invalid hash length: expected 32 hex characters, got {}",
            clean.len()
        ));
    }

    AddressHash::new_from_hex_string(clean)
        .map_err(|_| "Invalid hexadecimal string".to_string())
}

/// Create a transport instance for querying
async fn create_transport(_config: &ReticulumConfig) -> Transport {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport_config = TransportConfig::new("rnpath", &identity, false);
    Transport::new(transport_config)
}

/// Create an RPC client for daemon communication
fn create_rpc_client(config: &ReticulumConfig) -> RpcClient {
    let socket_dir = config.paths.config_dir.join("sockets");
    let rpc_addr = ListenerAddr::default_rpc("default", &socket_dir, config.control_port);
    RpcClient::new(rpc_addr)
}

/// Check if a daemon is running
async fn is_daemon_running(config: &ReticulumConfig) -> bool {
    let client = create_rpc_client(config);
    client.is_daemon_running().await
}

/// Handle path table display (-t)
async fn handle_path_table(args: &Args, config: &ReticulumConfig) -> i32 {
    // Try RPC first if daemon is running
    let client = create_rpc_client(config);
    let rpc_paths = client
        .get_path_table(args.max_hops.map(|h| h as u32))
        .await
        .ok();

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
        println!("No rate information available");
        println!();
        return 1;
    }

    println!();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    for rate in &rates {
        let last_str = if let Some(last) = rate.last_announce {
            let ago = now - last;
            pretty_time(ago)
        } else {
            "never".to_string()
        };

        // Calculate hourly rate
        let hour_rate = calculate_hourly_rate(&rate.timestamps, now);
        let span_str = calculate_span_str(&rate.timestamps, now);

        let mut suffix = String::new();

        // Rate violations
        if rate.violations > 0 {
            let word = if rate.violations == 1 {
                "violation"
            } else {
                "violations"
            };
            suffix.push_str(&format!(", {} active rate {}", rate.violations, word));
        }

        // Blocked status
        if let Some(blocked_until) = rate.blocked_until {
            if blocked_until > now {
                let remaining = blocked_until - now;
                suffix.push_str(&format!(
                    ", new announces allowed in {}",
                    pretty_time(remaining)
                ));
            }
        }

        println!(
            "<{}> last heard {} ago, {:.1} announces/hour in the last {}{}",
            rate.destination,
            last_str,
            hour_rate,
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
    let client = create_rpc_client(config);
    let rpc_result = client.drop_path(dest_hash.as_slice()).await;

    let success = match rpc_result {
        Ok(()) => true,
        Err(_) => {
            // Fall back to local transport
            let transport = create_transport(config).await;
            transport.drop_path(&dest_hash).await
        }
    };

    if success {
        if !args.json {
            println!("Dropped path to {}", pretty_hash(&dest_hash));
        }
        0
    } else {
        if !args.json {
            println!("No path to {} in table", pretty_hash(&dest_hash));
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
    let client = create_rpc_client(config);
    let rpc_result = client.drop_all_via(transport_hash.as_slice()).await;

    if rpc_result.is_err() {
        // Fall back to local transport
        let transport = create_transport(config).await;
        let count = transport.drop_via(&transport_hash).await;
        if !args.json {
            let path_word = if count == 1 { "path" } else { "paths" };
            println!(
                "Dropped {} {} via {}",
                count,
                path_word,
                pretty_hash(&transport_hash)
            );
        }
    } else if !args.json {
        println!(
            "Dropped paths via {} (via daemon)",
            pretty_hash(&transport_hash)
        );
    }

    0
}

/// Handle drop announces (-D)
async fn handle_drop_announces(args: &Args, config: &ReticulumConfig) -> i32 {
    // Try RPC first if daemon is running
    let client = create_rpc_client(config);
    if client.is_daemon_running().await {
        // RPC doesn't have a dedicated drop_announce_queues method yet,
        // so we fall back to local transport
    }

    let transport = create_transport(config).await;
    transport.drop_announce_queues().await;

    if !args.json {
        println!("Dropped all queued announces");
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
                format!("for {}", pretty_time(remaining.as_secs_f64()))
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
            println!("{} is already blackholed", pretty_hash(&identity_hash));
        }
        return 0;
    }

    // Add to blackhole with or without expiry
    if let Some(hours) = args.duration {
        let duration = Duration::from_secs_f64(hours * 3600.0);
        manager.add_temporary(identity_hash.clone(), duration);
    } else {
        manager.add(identity_hash.clone());
    }

    // Save to file
    let _ = manager.save();

    if !args.json {
        let duration_str = args
            .duration
            .map(|h| format!(" for {} hours", h))
            .unwrap_or_else(|| " indefinitely".to_string());

        println!(
            "Blackholed {}{}",
            pretty_hash(&identity_hash),
            duration_str
        );
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
            println!("Removed {} from blackhole", pretty_hash(&identity_hash));
        }
        0
    } else {
        if !args.json {
            println!("{} was not blackholed", pretty_hash(&identity_hash));
        }
        1
    }
}

// =============================================================================
// Formatting utilities
// =============================================================================

/// Format an AddressHash as a pretty hex string with angle brackets
fn pretty_hash(hash: &AddressHash) -> String {
    format!("<{}>", format_hash_hex(hash))
}

/// Format an AddressHash as a plain hex string
fn format_hash_hex(hash: &AddressHash) -> String {
    hash.as_slice()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Format seconds as human-readable time
fn pretty_time(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{:.0} seconds", seconds)
    } else if seconds < 3600.0 {
        let mins = seconds / 60.0;
        if mins < 2.0 {
            "1 minute".to_string()
        } else {
            format!("{:.0} minutes", mins)
        }
    } else if seconds < 86400.0 {
        let hours = seconds / 3600.0;
        if hours < 2.0 {
            "1 hour".to_string()
        } else {
            format!("{:.0} hours", hours)
        }
    } else if seconds < 604800.0 {
        let days = seconds / 86400.0;
        if days < 2.0 {
            "1 day".to_string()
        } else {
            format!("{:.0} days", days)
        }
    } else if seconds < 2592000.0 {
        let weeks = seconds / 604800.0;
        if weeks < 2.0 {
            "1 week".to_string()
        } else {
            format!("{:.0} weeks", weeks)
        }
    } else if seconds < 31536000.0 {
        let months = seconds / 2592000.0;
        if months < 2.0 {
            "1 month".to_string()
        } else {
            format!("{:.0} months", months)
        }
    } else {
        let years = seconds / 31536000.0;
        if years < 2.0 {
            "1 year".to_string()
        } else {
            format!("{:.0} years", years)
        }
    }
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
        format!("in {}", pretty_time(diff))
    } else {
        format!("{} ago", pretty_time(-diff))
    }
}

/// Calculate hourly announce rate from timestamps
fn calculate_hourly_rate(timestamps: &[f64], now: f64) -> f64 {
    if timestamps.is_empty() {
        return 0.0;
    }

    // Filter timestamps within the last hour
    let hour_ago = now - 3600.0;
    let recent: Vec<_> = timestamps.iter().filter(|&&ts| ts >= hour_ago).collect();

    if recent.len() <= 1 {
        return recent.len() as f64;
    }

    // Calculate span
    let oldest = **recent.first().unwrap();
    let newest = **recent.last().unwrap();
    let span = newest - oldest;

    if span < 1.0 {
        return recent.len() as f64;
    }

    // Normalize to hourly rate
    (recent.len() as f64 / span) * 3600.0
}

/// Calculate the time span string for rate display
fn calculate_span_str(timestamps: &[f64], now: f64) -> String {
    if timestamps.is_empty() {
        return "0 seconds".to_string();
    }

    let hour_ago = now - 3600.0;
    let recent: Vec<_> = timestamps.iter().filter(|&&ts| ts >= hour_ago).collect();

    if recent.is_empty() {
        return "0 seconds".to_string();
    }

    let oldest = **recent.first().unwrap();
    let span = now - oldest;

    pretty_time(span)
}
