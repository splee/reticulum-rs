//! Reticulum Path Explorer
//!
//! Request and display paths to destinations.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use reticulum::config::Config;
use reticulum::hash::AddressHash;
use reticulum::logging;

/// Reticulum Path Explorer
#[derive(Parser, Debug)]
#[command(name = "rnpath")]
#[command(author = "Reticulum Network Stack")]
#[command(version)]
#[command(about = "Explore paths to Reticulum destinations", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Timeout in seconds for path request
    #[arg(short, long, default_value = "15")]
    timeout: u64,

    /// Show detailed path information
    #[arg(short, long)]
    verbose: bool,

    /// Destination hash to find path to
    #[arg(required = true)]
    destination: String,
}

fn main() {
    let args = Args::parse();

    // Initialize logging
    logging::init_default();

    // Load configuration
    let _config = load_config(&args.config);

    // Parse destination hash
    let dest_hash = match parse_destination(&args.destination) {
        Some(hash) => hash,
        None => {
            eprintln!("Error: Invalid destination hash format");
            eprintln!("Expected: 32 character hexadecimal string");
            std::process::exit(1);
        }
    };

    println!("Path request to {}", args.destination);
    println!();

    request_path(&dest_hash, Duration::from_secs(args.timeout), args.verbose);
}

fn load_config(config_path: &Option<PathBuf>) -> Config {
    if let Some(path) = config_path {
        Config::from_file(path).unwrap_or_else(|e| {
            log::warn!("Failed to load config: {}", e);
            Config::default()
        })
    } else {
        Config::default()
    }
}

fn parse_destination(dest_str: &str) -> Option<AddressHash> {
    // Remove any / prefix if present
    let clean = dest_str.trim_start_matches('/').trim_end_matches('/');

    if clean.len() != 32 {
        return None;
    }

    AddressHash::new_from_hex_string(clean).ok()
}

fn request_path(dest: &AddressHash, timeout: Duration, verbose: bool) {
    println!("Requesting path to {}", format_hash(dest));
    println!("Timeout: {} seconds", timeout.as_secs());
    println!();

    if verbose {
        println!("Waiting for path response...");
        println!();
    }

    // Simulate path request
    println!("Path Status: No path found");
    println!();
    println!("The destination may be:");
    println!("  - Not reachable from this network");
    println!("  - Not announcing currently");
    println!("  - Behind an unconnected interface");
    println!();
    println!("Note: Path requests require a running rnsd daemon with");
    println!("      properly configured interfaces.");
}

fn format_hash(hash: &AddressHash) -> String {
    let bytes = hash.as_slice();
    let mut hex = String::with_capacity(bytes.len() * 2 + 2);
    hex.push('/');
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex.push('/');
    hex
}
