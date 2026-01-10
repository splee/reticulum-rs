//! Reticulum Network Probe
//!
//! Test destination reachability on the Reticulum network.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use reticulum::config::Config;
use reticulum::hash::AddressHash;
use reticulum::logging;

/// Reticulum Network Probe
#[derive(Parser, Debug)]
#[command(name = "rnprobe")]
#[command(author = "Reticulum Network Stack")]
#[command(version)]
#[command(about = "Probe Reticulum network destinations", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Timeout in seconds
    #[arg(short, long, default_value = "10")]
    timeout: u64,

    /// Number of probes to send
    #[arg(short, long, default_value = "1")]
    count: u32,

    /// Show detailed output
    #[arg(short, long)]
    verbose: bool,

    /// Destination hash to probe
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

    probe_destination(&dest_hash, args.timeout, args.count, args.verbose);
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
    let clean = dest_str.trim_start_matches('/').trim_end_matches('/');

    if clean.len() != 32 {
        return None;
    }

    AddressHash::new_from_hex_string(clean).ok()
}

fn probe_destination(dest: &AddressHash, timeout_secs: u64, count: u32, verbose: bool) {
    let timeout = Duration::from_secs(timeout_secs);
    let dest_str = format_hash(dest);

    println!("Probing {} with {} probe(s)", dest_str, count);
    println!();

    let mut sent = 0u32;
    let mut received = 0u32;
    let mut times = Vec::new();

    for i in 0..count {
        if verbose {
            println!("Probe {} to {}", i + 1, dest_str);
        }

        let start = Instant::now();
        sent += 1;

        // Simulate probe (in real implementation, this would send a link request)
        let (success, rtt) = simulate_probe(timeout);

        if success {
            received += 1;
            let elapsed = rtt;
            times.push(elapsed);

            if verbose {
                println!("  Reply from {} time={:.2}ms", dest_str, elapsed);
            }
        } else {
            if verbose {
                println!("  Request timed out");
            }
        }

        // Wait between probes
        if i < count - 1 {
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    println!();
    println!("--- {} probe statistics ---", dest_str);
    println!(
        "{} probes sent, {} received, {:.1}% loss",
        sent,
        received,
        if sent > 0 {
            ((sent - received) as f64 / sent as f64) * 100.0
        } else {
            0.0
        }
    );

    if !times.is_empty() {
        let min = times.iter().min_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
        let max = times.iter().max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
        let avg: f64 = times.iter().sum::<f64>() / times.len() as f64;

        println!("rtt min/avg/max = {:.2}/{:.2}/{:.2} ms", min, avg, max);
    }
}

fn simulate_probe(_timeout: Duration) -> (bool, f64) {
    // In a real implementation, this would:
    // 1. Check if destination is in path table
    // 2. Send a link request packet
    // 3. Wait for link proof
    // 4. Return success/failure and RTT

    // For now, return failure (no daemon running)
    (false, 0.0)
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
