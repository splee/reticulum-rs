//! Reticulum Network Status
//!
//! Display network status, interfaces, paths, and links.

use std::path::PathBuf;

use clap::Parser;
use reticulum::config::Config;
use reticulum::logging;

/// Reticulum Network Status
#[derive(Parser, Debug)]
#[command(name = "rnstatus")]
#[command(author = "Reticulum Network Stack")]
#[command(version)]
#[command(about = "Display Reticulum network status", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Show all details
    #[arg(short, long)]
    all: bool,

    /// Output as JSON
    #[arg(short, long)]
    json: bool,

    /// Sort output by field
    #[arg(short, long, value_name = "FIELD")]
    sort: Option<String>,

    /// Remote destination hash to query
    #[arg(value_name = "DESTINATION")]
    destination: Option<String>,
}

fn main() {
    let args = Args::parse();

    // Initialize logging
    logging::init_default();

    // Load configuration
    let _config = load_config(&args.config);

    if let Some(dest) = &args.destination {
        show_remote_status(dest, args.json);
    } else {
        show_local_status(args.all, args.json);
    }
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

fn show_local_status(show_all: bool, as_json: bool) {
    if as_json {
        println!(r#"{{
  "status": "standalone",
  "interfaces": [],
  "paths": [],
  "links": []
}}"#);
    } else {
        println!("Reticulum Network Status");
        println!("========================");
        println!();
        println!("Status: Standalone (no shared instance connected)");
        println!();

        println!("Interfaces:");
        println!("  (no interfaces configured)");
        println!();

        if show_all {
            println!("Path Table:");
            println!("  (empty)");
            println!();

            println!("Active Links:");
            println!("  (none)");
            println!();
        }

        println!("Statistics:");
        println!("  TX Packets: 0");
        println!("  RX Packets: 0");
        println!("  TX Bytes:   0");
        println!("  RX Bytes:   0");
    }
}

fn show_remote_status(destination: &str, as_json: bool) {
    if as_json {
        println!(r#"{{
  "error": "not_implemented",
  "message": "Remote status queries not yet implemented",
  "destination": "{}"
}}"#, destination);
    } else {
        println!("Remote Status Query");
        println!("===================");
        println!();
        println!("Destination: {}", destination);
        println!("Status: Not implemented");
        println!();
        println!("Remote status queries will be available in a future version.");
    }
}
