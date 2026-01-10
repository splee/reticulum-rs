//! Reticulum Network Stack Daemon
//!
//! The main daemon process that manages the Reticulum network stack,
//! interfaces, and routing.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use reticulum::config::{Config, LogLevel, StoragePaths};
use reticulum::logging;

/// Reticulum Network Stack Daemon
#[derive(Parser, Debug)]
#[command(name = "rnsd")]
#[command(author = "Reticulum Network Stack")]
#[command(version)]
#[command(about = "Reticulum Network Stack Daemon", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Increase verbosity (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity
    #[arg(short, long)]
    quiet: bool,

    /// Run in service/background mode
    #[arg(short, long)]
    service: bool,

    /// Run in interactive mode
    #[arg(short, long)]
    interactive: bool,

    /// Print example configuration
    #[arg(long)]
    exampleconfig: bool,
}

fn main() {
    let args = Args::parse();

    // Print example config if requested
    if args.exampleconfig {
        print_example_config();
        return;
    }

    // Determine log level from verbosity flags
    let log_level = if args.quiet {
        LogLevel::Critical
    } else {
        match args.verbose {
            0 => LogLevel::Info,
            1 => LogLevel::Debug,
            _ => LogLevel::Verbose,
        }
    };

    // Initialize logging
    logging::init_with_level(log_level);

    log::info!("Reticulum Network Stack Daemon starting...");

    // Load configuration
    let config = if let Some(config_path) = &args.config {
        match Config::from_file(config_path) {
            Ok(cfg) => {
                log::info!("Loaded configuration from {:?}", config_path);
                cfg
            }
            Err(e) => {
                log::error!("Failed to load configuration: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Look for default config locations
        let storage = StoragePaths::default_config_dir();
        let default_path = storage.join("config");
        if default_path.exists() {
            match Config::from_file(&default_path) {
                Ok(cfg) => {
                    log::info!("Loaded configuration from {:?}", default_path);
                    cfg
                }
                Err(e) => {
                    log::warn!("Failed to load default config: {}", e);
                    log::info!("Using default configuration");
                    Config::default()
                }
            }
        } else {
            log::info!("No configuration file found, using defaults");
            Config::default()
        }
    };

    log::debug!("Configuration: {:?}", config);

    // Set up shutdown handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // Run the daemon
    if args.interactive {
        log::info!("Running in interactive mode");
        run_interactive(&config, running);
    } else {
        log::info!("Running in daemon mode");
        run_daemon(&config, running);
    }

    log::info!("Reticulum Network Stack Daemon stopped");
}

fn run_daemon(config: &Config, running: Arc<AtomicBool>) {
    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

    rt.block_on(async {
        log::info!("Daemon started, press Ctrl-C to stop");

        // Main loop
        while running.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });
}

fn run_interactive(_config: &Config, running: Arc<AtomicBool>) {
    println!("Reticulum Network Stack Daemon - Interactive Mode");
    println!("Type 'help' for available commands, 'quit' to exit");
    println!();

    use std::io::{self, BufRead, Write};

    while running.load(Ordering::SeqCst) {
        print!("rns> ");
        io::stdout().flush().unwrap();

        let stdin = io::stdin();
        let mut line = String::new();

        match stdin.lock().read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let cmd = line.trim();
                match cmd {
                    "help" | "?" => {
                        println!("Available commands:");
                        println!("  status    - Show network status");
                        println!("  paths     - Show path table");
                        println!("  ifaces    - Show interfaces");
                        println!("  quit      - Exit daemon");
                    }
                    "status" => {
                        println!("Status: Running");
                        println!("Interfaces: 0");
                        println!("Paths: 0");
                        println!("Links: 0");
                    }
                    "paths" => {
                        println!("Path table is empty");
                    }
                    "ifaces" => {
                        println!("No interfaces configured");
                    }
                    "quit" | "exit" => {
                        running.store(false, Ordering::SeqCst);
                    }
                    "" => {}
                    _ => {
                        println!("Unknown command: {}", cmd);
                    }
                }
            }
            Err(e) => {
                log::error!("Error reading input: {}", e);
                break;
            }
        }
    }
}

fn print_example_config() {
    println!(r#"# Reticulum Network Stack Configuration
# This is an example configuration file

[reticulum]
# Enable transport mode (routing packets for other nodes)
enable_transport = false

# Share instances with other applications
share_instance = true

# Shared instance port
shared_instance_port = 37428

# Panic on unparseable interfaces
panic_on_interface_error = false

# Log level: CRITICAL, ERROR, WARNING, INFO, DEBUG, VERBOSE
loglevel = INFO

[interfaces]

# Example TCP Server Interface
[[interfaces.tcp_server]]
name = "TCP Server"
enabled = true
listen_ip = "0.0.0.0"
listen_port = 4242
# Optional IFAC
# ifac_size = 16
# ifac_netname = "my_network"

# Example TCP Client Interface
[[interfaces.tcp_client]]
name = "TCP Client"
enabled = false
target_host = "192.168.1.100"
target_port = 4242
# reconnect = true
# max_reconnects = 0

# Example UDP Interface
[[interfaces.udp]]
name = "UDP Interface"
enabled = false
listen_ip = "0.0.0.0"
listen_port = 4243
forward_ip = "255.255.255.255"
forward_port = 4243
# broadcast = true

# Example Serial Interface (for RNode, TNCs, etc.)
[[interfaces.serial]]
name = "Serial"
enabled = false
port = "/dev/ttyUSB0"
speed = 115200
# databits = 8
# parity = "none"
# stopbits = 1
"#);
}
