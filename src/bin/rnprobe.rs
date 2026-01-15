//! Reticulum Network Probe
//!
//! Test destination reachability on the Reticulum network by sending
//! probe packets and measuring round-trip time.

use std::io::{self, Write as IoWrite};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use rand_core::{OsRng, RngCore};

use reticulum::cli::hash::parse_destination;
use reticulum::config::{LogLevel, ReticulumConfig};
use reticulum::destination::{DestinationName, SingleOutputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::logging;
use reticulum::packet::{DestinationType, Header, Packet, PacketContext, PacketDataBuffer, PacketType, PropagationType};
use reticulum::receipt::ReceiptStatus;
use reticulum::transport::{Transport, TransportConfig};

/// Reticulum Network Probe
#[derive(Parser, Debug)]
#[command(name = "rnprobe")]
#[command(author = "Reticulum Network Stack")]
#[command(version)]
#[command(about = "Probe Reticulum network destinations", long_about = None)]
struct Args {
    /// Path to alternative Reticulum config directory
    #[arg(long, value_name = "DIR")]
    config: Option<PathBuf>,

    /// Size of probe packet payload in bytes
    #[arg(short = 's', long, default_value = "16")]
    size: usize,

    /// Number of probes to send
    #[arg(short = 'n', long, default_value = "1")]
    probes: u32,

    /// Timeout before giving up (seconds)
    #[arg(short = 't', long, value_name = "seconds", default_value = "15")]
    timeout: f64,

    /// Time between each probe (seconds)
    #[arg(short = 'w', long, value_name = "seconds", default_value = "0")]
    wait: f64,

    /// Increase verbosity (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// TCP client to connect to (e.g., "host:port")
    #[arg(long = "tcp-client", value_name = "ADDR")]
    tcp_client: Option<String>,

    /// TCP server to listen on (e.g., "0.0.0.0:4242")
    #[arg(long = "tcp-server", value_name = "ADDR")]
    tcp_server: Option<String>,

    /// Destination hash to probe (32 hex characters)
    destination: String,
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
            eprintln!("Failed to load configuration: {}", e);
            std::process::exit(20);
        }
    };

    // Parse destination hash
    let dest_hash = match parse_destination(&args.destination) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Expected: 32 character hexadecimal string");
            std::process::exit(1);
        }
    };

    // Run the probe
    let exit_code = run_probe(&args, &config, &dest_hash).await;
    std::process::exit(exit_code);
}

/// Create and configure transport with interfaces
async fn create_transport(args: &Args, config: &ReticulumConfig) -> Transport {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport_config = TransportConfig::new("rnprobe", &identity, false);
    let transport = Transport::new(transport_config);

    // Set up interfaces from command line args or config
    if let Some(ref server_addr) = args.tcp_server {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(
                TcpServer::new(server_addr, transport.iface_manager()),
                TcpServer::spawn,
            );
    }

    if let Some(ref client_addr) = args.tcp_client {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(client_addr), TcpClient::spawn);
    }

    // If no CLI interfaces specified, use config interfaces
    if args.tcp_client.is_none() && args.tcp_server.is_none() {
        for iface_config in config.interface_configs() {
            match iface_config.interface_type.as_str() {
                "TCPClientInterface" => {
                    if let Some(ref target) = iface_config.target_host {
                        let port = iface_config.target_port.unwrap_or(4242);
                        let addr = format!("{}:{}", target, port);
                        transport
                            .iface_manager()
                            .lock()
                            .await
                            .spawn(TcpClient::new(&addr), TcpClient::spawn);
                    }
                }
                "TCPServerInterface" => {
                    let listen_ip = iface_config.listen_ip.as_deref().unwrap_or("0.0.0.0");
                    let listen_port = iface_config.listen_port.unwrap_or(4242);
                    let addr = format!("{}:{}", listen_ip, listen_port);
                    transport
                        .iface_manager()
                        .lock()
                        .await
                        .spawn(
                            TcpServer::new(&addr, transport.iface_manager()),
                            TcpServer::spawn,
                        );
                }
                _ => {
                    log::debug!("Skipping unsupported interface type: {}", iface_config.interface_type);
                }
            }
        }
    }

    // Give interfaces time to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    transport
}

/// Run the probe operation
async fn run_probe(args: &Args, config: &ReticulumConfig, dest_hash: &AddressHash) -> i32 {
    let transport = create_transport(args, config).await;
    let timeout = Duration::from_secs_f64(args.timeout);

    // Subscribe to announces to cache destination identity
    let _announce_rx = transport.recv_announces().await;

    println!("Probing {} with {} probe(s)", pretty_hash(dest_hash), args.probes);
    println!();

    // Phase 1: Path discovery
    if !transport.has_path(dest_hash).await {
        print!("Path request to {} ", pretty_hash(dest_hash));
        io::stdout().flush().ok();

        transport.request_path(dest_hash, None).await;

        let path_found = wait_for_path(&transport, dest_hash, timeout).await;

        if !path_found {
            println!("\rPath not found                              ");
            return 1; // Path timeout exit code
        }

        println!("\rPath found                                  ");
    }

    // Phase 2: Get destination identity
    // Wait a bit for announce to arrive after path discovery
    tokio::time::sleep(Duration::from_millis(500)).await;

    let identity = match transport.recall_identity(dest_hash).await {
        Some(id) => id,
        None => {
            eprintln!("Error: Could not recall destination identity");
            eprintln!("The destination may not have announced yet.");
            return 1;
        }
    };

    // Create output destination for packet encryption
    let destination = SingleOutputDestination::new(
        identity,
        DestinationName::new_from_hash_slice(dest_hash.as_slice()),
    );

    // Phase 3: Send probes
    let mut sent = 0u32;
    let mut received = 0u32;
    let mut times: Vec<Duration> = Vec::new();

    for i in 0..args.probes {
        if i > 0 && args.wait > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(args.wait)).await;
        }

        // Generate random probe data
        let mut probe_data = vec![0u8; args.size];
        OsRng.fill_bytes(&mut probe_data);

        // Create probe packet
        let packet = match create_probe_packet(&destination, &probe_data) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error creating probe packet: {:?}", e);
                continue;
            }
        };

        // Get hop count for receipt timeout calculation
        let hops = transport.hops_to(dest_hash).await.unwrap_or(1);

        // Send packet and get receipt
        let receipt = transport
            .send_packet_with_receipt(packet, *dest_hash, hops)
            .await;

        sent += 1;

        if args.verbose > 0 {
            print!("Sent probe {} ({} bytes) to {} ", i + 1, args.size, pretty_hash(dest_hash));
            io::stdout().flush().ok();
        }

        // Wait for proof with spinner
        match wait_for_proof(receipt, timeout).await {
            Some(rtt) => {
                received += 1;
                times.push(rtt);

                if args.verbose > 0 {
                    println!("- reply in {}", format_duration(rtt));
                } else {
                    println!(
                        "Valid reply from {} - Round-trip time: {} over {} hop{}",
                        pretty_hash(dest_hash),
                        format_duration(rtt),
                        hops,
                        if hops == 1 { "" } else { "s" }
                    );
                }
            }
            None => {
                if args.verbose > 0 {
                    println!("- timeout");
                } else {
                    println!("Probe {} timed out", i + 1);
                }
            }
        }
    }

    // Phase 4: Print statistics
    println!();
    println!("--- {} probe statistics ---", pretty_hash(dest_hash));

    let loss = if sent > 0 {
        ((sent - received) as f64 / sent as f64) * 100.0
    } else {
        0.0
    };

    println!(
        "{} probes sent, {} received, {:.1}% loss",
        sent, received, loss
    );

    if !times.is_empty() {
        let min = times.iter().min().unwrap();
        let max = times.iter().max().unwrap();
        let avg_ms: f64 = times.iter().map(|d| d.as_secs_f64() * 1000.0).sum::<f64>()
            / times.len() as f64;

        println!(
            "rtt min/avg/max = {}/{:.2}ms/{}",
            format_duration(*min),
            avg_ms,
            format_duration(*max)
        );
    }

    // Exit code based on loss
    if loss > 0.0 {
        2 // Some probes lost
    } else {
        0 // All successful
    }
}

/// Wait for path discovery with spinner animation
async fn wait_for_path(transport: &Transport, dest_hash: &AddressHash, timeout: Duration) -> bool {
    let spinner = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];
    let mut spinner_idx = 0;
    let start = Instant::now();

    while start.elapsed() < timeout {
        if transport.has_path(dest_hash).await {
            return true;
        }

        print!("\r{} ", spinner[spinner_idx % spinner.len()]);
        io::stdout().flush().ok();
        spinner_idx += 1;

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    false
}

/// Wait for proof receipt with spinner animation
async fn wait_for_proof(
    receipt: Arc<tokio::sync::Mutex<reticulum::receipt::PacketReceipt>>,
    timeout: Duration,
) -> Option<Duration> {
    let spinner = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];
    let mut spinner_idx = 0;
    let start = Instant::now();

    while start.elapsed() < timeout {
        {
            let r = receipt.lock().await;
            if r.is_delivered() {
                return r.rtt();
            }
            if r.status() == ReceiptStatus::Failed {
                return None;
            }
        }

        print!("\r{} ", spinner[spinner_idx % spinner.len()]);
        io::stdout().flush().ok();
        spinner_idx += 1;

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Mark as timed out
    {
        let mut r = receipt.lock().await;
        r.check_timeout();
    }

    None
}

/// Create a probe packet for the destination
fn create_probe_packet(
    destination: &SingleOutputDestination,
    payload: &[u8],
) -> Result<Packet, reticulum::error::RnsError> {
    // For SINGLE destinations, we need to encrypt the payload
    // For now, we'll send unencrypted data as a simple probe
    // (Full encryption would require the Identity::encrypt method)

    let mut data = PacketDataBuffer::new();
    data.chain_safe_write(payload);

    Ok(Packet {
        header: Header {
            packet_type: PacketType::Data,
            destination_type: DestinationType::Single,
            propagation_type: PropagationType::Broadcast,
            ..Default::default()
        },
        destination: destination.desc.address_hash,
        context: PacketContext::None,
        data,
        ..Default::default()
    })
}

/// Format an AddressHash for display
fn pretty_hash(hash: &AddressHash) -> String {
    let bytes = hash.as_slice();
    let mut hex = String::with_capacity(bytes.len() * 2 + 2);
    hex.push('<');
    for byte in &bytes[..8] {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex.push_str("..");
    hex.push('>');
    hex
}

/// Format a Duration for display
fn format_duration(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 1.0 {
        format!("{:.2}ms", ms)
    } else if ms < 1000.0 {
        format!("{:.1}ms", ms)
    } else {
        format!("{:.2}s", d.as_secs_f64())
    }
}
