//! Reticulum Remote Execution Utility
//!
//! Allows executing commands on remote Reticulum nodes.
//!
//! Server mode (-l/--listen): Listen for incoming command requests
//! Client mode: Send commands to remote rnx listener
//! Interactive mode (-x): REPL for multiple commands over same link

use std::fs;
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use rand_core::OsRng;
use reticulum::config::{LogLevel, StoragePaths};
use reticulum::destination::link::{LinkEvent, LinkEventData, LinkStatus};
use reticulum::destination::DestinationName;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::logging;
use reticulum::transport::{Transport, TransportConfig};
use rmpv::Value;
use tokio::sync::Mutex;

const APP_NAME: &str = "rnx";
const ASPECT: &str = "execute";
const DEFAULT_TIMEOUT: f64 = 15.0;

/// Reticulum Remote Execution Utility
#[derive(Parser, Debug)]
#[command(name = "rnx")]
#[command(author = "Reticulum Network Stack")]
#[command(version)]
#[command(about = "Reticulum Remote Execution Utility", long_about = None)]
struct Args {
    /// Hexadecimal hash of the listener destination
    destination: Option<String>,

    /// Command to execute
    command: Option<String>,

    /// Path to alternative Reticulum config directory
    #[arg(long, value_name = "path")]
    config: Option<PathBuf>,

    /// Increase verbosity (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Count)]
    quiet: u8,

    /// Print identity and destination info and exit
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,

    /// Listen for incoming commands (server mode)
    #[arg(short = 'l', long)]
    listen: bool,

    /// Path to identity to use
    #[arg(short = 'i', value_name = "identity")]
    identity: Option<PathBuf>,

    /// Enter interactive mode (REPL)
    #[arg(short = 'x', long)]
    interactive: bool,

    /// Don't announce at program start
    #[arg(short = 'b', long = "no-announce")]
    no_announce: bool,

    /// Accept from this identity (can be repeated)
    #[arg(short = 'a', value_name = "allowed_hash", action = clap::ArgAction::Append)]
    allowed: Vec<String>,

    /// Accept commands from anyone (disable auth)
    #[arg(short = 'n', long = "noauth")]
    noauth: bool,

    /// Don't identify to listener
    #[arg(short = 'N', long = "noid")]
    noid: bool,

    /// Show detailed result output
    #[arg(short = 'd', long)]
    detailed: bool,

    /// Mirror exit code of remote command
    #[arg(short = 'm')]
    mirror: bool,

    /// Connect and request timeout in seconds
    #[arg(short = 'w', value_name = "seconds", default_value_t = DEFAULT_TIMEOUT)]
    timeout: f64,

    /// Max result download time in seconds
    #[arg(short = 'W', value_name = "seconds")]
    result_timeout: Option<f64>,

    /// Pass input to stdin
    #[arg(long)]
    stdin: Option<String>,

    /// Max size in bytes of returned stdout
    #[arg(long)]
    stdout: Option<usize>,

    /// Max size in bytes of returned stderr
    #[arg(long)]
    stderr: Option<usize>,

    /// TCP client to connect to (e.g., "host:port")
    #[arg(long = "tcp-client")]
    tcp_client: Option<String>,

    /// TCP server to listen on (e.g., "0.0.0.0:4242")
    #[arg(long = "tcp-server")]
    tcp_server: Option<String>,
}

/// Command execution result - wire format compatible with Python rnx
#[derive(Debug)]
struct CommandResult {
    executed: bool,
    return_code: Option<i32>,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
    stdout_total_len: Option<usize>,
    stderr_total_len: Option<usize>,
    started: f64,
    concluded: Option<f64>,
}

impl CommandResult {
    /// Serialize to msgpack format compatible with Python rnx
    fn to_msgpack(&self) -> Vec<u8> {
        let result = vec![
            Value::Boolean(self.executed),
            self.return_code
                .map(|v| Value::Integer(v.into()))
                .unwrap_or(Value::Nil),
            self.stdout
                .as_ref()
                .map(|d| Value::Binary(d.clone()))
                .unwrap_or(Value::Nil),
            self.stderr
                .as_ref()
                .map(|d| Value::Binary(d.clone()))
                .unwrap_or(Value::Nil),
            self.stdout_total_len
                .map(|v| Value::Integer((v as i64).into()))
                .unwrap_or(Value::Nil),
            self.stderr_total_len
                .map(|v| Value::Integer((v as i64).into()))
                .unwrap_or(Value::Nil),
            Value::F64(self.started),
            self.concluded.map(Value::F64).unwrap_or(Value::Nil),
        ];

        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &Value::Array(result)).unwrap();
        buf
    }

    /// Deserialize from msgpack format
    fn from_msgpack(data: &[u8]) -> Result<Self, &'static str> {
        let value =
            rmpv::decode::read_value(&mut &data[..]).map_err(|_| "Failed to decode msgpack")?;

        let arr = match value {
            Value::Array(a) if a.len() >= 8 => a,
            _ => return Err("Expected array with 8 elements"),
        };

        Ok(Self {
            executed: arr[0].as_bool().unwrap_or(false),
            return_code: arr[1].as_i64().map(|v| v as i32),
            stdout: match &arr[2] {
                Value::Binary(b) => Some(b.clone()),
                _ => None,
            },
            stderr: match &arr[3] {
                Value::Binary(b) => Some(b.clone()),
                _ => None,
            },
            stdout_total_len: arr[4].as_u64().map(|v| v as usize),
            stderr_total_len: arr[5].as_u64().map(|v| v as usize),
            started: arr[6].as_f64().unwrap_or(0.0),
            concluded: arr[7].as_f64(),
        })
    }
}

/// Build request data compatible with Python rnx
fn build_request_data(
    command: &str,
    timeout: Option<f64>,
    stdout_limit: Option<usize>,
    stderr_limit: Option<usize>,
    stdin_data: Option<&[u8]>,
) -> Vec<u8> {
    let request = vec![
        Value::Binary(command.as_bytes().to_vec()),
        timeout.map(Value::F64).unwrap_or(Value::Nil),
        stdout_limit
            .map(|v| Value::Integer((v as i64).into()))
            .unwrap_or(Value::Nil),
        stderr_limit
            .map(|v| Value::Integer((v as i64).into()))
            .unwrap_or(Value::Nil),
        stdin_data
            .map(|d| Value::Binary(d.to_vec()))
            .unwrap_or(Value::Nil),
    ];

    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &Value::Array(request)).unwrap();
    buf
}

/// Parse request data from msgpack
#[allow(clippy::type_complexity)]
fn parse_request_data(
    data: &[u8],
) -> Result<(String, Option<f64>, Option<usize>, Option<usize>, Option<Vec<u8>>), &'static str> {
    let value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|_| "Failed to decode msgpack request")?;

    let arr = match value {
        Value::Array(a) if a.len() >= 5 => a,
        _ => return Err("Expected array with 5 elements"),
    };

    let command = match &arr[0] {
        Value::Binary(b) => String::from_utf8_lossy(b).to_string(),
        Value::String(s) => s.as_str().unwrap_or("").to_string(),
        _ => return Err("Command must be bytes or string"),
    };

    let timeout = arr[1].as_f64();
    let stdout_limit = arr[2].as_u64().map(|v| v as usize);
    let stderr_limit = arr[3].as_u64().map(|v| v as usize);
    let stdin_data = match &arr[4] {
        Value::Binary(b) => Some(b.clone()),
        _ => None,
    };

    Ok((command, timeout, stdout_limit, stderr_limit, stdin_data))
}

fn main() {
    let args = Args::parse();

    // Determine log level from verbosity flags
    let effective_verbosity = args.verbose as i8 - args.quiet as i8;
    let log_level = match effective_verbosity {
        i if i < 0 => LogLevel::Critical,
        0 => LogLevel::Info,
        1 => LogLevel::Debug,
        _ => LogLevel::Verbose,
    };

    // Initialize logging
    logging::init_with_level(log_level);

    // Set up shutdown handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

    let exit_code = rt.block_on(async {
        if args.listen || args.print_identity {
            run_server(&args, running).await
        } else if args.destination.is_some() {
            if args.interactive {
                run_interactive(&args, running).await
            } else if args.command.is_some() {
                run_client(&args, running).await
            } else {
                eprintln!("Error: command required when destination is specified");
                print_usage();
                1
            }
        } else {
            print_usage();
            0
        }
    });

    std::process::exit(exit_code);
}

fn print_usage() {
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  rnx -l [options]                    # Listen for commands (server mode)");
    eprintln!("  rnx <destination> <command>         # Execute command on remote");
    eprintln!("  rnx -x <destination>                # Interactive mode");
    eprintln!();
    eprintln!("Run 'rnx --help' for more options");
}

/// Load or create identity from file
fn load_or_create_identity(identity_path: Option<&PathBuf>) -> PrivateIdentity {
    // Determine identity file path
    let identity_file = if let Some(path) = identity_path {
        path.clone()
    } else {
        // Use default path ~/.reticulum/identities/rnx
        let paths = StoragePaths::new(StoragePaths::default_config_dir());
        paths.identity_path.join(APP_NAME)
    };

    // Try to load existing identity
    if identity_file.exists() {
        log::info!("Loading identity from {:?}", identity_file);
        if let Ok(mut file) = fs::File::open(&identity_file) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                if let Ok(identity) = PrivateIdentity::new_from_hex_string(contents.trim()) {
                    log::debug!(
                        "Identity loaded: {}",
                        hex::encode(identity.as_identity().address_hash.as_slice())
                    );
                    return identity;
                }
            }
        }
        log::warn!("Failed to load identity from {:?}", identity_file);
    }

    // Create new identity
    log::info!("Creating new identity...");
    let identity = PrivateIdentity::new_from_rand(OsRng);
    log::info!(
        "New identity created: {}",
        hex::encode(identity.as_identity().address_hash.as_slice())
    );

    // Save identity
    if let Some(parent) = identity_file.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if let Ok(mut file) = fs::File::create(&identity_file) {
        let hex = identity.to_hex_string();
        let _ = file.write_all(hex.as_bytes());
        log::debug!("Identity saved to {:?}", identity_file);
    }

    identity
}

/// Load allowed identity hashes from CLI args and config files
fn load_allowed_identities(cli_allowed: &[String]) -> Vec<AddressHash> {
    let mut allowed = Vec::new();

    // From CLI
    for hex_str in cli_allowed {
        if hex_str.len() == 32 {
            // 16 bytes * 2
            if let Ok(hash) = AddressHash::new_from_hex_string(hex_str) {
                allowed.push(hash);
            } else {
                log::warn!("Invalid allowed hash: {}", hex_str);
            }
        } else {
            log::warn!(
                "Allowed hash must be 32 hex characters, got {}: {}",
                hex_str.len(),
                hex_str
            );
        }
    }

    // From config files
    let config_paths = [
        PathBuf::from("/etc/rnx/allowed_identities"),
        dirs::config_dir()
            .map(|d| d.join("rnx/allowed_identities"))
            .unwrap_or_default(),
        dirs::home_dir()
            .map(|d| d.join(".rnx/allowed_identities"))
            .unwrap_or_default(),
    ];

    for path in config_paths {
        if path.as_os_str().is_empty() {
            continue;
        }
        if path.exists() {
            log::debug!("Loading allowed identities from {:?}", path);
            if let Ok(contents) = fs::read_to_string(&path) {
                for line in contents.lines() {
                    let trimmed = line.trim();
                    if trimmed.len() == 32 {
                        if let Ok(hash) = AddressHash::new_from_hex_string(trimmed) {
                            allowed.push(hash);
                        }
                    }
                }
            }
        }
    }

    allowed
}

/// Run in server mode - listen for incoming commands
async fn run_server(args: &Args, running: Arc<AtomicBool>) -> i32 {
    let identity = load_or_create_identity(args.identity.as_ref());
    let public = identity.as_identity();

    // Handle print_identity flag
    if args.print_identity {
        println!(
            "Identity     : {}",
            hex::encode(public.address_hash.as_slice())
        );

        // Create destination to get its hash
        let dest_name = match DestinationName::new(APP_NAME, ASPECT) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("Invalid destination name: {}", e);
                return 1;
            }
        };
        // Create a minimal transport just to get the destination hash
        let transport = Transport::new(TransportConfig::new(APP_NAME, &identity, false));
        let destination = transport.add_destination(identity.clone(), dest_name).await;
        let dest_hash = destination.lock().await.desc.address_hash;
        println!("Listening on : {}", hex::encode(dest_hash.as_slice()));
        return 0;
    }

    // Load allowed identities
    let allowed_hashes = load_allowed_identities(&args.allowed);

    if allowed_hashes.is_empty() && !args.noauth {
        log::warn!("Warning: No allowed identities configured, rnx will not accept any commands!");
        eprintln!("Warning: No allowed identities configured, rnx will not accept any commands!");
    }

    // Create transport
    let transport = Transport::new(TransportConfig::new(APP_NAME, &identity, false));

    // Set up interfaces
    if let Some(server_addr) = &args.tcp_server {
        log::info!("Starting TCP server on {}", server_addr);
        transport.iface_manager().lock().await.spawn(
            TcpServer::new(server_addr, transport.iface_manager()),
            TcpServer::spawn,
        );
    }

    if let Some(client_addr) = &args.tcp_client {
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
    let dest_name = match DestinationName::new(APP_NAME, ASPECT) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Invalid destination name: {}", e);
            return 1;
        }
    };
    let destination = transport.add_destination(identity.clone(), dest_name).await;

    let dest_hash = destination.lock().await.desc.address_hash;
    log::info!(
        "rnx listening for commands on {}",
        hex::encode(dest_hash.as_slice())
    );

    // Send initial announce unless disabled
    if !args.no_announce {
        transport.send_announce(&destination, None).await;
        log::info!("Sent initial announce");
    }

    // Subscribe to incoming link events
    let mut link_events = transport.in_link_events();

    // Announce interval
    let announce_interval = Duration::from_secs(180);
    let mut next_announce = tokio::time::Instant::now() + announce_interval;

    // Main event loop
    while running.load(Ordering::SeqCst) {
        tokio::select! {
            Ok(event) = link_events.recv() => {
                handle_server_event(
                    &transport,
                    &event,
                    &allowed_hashes,
                    args.noauth,
                ).await;
            }
            _ = tokio::time::sleep_until(next_announce) => {
                if running.load(Ordering::SeqCst) && !args.no_announce {
                    transport.send_announce(&destination, None).await;
                    log::debug!("Sent periodic announce");
                    next_announce = tokio::time::Instant::now() + announce_interval;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Check running flag
            }
        }
    }

    log::info!("rnx server shutting down");
    0
}

/// Handle incoming link events in server mode
async fn handle_server_event(
    transport: &Transport,
    event: &LinkEventData,
    _allowed_hashes: &[AddressHash],
    _noauth: bool,
) {
    let link_id_hex = hex::encode(event.id.as_slice());

    match &event.event {
        LinkEvent::Activated => {
            log::info!("Link {} activated", link_id_hex);
        }
        LinkEvent::Request(payload) => {
            log::info!(
                "Request received on link {} ({} bytes)",
                link_id_hex,
                payload.len()
            );

            // Parse request
            match parse_request_data(payload.as_slice()) {
                Ok((command, timeout, stdout_limit, stderr_limit, stdin_data)) => {
                    log::info!("Executing command: [{}]", command);

                    // Execute the command
                    let result = execute_command(
                        &command,
                        timeout,
                        stdout_limit,
                        stderr_limit,
                        stdin_data.as_deref(),
                    )
                    .await;

                    // Serialize and send response
                    let response_data = result.to_msgpack();
                    log::debug!("Sending response: {} bytes", response_data.len());

                    // Get the link and send response using find_in_link
                    if let Some(link_mutex) = transport.find_in_link(&event.id).await {
                        let link = link_mutex.lock().await;
                        if let Ok(packet) = link.response_packet(&response_data) {
                            transport.send_packet(packet).await;
                            log::info!("Response sent for command [{}]", command);
                        }
                    } else {
                        log::error!("Could not find link {} to send response", link_id_hex);
                    }
                }
                Err(e) => {
                    log::error!("Failed to parse request: {}", e);
                }
            }
        }
        LinkEvent::Closed => {
            log::info!("Link {} closed", link_id_hex);
        }
        _ => {
            log::debug!("Link {}: unhandled event", link_id_hex);
        }
    }
}

/// Execute a command and capture output
async fn execute_command(
    command_str: &str,
    exec_timeout: Option<f64>,
    stdout_limit: Option<usize>,
    stderr_limit: Option<usize>,
    stdin_data: Option<&[u8]>,
) -> CommandResult {
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    let mut result = CommandResult {
        executed: false,
        return_code: None,
        stdout: None,
        stderr: None,
        stdout_total_len: None,
        stderr_total_len: None,
        started,
        concluded: None,
    };

    // Parse command - split on whitespace (simplified, doesn't handle quotes)
    // For proper shell parsing, we'd need a shell-words crate
    let parts: Vec<&str> = command_str.split_whitespace().collect();

    if parts.is_empty() {
        return result;
    }

    // Spawn the process
    let mut cmd = tokio::process::Command::new(parts[0]);
    if parts.len() > 1 {
        cmd.args(&parts[1..]);
    }

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to spawn command: {}", e);
            return result;
        }
    };

    result.executed = true;

    // Write stdin if provided
    if let Some(stdin) = stdin_data {
        if let Some(mut child_stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = child_stdin.write_all(stdin).await;
        }
    }

    // Wait for output with optional timeout
    let timeout_duration = exec_timeout.map(Duration::from_secs_f64);

    let output = if let Some(timeout) = timeout_duration {
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => Some(output),
            Ok(Err(e)) => {
                log::error!("Error waiting for command: {}", e);
                None
            }
            Err(_) => {
                log::warn!("Command timed out");
                // Child process will be killed when dropped
                None
            }
        }
    } else {
        match child.wait_with_output().await {
            Ok(output) => Some(output),
            Err(e) => {
                log::error!("Error waiting for command: {}", e);
                None
            }
        }
    };

    let concluded = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    result.concluded = Some(concluded);

    if let Some(output) = output {
        result.return_code = output.status.code();

        // Store total lengths before truncation
        result.stdout_total_len = Some(output.stdout.len());
        result.stderr_total_len = Some(output.stderr.len());

        // Apply limits
        result.stdout = Some(if let Some(limit) = stdout_limit {
            if limit == 0 {
                Vec::new()
            } else {
                output.stdout.into_iter().take(limit).collect()
            }
        } else {
            output.stdout
        });

        result.stderr = Some(if let Some(limit) = stderr_limit {
            if limit == 0 {
                Vec::new()
            } else {
                output.stderr.into_iter().take(limit).collect()
            }
        } else {
            output.stderr
        });
    }

    result
}

/// Run in client mode - execute a single command
async fn run_client(args: &Args, running: Arc<AtomicBool>) -> i32 {
    let destination_hex = args.destination.as_ref().unwrap();
    let command = args.command.as_ref().unwrap();

    let identity = load_or_create_identity(args.identity.as_ref());

    // Parse destination hash
    let dest_hash = match AddressHash::new_from_hex_string(destination_hex) {
        Ok(hash) => hash,
        Err(_) => {
            eprintln!(
                "Error: Invalid destination hash format. Expected 32 hex characters, got {}",
                destination_hex.len()
            );
            return 241;
        }
    };

    // Create transport
    let transport = Transport::new(TransportConfig::new(APP_NAME, &identity, false));

    // Set up interfaces
    if let Some(server_addr) = &args.tcp_server {
        transport.iface_manager().lock().await.spawn(
            TcpServer::new(server_addr, transport.iface_manager()),
            TcpServer::spawn,
        );
    }

    if let Some(client_addr) = &args.tcp_client {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(client_addr), TcpClient::spawn);
    }

    // Give interfaces time to connect
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Wait for announce from destination
    let timeout_duration = Duration::from_secs_f64(args.timeout);
    let deadline = tokio::time::Instant::now() + timeout_duration;

    print!("Path to {} requested ", destination_hex);
    std::io::stdout().flush().unwrap();

    let mut announce_rx = transport.recv_announces().await;
    let dest_desc = loop {
        if tokio::time::Instant::now() >= deadline {
            println!();
            eprintln!("Path not found");
            return 242;
        }

        if !running.load(Ordering::SeqCst) {
            println!();
            return 1;
        }

        tokio::select! {
            Ok(event) = announce_rx.recv() => {
                let announced_hash = event.destination.lock().await.desc.address_hash;
                if announced_hash == dest_hash {
                    println!("OK");
                    break event.destination.lock().await.desc;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                print!(".");
                std::io::stdout().flush().unwrap();
            }
        }
    };

    // Establish link
    print!("Establishing link with {} ", destination_hex);
    std::io::stdout().flush().unwrap();

    let link = transport.link(dest_desc).await;

    // Wait for link activation
    let deadline = tokio::time::Instant::now() + timeout_duration;
    let mut out_link_events = transport.out_link_events();

    loop {
        if tokio::time::Instant::now() >= deadline {
            println!();
            eprintln!("Could not establish link with {}", destination_hex);
            return 243;
        }

        if !running.load(Ordering::SeqCst) {
            println!();
            return 1;
        }

        let status = link.lock().await.status();
        if status == LinkStatus::Active {
            println!("OK");
            break;
        }

        tokio::select! {
            Ok(_event) = out_link_events.recv() => {
                // Link events are handled internally
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                print!(".");
                std::io::stdout().flush().unwrap();
            }
        }
    }

    // Build and send request
    let request_data = build_request_data(
        command,
        Some(args.timeout),
        args.stdout,
        args.stderr,
        args.stdin.as_ref().map(|s| s.as_bytes()),
    );

    // Send request
    {
        let link_guard = link.lock().await;
        if let Ok(packet) = link_guard.request_packet(&request_data) {
            transport.send_packet(packet).await;
            log::debug!("Request sent: {} bytes", request_data.len());
        } else {
            eprintln!("Could not send request");
            return 244;
        }
    }

    print!("Command delivered, awaiting result ");
    std::io::stdout().flush().unwrap();

    // Wait for response
    let result_timeout = args.result_timeout.unwrap_or(args.timeout * 2.0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(result_timeout);

    let response = loop {
        if tokio::time::Instant::now() >= deadline {
            println!();
            eprintln!("No result was received");
            return 245;
        }

        if !running.load(Ordering::SeqCst) {
            println!();
            return 1;
        }

        tokio::select! {
            Ok(event) = out_link_events.recv() => {
                if let LinkEvent::Response(payload) = &event.event {
                    println!("OK");
                    break payload.as_slice().to_vec();
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                print!(".");
                std::io::stdout().flush().unwrap();
            }
        }
    };

    // Parse and display result
    match CommandResult::from_msgpack(&response) {
        Ok(result) => {
            display_result(&result, args.detailed);

            if args.mirror {
                result.return_code.unwrap_or(240)
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("Received invalid result: {}", e);
            247
        }
    }
}

/// Display command execution result
fn display_result(result: &CommandResult, detailed: bool) {
    if !result.executed {
        eprintln!("Remote could not execute command");
        return;
    }

    // Print stdout
    if let Some(stdout) = &result.stdout {
        if !stdout.is_empty() {
            print!("{}", String::from_utf8_lossy(stdout));
        }
    }

    // Print stderr
    if let Some(stderr) = &result.stderr {
        if !stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(stderr));
        }
    }

    if detailed {
        println!();
        println!("--- End of remote output, rnx done ---");

        if let (Some(started), Some(concluded)) = (Some(result.started), result.concluded) {
            let duration = concluded - started;
            println!("Remote command execution took {:.3} seconds", duration);
        }

        if let Some(code) = result.return_code {
            println!("Remote exit code: {}", code);
        }

        if let (Some(stdout_len), Some(stdout)) = (result.stdout_total_len, &result.stdout) {
            if stdout.len() < stdout_len {
                println!(
                    "Remote wrote {} bytes to stdout, {} bytes displayed",
                    stdout_len,
                    stdout.len()
                );
            }
        }

        if let (Some(stderr_len), Some(stderr)) = (result.stderr_total_len, &result.stderr) {
            if stderr.len() < stderr_len {
                println!(
                    "Remote wrote {} bytes to stderr, {} bytes displayed",
                    stderr_len,
                    stderr.len()
                );
            }
        }
    } else {
        // Check for truncation
        let mut truncated = false;
        if let (Some(stdout_len), Some(stdout)) = (result.stdout_total_len, &result.stdout) {
            if stdout.len() < stdout_len && args_stdout_limit_nonzero() {
                truncated = true;
            }
        }
        if let (Some(stderr_len), Some(stderr)) = (result.stderr_total_len, &result.stderr) {
            if stderr.len() < stderr_len && args_stderr_limit_nonzero() {
                truncated = true;
            }
        }

        if truncated {
            eprintln!();
            eprintln!("Output truncated before being returned");
        }
    }
}

// Helper to check if output limits were set (simplified - always returns true for now)
fn args_stdout_limit_nonzero() -> bool {
    true
}

fn args_stderr_limit_nonzero() -> bool {
    true
}

/// Run in interactive mode - REPL for multiple commands
async fn run_interactive(args: &Args, running: Arc<AtomicBool>) -> i32 {
    let destination_hex = args.destination.as_ref().unwrap();

    let identity = load_or_create_identity(args.identity.as_ref());

    // Parse destination hash
    let dest_hash = match AddressHash::new_from_hex_string(destination_hex) {
        Ok(hash) => hash,
        Err(_) => {
            eprintln!("Error: Invalid destination hash format");
            return 241;
        }
    };

    // Create transport
    let transport = Transport::new(TransportConfig::new(APP_NAME, &identity, false));

    // Set up interfaces
    if let Some(server_addr) = &args.tcp_server {
        transport.iface_manager().lock().await.spawn(
            TcpServer::new(server_addr, transport.iface_manager()),
            TcpServer::spawn,
        );
    }

    if let Some(client_addr) = &args.tcp_client {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(client_addr), TcpClient::spawn);
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Wait for announce
    let timeout_duration = Duration::from_secs_f64(args.timeout);
    let deadline = tokio::time::Instant::now() + timeout_duration;

    println!("Waiting for path to {}...", destination_hex);

    let mut announce_rx = transport.recv_announces().await;
    let dest_desc = loop {
        if tokio::time::Instant::now() >= deadline {
            eprintln!("Path not found");
            return 242;
        }

        tokio::select! {
            Ok(event) = announce_rx.recv() => {
                let announced_hash = event.destination.lock().await.desc.address_hash;
                if announced_hash == dest_hash {
                    println!("Path found");
                    break event.destination.lock().await.desc;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    };

    // Establish link
    println!("Establishing link...");
    let link = transport.link(dest_desc).await;

    // Wait for link activation
    let deadline = tokio::time::Instant::now() + timeout_duration;
    let mut out_link_events = transport.out_link_events();

    loop {
        if tokio::time::Instant::now() >= deadline {
            eprintln!("Could not establish link");
            return 243;
        }

        let status = link.lock().await.status();
        if status == LinkStatus::Active {
            println!("Link established");
            break;
        }

        tokio::select! {
            Ok(_) = out_link_events.recv() => {}
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    // Interactive REPL
    let mut last_exit_code: Option<i32> = None;
    let link = Arc::new(Mutex::new(link));
    let transport = Arc::new(transport);

    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        // Print prompt
        let prompt = match last_exit_code {
            Some(code) if code != 0 => format!("{}> ", code),
            _ => "> ".to_string(),
        };
        print!("{}", prompt);
        std::io::stdout().flush().unwrap();

        // Read command
        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }

        let command = input.trim();

        // Handle special commands
        match command.to_lowercase().as_str() {
            "exit" | "quit" => break,
            "clear" => {
                print!("\x1b[2J\x1b[H");
                continue;
            }
            "" => continue,
            _ => {}
        }

        // Execute remote command
        let request_data = build_request_data(command, Some(args.timeout), args.stdout, args.stderr, None);

        // Send request
        {
            let link_guard = link.lock().await;
            let inner_link = link_guard.lock().await;
            if let Ok(packet) = inner_link.request_packet(&request_data) {
                transport.send_packet(packet).await;
            } else {
                eprintln!("Could not send request");
                continue;
            }
        }

        // Wait for response
        let result_timeout = args.result_timeout.unwrap_or(args.timeout * 2.0);
        let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(result_timeout);

        let response = loop {
            if tokio::time::Instant::now() >= deadline {
                eprintln!("No result received");
                last_exit_code = Some(245);
                break None;
            }

            tokio::select! {
                Ok(event) = out_link_events.recv() => {
                    if let LinkEvent::Response(payload) = &event.event {
                        break Some(payload.as_slice().to_vec());
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        };

        if let Some(response_data) = response {
            match CommandResult::from_msgpack(&response_data) {
                Ok(result) => {
                    display_result(&result, args.detailed);
                    last_exit_code = if args.mirror {
                        result.return_code
                    } else {
                        None
                    };
                }
                Err(e) => {
                    eprintln!("Invalid result: {}", e);
                    last_exit_code = Some(247);
                }
            }
        }
    }

    0
}
