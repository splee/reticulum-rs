//! Reticulum Identity Manager
//!
//! Generate, import, export, and manage Reticulum identities.
//! Provides cryptographic operations (sign, verify, encrypt, decrypt)
//! and network operations (announce, request identities).

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use data_encoding::{BASE32, BASE64};
use ed25519_dalek::Signature;
use rand_core::OsRng;
use reticulum::cli::format::{format_hash, spinner_char};
use reticulum::config::{LogLevel, ReticulumConfig};
use reticulum::destination::{DestinationName, SingleInputDestination, SingleOutputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::{Identity, PrivateIdentity};
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::logging;
use reticulum::transport::{Transport, TransportConfig};

/// File extension for Reticulum signatures
const SIG_EXT: &str = "rsg";

/// File extension for Reticulum encrypted files
const ENCRYPT_EXT: &str = "rfe";

/// Chunk size for file encryption/decryption (16 MB, matching Python)
const CHUNK_SIZE: usize = 16 * 1024 * 1024;

// Exit codes matching Python implementation
const EXIT_OK: i32 = 0;
const EXIT_GENERAL_ERROR: i32 = 1;
#[allow(dead_code)]
const EXIT_IDENTITY_NOT_FOUND: i32 = 5;
#[allow(dead_code)]
const EXIT_IDENTITY_REQUEST_TIMEOUT: i32 = 6;
const EXIT_SIGNING_NO_PRIVATE_KEY: i32 = 16;
const EXIT_SIGNING_READ_ERROR: i32 = 17;
const EXIT_SIGNING_WRITE_ERROR: i32 = 18;
const EXIT_VALIDATE_READ_ERROR: i32 = 20;
const EXIT_VALIDATE_INVALID_SIG: i32 = 22;
const EXIT_ENCRYPT_READ_ERROR: i32 = 24;
const EXIT_ENCRYPT_WRITE_ERROR: i32 = 25;
const EXIT_DECRYPT_NO_PRIVATE_KEY: i32 = 27;
const EXIT_DECRYPT_READ_ERROR: i32 = 28;
const EXIT_DECRYPT_FAILED: i32 = 30;
const EXIT_DECRYPT_WRITE_ERROR: i32 = 31;
const EXIT_ANNOUNCE_NO_PRIVATE_KEY: i32 = 33;

/// Reticulum Identity Manager
#[derive(Parser, Debug)]
#[command(name = "rnid")]
#[command(author = "Reticulum Network Stack")]
#[command(version, disable_version_flag = true)]
#[command(about = "Manage Reticulum identities", long_about = None)]
struct Args {
    /// Print version information
    #[arg(long)]
    version: bool,

    /// Path to alternative Reticulum config directory
    #[arg(long, value_name = "DIR")]
    config: Option<PathBuf>,

    /// Identity: hexadecimal hash, file path, or identity data
    #[arg(short = 'i', long, value_name = "IDENTITY")]
    identity: Option<String>,

    /// Generate a new identity and save to file
    #[arg(short = 'g', long, value_name = "FILE")]
    generate: Option<PathBuf>,

    /// Import identity from hex, base32, or base64 string
    #[arg(short = 'm', long = "import", value_name = "IDENTITY_DATA")]
    import_str: Option<String>,

    /// Export identity to hex, base32, or base64 format
    #[arg(short = 'x', long)]
    export: bool,

    /// Print identity info and exit
    #[arg(short = 'p', long)]
    print_identity: bool,

    /// Allow displaying private keys
    #[arg(short = 'P', long)]
    print_private: bool,

    /// Use base64-encoded input and output
    #[arg(short = 'b', long)]
    base64: bool,

    /// Use base32-encoded input and output
    #[arg(short = 'B', long)]
    base32: bool,

    /// Compute destination hash for app.aspect format
    #[arg(short = 'H', long, value_name = "ASPECTS")]
    hash: Option<String>,

    /// Announce destination to network
    #[arg(short = 'a', long, value_name = "ASPECTS")]
    announce: Option<String>,

    /// Request unknown identities from network
    #[arg(short = 'R', long)]
    request: bool,

    /// Timeout for network requests (seconds)
    #[arg(short = 't', value_name = "SECONDS", default_value = "15")]
    timeout: f64,

    /// Sign file with identity private key
    #[arg(short = 's', long, value_name = "FILE")]
    sign: Option<PathBuf>,

    /// Validate signature file
    #[arg(short = 'V', long, value_name = "FILE")]
    validate: Option<PathBuf>,

    /// Encrypt file for identity
    #[arg(short = 'e', long, value_name = "FILE")]
    encrypt: Option<PathBuf>,

    /// Decrypt file with identity private key
    #[arg(short = 'd', long, value_name = "FILE")]
    decrypt: Option<PathBuf>,

    /// Input file path for crypto operations
    #[arg(short = 'r', long, value_name = "FILE")]
    read: Option<PathBuf>,

    /// Output file path
    #[arg(short = 'w', long, value_name = "FILE")]
    write: Option<PathBuf>,

    /// Overwrite existing output files
    #[arg(short = 'f', long)]
    force: bool,

    /// Increase verbosity (can be repeated)
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity (can be repeated)
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,

    /// TCP client to connect to for network operations
    #[arg(long = "tcp-client", value_name = "ADDR")]
    tcp_client: Option<String>,

    /// TCP server to listen on for network operations
    #[arg(long = "tcp-server", value_name = "ADDR")]
    tcp_server: Option<String>,
}

/// Encoding format for identity data
#[derive(Clone, Copy)]
enum Encoding {
    Hex,
    Base64,
    Base32,
}

impl Encoding {
    fn from_args(args: &Args) -> Self {
        if args.base64 {
            Encoding::Base64
        } else if args.base32 {
            Encoding::Base32
        } else {
            Encoding::Hex
        }
    }

    fn encode(&self, data: &[u8]) -> String {
        match self {
            Encoding::Hex => hex::encode(data),
            Encoding::Base64 => BASE64.encode(data),
            Encoding::Base32 => BASE32.encode(data),
        }
    }

    fn decode(&self, s: &str) -> Result<Vec<u8>, String> {
        match self {
            Encoding::Hex => hex::decode(s).map_err(|e| format!("Invalid hex: {}", e)),
            Encoding::Base64 => BASE64
                .decode(s.as_bytes())
                .map_err(|e| format!("Invalid base64: {}", e)),
            Encoding::Base32 => BASE32
                .decode(s.as_bytes())
                .map_err(|e| format!("Invalid base32: {}", e)),
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Handle version flag
    if args.version {
        println!("rnid {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    // Determine log level from verbosity flags
    let base_level = 4i8; // Info
    let effective = (base_level + args.verbose as i8 - args.quiet as i8).clamp(0, 7);
    let log_level = match effective {
        0 => LogLevel::Critical,
        1 => LogLevel::Error,
        2 => LogLevel::Warning,
        3 => LogLevel::Notice,
        4 => LogLevel::Info,
        5 => LogLevel::Debug,
        _ => LogLevel::Verbose,
    };

    logging::init_with_level(log_level);

    let exit_code = run(&args).await;
    std::process::exit(exit_code);
}

async fn run(args: &Args) -> i32 {
    let encoding = Encoding::from_args(args);

    // Handle generate first (doesn't need existing identity)
    if let Some(ref path) = args.generate {
        return handle_generate(args, path, encoding);
    }

    // Handle import from string
    if let Some(ref import_data) = args.import_str {
        return handle_import_string(args, import_data, encoding);
    }

    // For other operations, we need an identity
    let identity_result = load_identity(args, encoding).await;

    // Handle operations that work with public identity
    if let Some(ref aspects) = args.hash {
        match &identity_result {
            Ok(IdentityType::Private(id)) => {
                return handle_destination_hash(id.as_identity(), aspects);
            }
            Ok(IdentityType::Public(id)) => {
                return handle_destination_hash(id, aspects);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                return EXIT_GENERAL_ERROR;
            }
        }
    }

    // Handle operations requiring identity
    match identity_result {
        Ok(IdentityType::Private(identity)) => {
            handle_private_identity_operations(args, &identity, encoding).await
        }
        Ok(IdentityType::Public(identity)) => {
            handle_public_identity_operations(args, &identity, encoding)
        }
        Err(e) => {
            if args.identity.is_some() || needs_identity(args) {
                eprintln!("Error: {}", e);
                EXIT_GENERAL_ERROR
            } else {
                print_usage();
                EXIT_GENERAL_ERROR
            }
        }
    }
}

/// Check if any operation requires an identity
fn needs_identity(args: &Args) -> bool {
    args.export
        || args.print_identity
        || args.sign.is_some()
        || args.validate.is_some()
        || args.encrypt.is_some()
        || args.decrypt.is_some()
        || args.hash.is_some()
        || args.announce.is_some()
}

#[allow(clippy::large_enum_variant)]
enum IdentityType {
    Private(PrivateIdentity),
    Public(Identity),
}

/// Load identity from various sources
async fn load_identity(args: &Args, encoding: Encoding) -> Result<IdentityType, String> {
    let identity_str = args
        .identity
        .as_ref()
        .ok_or_else(|| "No identity specified".to_string())?;

    // Try as file path first
    let path = PathBuf::from(identity_str);
    if path.exists() {
        let identity = load_identity_from_file(&path)?;
        return Ok(IdentityType::Private(identity));
    }

    // Try as hex/base32/base64 encoded identity data
    if let Ok(bytes) = encoding.decode(identity_str) {
        if bytes.len() == 64 {
            let identity = PrivateIdentity::new_from_bytes(&bytes)
                .map_err(|e| format!("Failed to parse identity: {:?}", e))?;
            return Ok(IdentityType::Private(identity));
        } else if bytes.len() == 64 * 2 {
            // Public key only (128 hex chars = 64 bytes public key)
            let identity = Identity::new_from_hex_string(identity_str)
                .map_err(|e| format!("Failed to parse public identity: {:?}", e))?;
            return Ok(IdentityType::Public(identity));
        }
    }

    // Try as destination/identity hash (16 bytes = 32 hex chars)
    if identity_str.len() == 32 {
        if let Ok(hash) = AddressHash::new_from_hex_string(identity_str) {
            // Try to recall from network if -R flag is set
            if args.request {
                return request_identity_from_network(args, &hash).await;
            } else {
                return Err(format!(
                    "Could not recall identity for {}. Use -R to request from network.",
                    format_hash(hash.as_slice())
                ));
            }
        }
    }

    Err(format!("Could not load identity from: {}", identity_str))
}

/// Request an identity from the network
async fn request_identity_from_network(
    args: &Args,
    _hash: &AddressHash,
) -> Result<IdentityType, String> {
    let config = ReticulumConfig::load(args.config.clone())
        .map_err(|e| format!("Failed to load config: {}", e))?;

    let transport = create_transport(args, &config).await;

    // Give interfaces time to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    let timeout = Duration::from_secs_f64(args.timeout);
    let start = std::time::Instant::now();

    let mut spinner_idx = 0;

    // Request path and wait for identity
    // TODO: Implement transport.request_path() and identity recall
    // For now, we simulate the waiting with a timeout
    print!("\rRequesting identity... ");
    io::stdout().flush().ok();

    while start.elapsed() < timeout {
        // TODO: Check if identity has been received
        // if let Some(identity) = transport.recall_identity(hash) {
        //     println!("\rReceived identity from network");
        //     return Ok(IdentityType::Public(identity));
        // }

        print!("\rRequesting identity {} ", spinner_char(spinner_idx));
        io::stdout().flush().ok();
        spinner_idx += 1;

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    drop(transport);
    println!();
    Err("Identity request timed out".to_string())
}

/// Handle operations that require a private identity
async fn handle_private_identity_operations(
    args: &Args,
    identity: &PrivateIdentity,
    encoding: Encoding,
) -> i32 {
    if args.print_identity || args.export {
        print_identity_info(identity, args.print_private, args.export, encoding);
        return EXIT_OK;
    }

    if let Some(ref file) = args.sign {
        return handle_sign(args, identity, file);
    }

    if let Some(ref sig_file) = args.validate {
        return handle_validate(args, identity.as_identity(), sig_file);
    }

    if let Some(ref file) = args.encrypt {
        return handle_encrypt(args, identity.as_identity(), file);
    }

    if let Some(ref file) = args.decrypt {
        return handle_decrypt(args, identity, file);
    }

    if let Some(ref aspects) = args.announce {
        return handle_announce(args, identity, aspects).await;
    }

    // If we have an identity but no operation, just print it
    print_identity_info(identity, args.print_private, false, encoding);
    EXIT_OK
}

/// Handle operations that only have a public identity
fn handle_public_identity_operations(args: &Args, identity: &Identity, encoding: Encoding) -> i32 {
    if args.print_identity || args.export {
        print_public_identity_info(identity, args.export, encoding);
        return EXIT_OK;
    }

    if let Some(ref sig_file) = args.validate {
        return handle_validate(args, identity, sig_file);
    }

    if let Some(ref file) = args.encrypt {
        return handle_encrypt(args, identity, file);
    }

    if args.decrypt.is_some() {
        eprintln!("Error: Decryption requires a private key");
        return EXIT_DECRYPT_NO_PRIVATE_KEY;
    }

    if args.sign.is_some() {
        eprintln!("Error: Signing requires a private key");
        return EXIT_SIGNING_NO_PRIVATE_KEY;
    }

    if args.announce.is_some() {
        eprintln!("Error: Announcing requires a private key");
        return EXIT_ANNOUNCE_NO_PRIVATE_KEY;
    }

    print_public_identity_info(identity, false, encoding);
    EXIT_OK
}

/// Generate a new identity and save to file (Python-compatible interface)
fn handle_generate(args: &Args, path: &PathBuf, encoding: Encoding) -> i32 {
    log::info!("Generating new identity...");

    // Check if file exists
    if path.exists() && !args.force {
        eprintln!("Error: File already exists: {:?}", path);
        eprintln!("Use -f to overwrite");
        return EXIT_GENERAL_ERROR;
    }

    // Generate identity
    let identity = PrivateIdentity::new_from_rand(OsRng);

    // Save to file
    match export_identity_to_file(&identity, path) {
        Ok(_) => {
            // Print Python-compatible output format: timestamp + message
            let timestamp = chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]");
            println!(
                "{} New identity {} written to {}",
                timestamp,
                format_hash(identity.as_identity().address_hash.as_slice()),
                path.display()
            );

            // If verbose or print flags are set, also show full details
            if args.print_identity || args.verbose > 0 {
                println!();
                print_identity_info(&identity, args.print_private, false, encoding);
            }

            EXIT_OK
        }
        Err(e) => {
            eprintln!("Failed to save identity: {}", e);
            EXIT_GENERAL_ERROR
        }
    }
}

/// Import identity from encoded string
fn handle_import_string(args: &Args, import_data: &str, encoding: Encoding) -> i32 {
    let bytes = match encoding.decode(import_data) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error decoding identity data: {}", e);
            return EXIT_GENERAL_ERROR;
        }
    };

    if bytes.len() != 64 {
        eprintln!(
            "Error: Invalid identity data length: expected 64 bytes, got {}",
            bytes.len()
        );
        return EXIT_GENERAL_ERROR;
    }

    let identity = match PrivateIdentity::new_from_bytes(&bytes) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Error parsing identity: {:?}", e);
            return EXIT_GENERAL_ERROR;
        }
    };

    println!("Identity imported successfully");
    println!();
    print_identity_info(&identity, args.print_private, args.export, encoding);

    // Save to file if specified
    if let Some(ref path) = args.write {
        if path.exists() && !args.force {
            eprintln!("Error: File already exists: {:?}", path);
            eprintln!("Use -f to overwrite");
            return EXIT_GENERAL_ERROR;
        }

        match export_identity_to_file(&identity, path) {
            Ok(_) => {
                println!();
                println!("Identity saved to {:?}", path);
            }
            Err(e) => {
                eprintln!("Failed to save identity: {}", e);
                return EXIT_GENERAL_ERROR;
            }
        }
    }

    EXIT_OK
}

/// Compute destination hash for app.aspect format
fn handle_destination_hash(identity: &Identity, aspects: &str) -> i32 {
    let parts: Vec<&str> = aspects.split('.').collect();
    if parts.len() < 2 {
        eprintln!("Error: Invalid aspects format. Expected: app_name.aspect1[.aspect2...]");
        return EXIT_GENERAL_ERROR;
    }

    let app_name = parts[0];
    let aspect_parts = parts[1..].join(".");

    let name = match DestinationName::new(app_name, &aspect_parts) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Invalid destination name: {}", e);
            return EXIT_GENERAL_ERROR;
        }
    };
    let dest = SingleOutputDestination::new(*identity, name);

    println!(
        "The {} destination for this Identity is {}",
        aspects,
        format_hash(dest.desc.address_hash.as_slice())
    );

    EXIT_OK
}

/// Sign a file
fn handle_sign(args: &Args, identity: &PrivateIdentity, sign_file: &PathBuf) -> i32 {
    // Determine input file
    let input_path = args.read.as_ref().unwrap_or(sign_file);

    // Determine output file
    let output_path = args.write.clone().unwrap_or_else(|| {
        let mut p = input_path.clone();
        let new_name = format!(
            "{}.{}",
            p.file_name().unwrap_or_default().to_string_lossy(),
            SIG_EXT
        );
        p.set_file_name(new_name);
        p
    });

    // Check if output exists
    if output_path.exists() && !args.force {
        eprintln!("Error: Output file already exists: {:?}", output_path);
        eprintln!("Use -f to overwrite");
        return EXIT_SIGNING_WRITE_ERROR;
    }

    // Read input file
    let data = match fs::read(input_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading file {:?}: {}", input_path, e);
            return EXIT_SIGNING_READ_ERROR;
        }
    };

    // Sign the data
    let signature = identity.sign(&data);

    // Write signature
    match fs::write(&output_path, signature.to_bytes()) {
        Ok(_) => {
            log::info!(
                "Signed {:?}, signature written to {:?}",
                input_path,
                output_path
            );
            println!("Signature written to {:?}", output_path);
            EXIT_OK
        }
        Err(e) => {
            eprintln!("Error writing signature: {}", e);
            EXIT_SIGNING_WRITE_ERROR
        }
    }
}

/// Validate a signature
fn handle_validate(args: &Args, identity: &Identity, sig_file: &PathBuf) -> i32 {
    // Determine input file (the data file)
    let input_path = if let Some(ref path) = args.read {
        path.clone()
    } else {
        // Try to infer from signature file name
        let sig_str = sig_file.to_string_lossy();
        if sig_str.ends_with(&format!(".{}", SIG_EXT)) {
            PathBuf::from(&sig_str[..sig_str.len() - SIG_EXT.len() - 1])
        } else {
            eprintln!("Error: No input file specified. Use -r <file>");
            return EXIT_VALIDATE_READ_ERROR;
        }
    };

    // Read signature file
    let sig_bytes = match fs::read(sig_file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading signature file {:?}: {}", sig_file, e);
            return EXIT_VALIDATE_READ_ERROR;
        }
    };

    if sig_bytes.len() != 64 {
        eprintln!(
            "Error: Invalid signature file size: expected 64 bytes, got {}",
            sig_bytes.len()
        );
        return EXIT_VALIDATE_INVALID_SIG;
    }

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Error: Invalid signature format");
            return EXIT_VALIDATE_INVALID_SIG;
        }
    };

    // Read data file
    let data = match fs::read(&input_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading data file {:?}: {}", input_path, e);
            return EXIT_VALIDATE_READ_ERROR;
        }
    };

    // Verify signature
    match identity.verify(&data, &signature) {
        Ok(_) => {
            println!(
                "Signature {:?} for file {:?} is valid",
                sig_file, input_path
            );
            EXIT_OK
        }
        Err(_) => {
            eprintln!(
                "Signature {:?} for file {:?} is INVALID",
                sig_file, input_path
            );
            EXIT_VALIDATE_INVALID_SIG
        }
    }
}

/// Encrypt a file for an identity
fn handle_encrypt(args: &Args, identity: &Identity, encrypt_file: &PathBuf) -> i32 {
    // Determine input file
    let input_path = args.read.as_ref().unwrap_or(encrypt_file);

    // Determine output file
    let output_path = args.write.clone().unwrap_or_else(|| {
        let mut p = input_path.clone();
        let new_name = format!(
            "{}.{}",
            p.file_name().unwrap_or_default().to_string_lossy(),
            ENCRYPT_EXT
        );
        p.set_file_name(new_name);
        p
    });

    // Check if output exists
    if output_path.exists() && !args.force {
        eprintln!("Error: Output file already exists: {:?}", output_path);
        eprintln!("Use -f to overwrite");
        return EXIT_ENCRYPT_WRITE_ERROR;
    }

    // Open input file
    let mut input_file = match File::open(input_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening input file {:?}: {}", input_path, e);
            return EXIT_ENCRYPT_READ_ERROR;
        }
    };

    // Create output file
    let mut output_file = match File::create(&output_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error creating output file {:?}: {}", output_path, e);
            return EXIT_ENCRYPT_WRITE_ERROR;
        }
    };

    // Process in chunks
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let bytes_read = match input_file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                return EXIT_ENCRYPT_READ_ERROR;
            }
        };

        // Encrypt chunk using Identity::encrypt_for()
        match identity.encrypt_for(OsRng, &buffer[..bytes_read]) {
            Ok(encrypted) => {
                // Write length prefix (4 bytes big-endian) + encrypted data
                let len_bytes = (encrypted.len() as u32).to_be_bytes();
                if output_file.write_all(&len_bytes).is_err()
                    || output_file.write_all(&encrypted).is_err()
                {
                    eprintln!("Error writing output");
                    return EXIT_ENCRYPT_WRITE_ERROR;
                }
            }
            Err(e) => {
                eprintln!("Error encrypting data: {:?}", e);
                return EXIT_ENCRYPT_WRITE_ERROR;
            }
        }
    }

    log::info!(
        "Encrypted {:?}, output written to {:?}",
        input_path,
        output_path
    );
    println!("Encrypted file written to {:?}", output_path);
    EXIT_OK
}

/// Decrypt a file with a private identity
fn handle_decrypt(args: &Args, identity: &PrivateIdentity, decrypt_file: &PathBuf) -> i32 {
    // Determine input file
    let input_path = args.read.as_ref().unwrap_or(decrypt_file);

    // Determine output file
    let output_path = args.write.clone().unwrap_or_else(|| {
        let input_str = input_path.to_string_lossy();
        if input_str.ends_with(&format!(".{}", ENCRYPT_EXT)) {
            PathBuf::from(&input_str[..input_str.len() - ENCRYPT_EXT.len() - 1])
        } else {
            let mut p = input_path.clone();
            let new_name = format!(
                "{}.decrypted",
                p.file_name().unwrap_or_default().to_string_lossy()
            );
            p.set_file_name(new_name);
            p
        }
    });

    // Check if output exists
    if output_path.exists() && !args.force {
        eprintln!("Error: Output file already exists: {:?}", output_path);
        eprintln!("Use -f to overwrite");
        return EXIT_DECRYPT_WRITE_ERROR;
    }

    // Open input file
    let mut input_file = match File::open(input_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening input file {:?}: {}", input_path, e);
            return EXIT_DECRYPT_READ_ERROR;
        }
    };

    // Create output file
    let mut output_file = match File::create(&output_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error creating output file {:?}: {}", output_path, e);
            return EXIT_DECRYPT_WRITE_ERROR;
        }
    };

    // Process chunks
    let mut len_buffer = [0u8; 4];

    loop {
        // Read length prefix
        match input_file.read_exact(&mut len_buffer) {
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                return EXIT_DECRYPT_READ_ERROR;
            }
        }

        let chunk_len = u32::from_be_bytes(len_buffer) as usize;
        let mut chunk = vec![0u8; chunk_len];

        match input_file.read_exact(&mut chunk) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error reading encrypted chunk: {}", e);
                return EXIT_DECRYPT_READ_ERROR;
            }
        }

        // Decrypt chunk using PrivateIdentity::decrypt_for()
        match identity.decrypt_for(OsRng, &chunk) {
            Ok(decrypted) => {
                if output_file.write_all(&decrypted).is_err() {
                    eprintln!("Error writing output");
                    return EXIT_DECRYPT_WRITE_ERROR;
                }
            }
            Err(e) => {
                eprintln!("Error decrypting data: {:?}", e);
                return EXIT_DECRYPT_FAILED;
            }
        }
    }

    log::info!(
        "Decrypted {:?}, output written to {:?}",
        input_path,
        output_path
    );
    println!("Decrypted file written to {:?}", output_path);
    EXIT_OK
}

/// Announce a destination to the network
async fn handle_announce(args: &Args, identity: &PrivateIdentity, aspects: &str) -> i32 {
    let parts: Vec<&str> = aspects.split('.').collect();
    if parts.len() < 2 {
        eprintln!("Error: Invalid aspects format. Expected: app_name.aspect1[.aspect2...]");
        return EXIT_GENERAL_ERROR;
    }

    let app_name = parts[0];
    let aspect_parts = parts[1..].join(".");

    let config = match ReticulumConfig::load(args.config.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            return EXIT_GENERAL_ERROR;
        }
    };

    let name = match DestinationName::new(app_name, &aspect_parts) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Invalid destination name: {}", e);
            return EXIT_GENERAL_ERROR;
        }
    };
    let mut destination = SingleInputDestination::new(identity.clone(), name);

    log::info!(
        "Created destination {}",
        format_hash(destination.desc.address_hash.as_slice())
    );

    // Create transport and announce
    let transport = create_transport(args, &config).await;

    // Give interfaces time to connect
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Create and send announce packet
    let announce = match destination.announce(OsRng, None) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Failed to create announce: {:?}", e);
            return EXIT_GENERAL_ERROR;
        }
    };

    log::info!(
        "Announcing destination {}",
        format_hash(destination.desc.address_hash.as_slice())
    );

    // Send announce through transport
    transport.send_packet(announce).await;

    // Wait briefly for propagation
    tokio::time::sleep(Duration::from_millis(250)).await;

    println!(
        "Announced destination {}",
        format_hash(destination.desc.address_hash.as_slice())
    );

    EXIT_OK
}

/// Create transport with interfaces for network operations
async fn create_transport(args: &Args, _config: &ReticulumConfig) -> Transport {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport_config = TransportConfig::new("rnid", &identity, false);
    let transport = Transport::new(transport_config);

    // Set up interfaces from command line args
    if let Some(ref server_addr) = args.tcp_server {
        let name = format!("TCPServerInterface[{}]", server_addr);
        transport.spawn_interface(
            TcpServer::new(server_addr, transport.iface_manager()),
            TcpServer::spawn,
            &name,
        ).await;
    }

    if let Some(ref client_addr) = args.tcp_client {
        let name = format!("TCPInterface[{}]", client_addr);
        transport.spawn_interface(
            TcpClient::new(client_addr),
            TcpClient::spawn,
            &name,
        ).await;
    }

    // TODO: Connect to shared instance if available via IPC
    // Currently the LocalClientInterface is not implemented
    // let socket_dir = config.paths.config_dir.join("sockets");
    // if socket_dir.exists() { ... }

    transport
}

/// Print identity information
fn print_identity_info(
    identity: &PrivateIdentity,
    show_private: bool,
    export_mode: bool,
    encoding: Encoding,
) {
    let public = identity.as_identity();

    if export_mode {
        // Export just the encoded identity data
        println!("{}", encoding.encode(&identity.to_bytes()));
        return;
    }

    println!("Address Hash:  {}", format_hash(public.address_hash.as_slice()));
    println!("Public Key:    {}", encoding.encode(public.public_key_bytes()));
    println!("Verifying Key: {}", encoding.encode(public.verifying_key_bytes()));

    if show_private {
        println!();
        println!("Private Key:   {}", encoding.encode(&identity.to_bytes()[..32]));
        println!("Signing Key:   {}", encoding.encode(&identity.to_bytes()[32..]));
    }
}

/// Print public-only identity information
fn print_public_identity_info(identity: &Identity, export_mode: bool, encoding: Encoding) {
    if export_mode {
        // Export just the encoded public key data
        let mut pub_bytes = [0u8; 64];
        pub_bytes[..32].copy_from_slice(identity.public_key_bytes());
        pub_bytes[32..].copy_from_slice(identity.verifying_key_bytes());
        println!("{}", encoding.encode(&pub_bytes));
        return;
    }

    println!("Address Hash:  {}", format_hash(identity.address_hash.as_slice()));
    println!("Public Key:    {}", encoding.encode(identity.public_key_bytes()));
    println!("Verifying Key: {}", encoding.encode(identity.verifying_key_bytes()));
    println!();
    println!("(Public identity only - no private key available)");
}

fn export_identity_to_file(identity: &PrivateIdentity, path: &PathBuf) -> Result<(), String> {
    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    // Export as binary (Python-compatible format)
    let bytes = identity.to_bytes();

    let mut file = File::create(path).map_err(|e| format!("Failed to create file: {}", e))?;
    file.write_all(&bytes)
        .map_err(|e| format!("Failed to write file: {}", e))?;

    Ok(())
}

fn load_identity_from_file(path: &PathBuf) -> Result<PrivateIdentity, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    // Binary format: 64 bytes (Python-compatible)
    if bytes.len() != 64 {
        return Err(format!(
            "Invalid identity file: expected 64 bytes, got {} bytes",
            bytes.len()
        ));
    }

    PrivateIdentity::new_from_bytes(&bytes)
        .map_err(|e| format!("Failed to parse identity: {:?}", e))
}

fn print_usage() {
    eprintln!("No action specified. Use --help for usage information.");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  rnid -g identity.dat          Generate and save new identity");
    eprintln!("  rnid -i identity.dat -p       Print identity information");
    eprintln!("  rnid -i identity.dat -x       Export identity as hex");
    eprintln!("  rnid -i identity.dat -s file  Sign a file");
    eprintln!("  rnid -i identity.dat -V file.rsg -r file  Validate signature");
    eprintln!("  rnid -i identity.dat -e file  Encrypt a file");
    eprintln!("  rnid -i identity.dat -d file.rfe  Decrypt a file");
    eprintln!("  rnid -i identity.dat -H app.aspect  Compute destination hash");
    eprintln!("  rnid -i identity.dat -a app.aspect  Announce destination");
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // Encoding Tests
    // ==========================================================================

    #[test]
    fn test_encoding_hex_roundtrip() {
        let data = b"Hello, Reticulum!";
        let encoding = Encoding::Hex;

        let encoded = encoding.encode(data);
        let decoded = encoding.decode(&encoded).unwrap();

        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_encoding_base64_roundtrip() {
        let data = b"Hello, Reticulum!";
        let encoding = Encoding::Base64;

        let encoded = encoding.encode(data);
        let decoded = encoding.decode(&encoded).unwrap();

        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_encoding_base32_roundtrip() {
        let data = b"Hello, Reticulum!";
        let encoding = Encoding::Base32;

        let encoded = encoding.encode(data);
        let decoded = encoding.decode(&encoded).unwrap();

        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_encoding_identity_bytes() {
        // Test encoding a 64-byte identity
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let bytes = identity.to_bytes();

        for encoding in [Encoding::Hex, Encoding::Base64, Encoding::Base32] {
            let encoded = encoding.encode(&bytes);
            let decoded = encoding.decode(&encoded).unwrap();
            assert_eq!(bytes.as_slice(), decoded.as_slice());
        }
    }

    #[test]
    fn test_encoding_decode_invalid_hex() {
        let encoding = Encoding::Hex;
        let result = encoding.decode("not_valid_hex_zzz");
        assert!(result.is_err());
    }

    #[test]
    fn test_encoding_decode_invalid_base64() {
        let encoding = Encoding::Base64;
        // Invalid base64 (wrong padding)
        let result = encoding.decode("!!!invalid!!!");
        assert!(result.is_err());
    }

    // ==========================================================================
    // Identity File I/O Tests
    // ==========================================================================

    #[test]
    fn test_identity_file_roundtrip() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("rnid_test_identity.dat");

        // Generate identity
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let original_hash = identity.as_identity().address_hash;

        // Export to file
        export_identity_to_file(&identity, &temp_file).unwrap();

        // Import from file
        let loaded = load_identity_from_file(&temp_file).unwrap();
        let loaded_hash = loaded.as_identity().address_hash;

        assert_eq!(original_hash.as_slice(), loaded_hash.as_slice());

        // Cleanup
        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_load_invalid_identity_file() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("rnid_test_invalid.dat");

        // Write invalid data (wrong size)
        std::fs::write(&temp_file, b"too short").unwrap();

        let result = load_identity_from_file(&temp_file);
        assert!(result.is_err());
        let err_msg = result.err().unwrap();
        assert!(err_msg.contains("expected 64 bytes"));

        // Cleanup
        std::fs::remove_file(&temp_file).ok();
    }

    // ==========================================================================
    // Encryption/Decryption Tests
    // ==========================================================================

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let plaintext = b"Secret message for Reticulum testing!";

        // Encrypt using public identity
        let encrypted = identity.as_identity().encrypt_for(OsRng, plaintext).unwrap();

        // Decrypt using private identity
        let decrypted = identity.decrypt_for(OsRng, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let plaintext = b"";

        let encrypted = identity.as_identity().encrypt_for(OsRng, plaintext).unwrap();
        let decrypted = identity.decrypt_for(OsRng, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        // Test with 1KB of data
        let plaintext: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();

        let encrypted = identity.as_identity().encrypt_for(OsRng, &plaintext).unwrap();
        let decrypted = identity.decrypt_for(OsRng, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_wrong_identity_fails() {
        let identity1 = PrivateIdentity::new_from_rand(OsRng);
        let identity2 = PrivateIdentity::new_from_rand(OsRng);
        let plaintext = b"Secret message";

        // Encrypt for identity1
        let encrypted = identity1.as_identity().encrypt_for(OsRng, plaintext).unwrap();

        // Try to decrypt with identity2 - should fail
        let result = identity2.decrypt_for(OsRng, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_corrupted_data_fails() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let plaintext = b"Secret message";

        let encrypted = identity.as_identity().encrypt_for(OsRng, plaintext).unwrap();

        // Corrupt the encrypted data
        let mut corrupted = encrypted.clone();
        if corrupted.len() > 40 {
            corrupted[40] ^= 0xFF; // Flip bits in the ciphertext
        }

        let result = identity.decrypt_for(OsRng, &corrupted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short_fails() {
        let identity = PrivateIdentity::new_from_rand(OsRng);

        // Data shorter than ephemeral key size
        let short_data = vec![0u8; 16];
        let result = identity.decrypt_for(OsRng, &short_data);
        assert!(result.is_err());
    }

    // ==========================================================================
    // Signing/Verification Tests
    // ==========================================================================

    #[test]
    fn test_sign_verify_roundtrip() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let message = b"Message to be signed";

        // Sign
        let signature = identity.sign(message);

        // Verify
        let result = identity.as_identity().verify(message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let message = b"Original message";
        let wrong_message = b"Different message";

        let signature = identity.sign(message);

        let result = identity.as_identity().verify(wrong_message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_identity_fails() {
        let identity1 = PrivateIdentity::new_from_rand(OsRng);
        let identity2 = PrivateIdentity::new_from_rand(OsRng);
        let message = b"Message to sign";

        // Sign with identity1
        let signature = identity1.sign(message);

        // Verify with identity2 - should fail
        let result = identity2.as_identity().verify(message, &signature);
        assert!(result.is_err());
    }

    // ==========================================================================
    // Destination Hash Tests
    // ==========================================================================

    #[test]
    fn test_destination_hash_deterministic() {
        let identity = PrivateIdentity::new_from_rand(OsRng);

        // Same identity + aspects should produce same hash
        let name1 = DestinationName::new("myapp", "test.aspect").unwrap();
        let dest1 = SingleOutputDestination::new(*identity.as_identity(), name1);

        let name2 = DestinationName::new("myapp", "test.aspect").unwrap();
        let dest2 = SingleOutputDestination::new(*identity.as_identity(), name2);

        assert_eq!(
            dest1.desc.address_hash.as_slice(),
            dest2.desc.address_hash.as_slice()
        );
    }

    #[test]
    fn test_destination_hash_different_aspects() {
        let identity = PrivateIdentity::new_from_rand(OsRng);

        let name1 = DestinationName::new("myapp", "aspect1").unwrap();
        let dest1 = SingleOutputDestination::new(*identity.as_identity(), name1);

        let name2 = DestinationName::new("myapp", "aspect2").unwrap();
        let dest2 = SingleOutputDestination::new(*identity.as_identity(), name2);

        // Different aspects should produce different hashes
        assert_ne!(
            dest1.desc.address_hash.as_slice(),
            dest2.desc.address_hash.as_slice()
        );
    }

    #[test]
    fn test_destination_hash_different_identities() {
        let identity1 = PrivateIdentity::new_from_rand(OsRng);
        let identity2 = PrivateIdentity::new_from_rand(OsRng);

        let name = DestinationName::new("myapp", "test").unwrap();

        let dest1 = SingleOutputDestination::new(*identity1.as_identity(), name);
        let dest2 = SingleOutputDestination::new(*identity2.as_identity(), name);

        // Different identities should produce different hashes
        assert_ne!(
            dest1.desc.address_hash.as_slice(),
            dest2.desc.address_hash.as_slice()
        );
    }

    // ==========================================================================
    // Python Interoperability Tests
    // ==========================================================================

    #[test]
    fn test_identity_binary_format_size() {
        // Python uses 64-byte binary format for identities
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let bytes = identity.to_bytes();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn test_signature_size() {
        // Ed25519 signatures are 64 bytes
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let signature = identity.sign(b"test");
        assert_eq!(signature.to_bytes().len(), 64);
    }

    #[test]
    fn test_address_hash_size() {
        // Address hashes are truncated to 16 bytes (128 bits)
        let identity = PrivateIdentity::new_from_rand(OsRng);
        assert_eq!(identity.as_identity().address_hash.as_slice().len(), 16);
    }
}
