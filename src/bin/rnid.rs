//! Reticulum Identity Manager
//!
//! Generate, import, export, and display identity information.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use clap::Parser;
use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;
use reticulum::logging;

/// Reticulum Identity Manager
#[derive(Parser, Debug)]
#[command(name = "rnid")]
#[command(author = "Reticulum Network Stack")]
#[command(version)]
#[command(about = "Manage Reticulum identities", long_about = None)]
struct Args {
    /// Generate a new identity
    #[arg(short, long)]
    generate: bool,

    /// Export identity to file
    #[arg(short, long, value_name = "FILE")]
    export: Option<PathBuf>,

    /// Import identity from file
    #[arg(short, long, value_name = "FILE")]
    import: Option<PathBuf>,

    /// Print/display identity information
    #[arg(short, long, value_name = "FILE")]
    print: Option<PathBuf>,

    /// Output as hex string
    #[arg(long)]
    hex: bool,
}

fn main() {
    let args = Args::parse();

    // Initialize logging
    logging::init_default();

    if args.generate {
        generate_identity(args.export.as_ref(), args.hex);
    } else if let Some(path) = &args.import {
        import_identity(path);
    } else if let Some(path) = &args.print {
        print_identity(path, args.hex);
    } else {
        eprintln!("No action specified. Use --help for usage information.");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  rnid -g                    Generate new identity");
        eprintln!("  rnid -g -e identity.dat    Generate and save to file");
        eprintln!("  rnid -p identity.dat       Print identity information");
        eprintln!("  rnid -i identity.dat       Import identity from file");
        std::process::exit(1);
    }
}

fn generate_identity(export_path: Option<&PathBuf>, as_hex: bool) {
    println!("Generating new identity...");
    println!();

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let public = identity.as_identity();

    println!("Identity generated successfully");
    println!();
    println!("Address Hash:  {}", format_hash(public.address_hash.as_slice()));

    if as_hex {
        println!("Public Key:    {}", format_hex(public.public_key_bytes()));
        println!("Verifying Key: {}", format_hex(public.verifying_key_bytes()));
    }

    if let Some(path) = export_path {
        match export_identity_to_file(&identity, path) {
            Ok(_) => {
                println!();
                println!("Identity exported to {:?}", path);
            }
            Err(e) => {
                eprintln!("Failed to export identity: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!();
        println!("Note: Identity not saved. Use -e <file> to export.");
    }
}

fn import_identity(path: &PathBuf) {
    println!("Importing identity from {:?}", path);
    println!();

    match load_identity_from_file(path) {
        Ok(identity) => {
            let public = identity.as_identity();
            println!("Identity imported successfully");
            println!();
            println!("Address Hash: {}", format_hash(public.address_hash.as_slice()));
        }
        Err(e) => {
            eprintln!("Failed to import identity: {}", e);
            std::process::exit(1);
        }
    }
}

fn print_identity(path: &PathBuf, as_hex: bool) {
    match load_identity_from_file(path) {
        Ok(identity) => {
            let public = identity.as_identity();

            println!("Identity Information");
            println!("====================");
            println!();
            println!("File:          {:?}", path);
            println!("Address Hash:  {}", format_hash(public.address_hash.as_slice()));

            if as_hex {
                println!();
                println!("Public Key:    {}", format_hex(public.public_key_bytes()));
                println!("Verifying Key: {}", format_hex(public.verifying_key_bytes()));
            }
        }
        Err(e) => {
            eprintln!("Failed to load identity: {}", e);
            std::process::exit(1);
        }
    }
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

fn format_hash(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2 + 2);
    hex.push('/');
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex.push('/');
    hex
}

fn format_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}
