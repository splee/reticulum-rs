//! Test GROUP destination encryption/decryption interoperability
//!
//! This binary tests that Rust can encrypt/decrypt data using the same
//! GROUP key format as Python Reticulum (64-byte key for AES-256-CBC).
//!
//! Supported commands (read from stdin):
//! - encrypt: Encrypt data with a GROUP key
//! - decrypt: Decrypt data with a GROUP key
//! - key-split: Output signing and encryption key halves
//! - address-hash: Compute GROUP destination address hash

use std::io::{self, BufRead};

use rand_core::OsRng;
use reticulum::destination::group::{GroupDestination, GroupKey};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    // Read command - first line
    let mode = lines.next().expect("Expected mode").expect("Failed to read mode");
    let mode = mode.trim();

    match mode {
        "encrypt" | "decrypt" => handle_encrypt_decrypt(mode, &mut lines),
        "key-split" => handle_key_split(&mut lines),
        "address-hash" => handle_address_hash(&mut lines),
        _ => {
            eprintln!("ERROR: Unknown mode '{}'. Use 'encrypt', 'decrypt', 'key-split', or 'address-hash'", mode);
            std::process::exit(1);
        }
    }
}

/// Handle encrypt/decrypt commands
fn handle_encrypt_decrypt(mode: &str, lines: &mut impl Iterator<Item = Result<String, io::Error>>) {
    // Read key (64 bytes = 128 hex chars)
    let key_hex = lines.next().expect("Expected key").expect("Failed to read key");
    let key_hex = key_hex.trim();

    // Read data
    let data_hex = lines.next().expect("Expected data").expect("Failed to read data");
    let data_hex = data_hex.trim();

    // Parse key
    let key_bytes = hex::decode(key_hex).expect("Invalid key hex");
    if key_bytes.len() != 64 {
        eprintln!("ERROR: Key must be 64 bytes (128 hex chars), got {} bytes", key_bytes.len());
        std::process::exit(1);
    }
    let group_key = GroupKey::from_bytes(&key_bytes).expect("Failed to create GroupKey");

    // Parse data
    let data_bytes = hex::decode(data_hex).expect("Invalid data hex");

    match mode {
        "encrypt" => {
            let mut out_buf = vec![0u8; data_bytes.len() + 256]; // Extra space for padding + overhead
            match group_key.encrypt(OsRng, &data_bytes, &mut out_buf) {
                Ok(ciphertext) => {
                    println!("RESULT={}", hex::encode(ciphertext));
                    println!("STATUS=OK");
                }
                Err(e) => {
                    eprintln!("ERROR: Encryption failed: {:?}", e);
                    println!("STATUS=ERROR");
                    std::process::exit(1);
                }
            }
        }
        "decrypt" => {
            let mut out_buf = vec![0u8; data_bytes.len()];
            match group_key.decrypt(OsRng, &data_bytes, &mut out_buf) {
                Ok(plaintext) => {
                    println!("RESULT={}", hex::encode(plaintext));
                    println!("STATUS=OK");
                }
                Err(e) => {
                    eprintln!("ERROR: Decryption failed: {:?}", e);
                    println!("STATUS=ERROR");
                    std::process::exit(1);
                }
            }
        }
        _ => unreachable!(),
    }
}

/// Handle key-split command: output signing and encryption key halves
fn handle_key_split(lines: &mut impl Iterator<Item = Result<String, io::Error>>) {
    let key_hex = lines.next().expect("Expected key").expect("Failed to read key");
    let key_hex = key_hex.trim();

    let key_bytes = hex::decode(key_hex).expect("Invalid key hex");
    if key_bytes.len() != 64 {
        eprintln!("ERROR: Key must be 64 bytes (128 hex chars), got {} bytes", key_bytes.len());
        std::process::exit(1);
    }

    let group_key = GroupKey::from_bytes(&key_bytes).expect("Failed to create GroupKey");

    println!("SIGNING_KEY={}", hex::encode(group_key.signing_key()));
    println!("ENCRYPTION_KEY={}", hex::encode(group_key.encryption_key()));
    println!("STATUS=OK");
}

/// Handle address-hash command: compute GROUP destination address hash
fn handle_address_hash(lines: &mut impl Iterator<Item = Result<String, io::Error>>) {
    let key_hex = lines.next().expect("Expected key").expect("Failed to read key");
    let key_hex = key_hex.trim();

    let app_name = lines.next().expect("Expected app_name").expect("Failed to read app_name");
    let app_name = app_name.trim();

    let aspects = lines.next().expect("Expected aspects").expect("Failed to read aspects");
    let aspects = aspects.trim();

    let key_bytes = hex::decode(key_hex).expect("Invalid key hex");
    if key_bytes.len() != 64 {
        eprintln!("ERROR: Key must be 64 bytes (128 hex chars), got {} bytes", key_bytes.len());
        std::process::exit(1);
    }

    let group_key = GroupKey::from_bytes(&key_bytes).expect("Failed to create GroupKey");
    let dest = GroupDestination::with_key(group_key, app_name, aspects);

    println!("ADDRESS_HASH={}", dest.address_hash().to_hex_string());
    println!("STATUS=OK");
}
