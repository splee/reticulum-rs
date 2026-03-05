//! Test GROUP destination encryption/decryption interoperability
//!
//! This binary tests that Rust can encrypt/decrypt data using the same
//! GROUP key format as Python Reticulum (64-byte key for AES-256-CBC).

use std::io::{self, BufRead};

use rand_core::OsRng;
use reticulum::destination::group::GroupKey;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    // Read mode (encrypt/decrypt) - first line
    let mode = lines.next().expect("Expected mode").expect("Failed to read mode");
    let mode = mode.trim();

    // Read key (64 bytes = 128 hex chars) - second line
    let key_hex = lines.next().expect("Expected key").expect("Failed to read key");
    let key_hex = key_hex.trim();

    // Read data - third line
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
        _ => {
            eprintln!("ERROR: Unknown mode '{}'. Use 'encrypt' or 'decrypt'", mode);
            std::process::exit(1);
        }
    }
}
