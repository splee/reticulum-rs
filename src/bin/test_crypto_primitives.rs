//! Test binary for cryptographic primitive interoperability.
//!
//! This binary provides a stdin-based interface for testing Ed25519 signatures,
//! X25519 key exchange, and HKDF key derivation for Python-Rust cross-validation.
//!
//! ## Commands
//!
//! ### Ed25519 Sign
//! ```
//! ed25519-sign <priv_hex> <msg_hex>
//! ```
//! Signs a message with Ed25519. Output: SIGNATURE=<hex>
//!
//! ### Ed25519 Verify
//! ```
//! ed25519-verify <pub_hex> <msg_hex> <sig_hex>
//! ```
//! Verifies an Ed25519 signature. Output: VALID=true|false
//!
//! ### X25519 Key Generation
//! ```
//! x25519-keygen [seed_hex]
//! ```
//! Generates an X25519 key pair. Output: PRIV_KEY=<hex>, PUB_KEY=<hex>
//!
//! ### X25519 Key Exchange
//! ```
//! x25519-exchange <priv_hex> <peer_pub_hex>
//! ```
//! Performs X25519 key exchange. Output: SHARED_SECRET=<hex>
//!
//! ### HKDF Derive
//! ```
//! hkdf-derive <secret_hex> [salt_hex]
//! ```
//! Derives a key using HKDF-SHA256. Output: DERIVED_KEY=<hex>

use std::io::{self, BufRead, Write as IoWrite};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use reticulum::crypt::hkdf::hkdf_into;
use reticulum::identity::DERIVED_KEY_LENGTH;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("ERROR: Failed to read line: {}", e);
                continue;
            }
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse command and arguments
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        let cmd = parts[0];
        let args = parts.get(1).copied().unwrap_or("");

        match cmd {
            "ed25519-sign" => {
                if let Err(e) = handle_ed25519_sign(args, &mut stdout) {
                    writeln!(stdout, "ERROR={}", e).ok();
                }
            }
            "ed25519-verify" => {
                if let Err(e) = handle_ed25519_verify(args, &mut stdout) {
                    writeln!(stdout, "ERROR={}", e).ok();
                }
            }
            "x25519-keygen" => {
                if let Err(e) = handle_x25519_keygen(args, &mut stdout) {
                    writeln!(stdout, "ERROR={}", e).ok();
                }
            }
            "x25519-exchange" => {
                if let Err(e) = handle_x25519_exchange(args, &mut stdout) {
                    writeln!(stdout, "ERROR={}", e).ok();
                }
            }
            "hkdf-derive" => {
                if let Err(e) = handle_hkdf_derive(args, &mut stdout) {
                    writeln!(stdout, "ERROR={}", e).ok();
                }
            }
            _ => {
                writeln!(stdout, "ERROR=Unknown command: {}", cmd).ok();
            }
        }
        stdout.flush().ok();
    }
}

/// Handle ed25519-sign command.
/// Input: <priv_hex> <msg_hex>
/// Output: SIGNATURE=<hex>
fn handle_ed25519_sign(args: &str, out: &mut impl IoWrite) -> Result<(), String> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Usage: ed25519-sign <priv_hex> <msg_hex>".to_string());
    }

    let priv_hex = parts[0];
    let msg_hex = parts[1];

    // Parse private key (32 bytes)
    let priv_bytes = hex::decode(priv_hex).map_err(|e| format!("Invalid priv hex: {}", e))?;
    if priv_bytes.len() != 32 {
        return Err(format!(
            "Private key must be 32 bytes, got {}",
            priv_bytes.len()
        ));
    }

    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(&priv_bytes);

    // Create signing key from private bytes
    let signing_key = SigningKey::from_bytes(&priv_arr);

    // Parse message
    let msg_bytes = hex::decode(msg_hex).map_err(|e| format!("Invalid msg hex: {}", e))?;

    // Sign the message
    let signature = signing_key.sign(&msg_bytes);

    writeln!(out, "SIGNATURE={}", hex::encode(signature.to_bytes())).ok();
    writeln!(out, "STATUS=OK").ok();

    Ok(())
}

/// Handle ed25519-verify command.
/// Input: <pub_hex> <msg_hex> <sig_hex>
/// Output: VALID=true|false
fn handle_ed25519_verify(args: &str, out: &mut impl IoWrite) -> Result<(), String> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("Usage: ed25519-verify <pub_hex> <msg_hex> <sig_hex>".to_string());
    }

    let pub_hex = parts[0];
    let msg_hex = parts[1];
    let sig_hex = parts[2];

    // Parse public key (32 bytes)
    let pub_bytes = hex::decode(pub_hex).map_err(|e| format!("Invalid pub hex: {}", e))?;
    if pub_bytes.len() != 32 {
        return Err(format!(
            "Public key must be 32 bytes, got {}",
            pub_bytes.len()
        ));
    }

    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);

    let verifying_key = VerifyingKey::from_bytes(&pub_arr)
        .map_err(|e| format!("Invalid public key: {}", e))?;

    // Parse message
    let msg_bytes = hex::decode(msg_hex).map_err(|e| format!("Invalid msg hex: {}", e))?;

    // Parse signature (64 bytes)
    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("Invalid sig hex: {}", e))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "Signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let signature = Signature::from_bytes(&sig_arr);

    // Verify the signature
    let valid = verifying_key.verify(&msg_bytes, &signature).is_ok();

    writeln!(out, "VALID={}", valid).ok();
    writeln!(out, "STATUS=OK").ok();

    Ok(())
}

/// Handle x25519-keygen command.
/// Input: [seed_hex] (optional)
/// Output: PRIV_KEY=<hex>, PUB_KEY=<hex>
fn handle_x25519_keygen(args: &str, out: &mut impl IoWrite) -> Result<(), String> {
    let args = args.trim();

    let private_key = if args.is_empty() {
        // Generate random key
        StaticSecret::random_from_rng(OsRng)
    } else {
        // Use seed to generate deterministic key
        let seed_bytes = hex::decode(args).map_err(|e| format!("Invalid seed hex: {}", e))?;
        if seed_bytes.len() != 32 {
            return Err(format!("Seed must be 32 bytes, got {}", seed_bytes.len()));
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed_bytes);
        StaticSecret::from(seed_arr)
    };

    let public_key = PublicKey::from(&private_key);

    writeln!(out, "PRIV_KEY={}", hex::encode(private_key.as_bytes())).ok();
    writeln!(out, "PUB_KEY={}", hex::encode(public_key.as_bytes())).ok();
    writeln!(out, "STATUS=OK").ok();

    Ok(())
}

/// Handle x25519-exchange command.
/// Input: <priv_hex> <peer_pub_hex>
/// Output: SHARED_SECRET=<hex>
fn handle_x25519_exchange(args: &str, out: &mut impl IoWrite) -> Result<(), String> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Usage: x25519-exchange <priv_hex> <peer_pub_hex>".to_string());
    }

    let priv_hex = parts[0];
    let peer_pub_hex = parts[1];

    // Parse private key (32 bytes)
    let priv_bytes = hex::decode(priv_hex).map_err(|e| format!("Invalid priv hex: {}", e))?;
    if priv_bytes.len() != 32 {
        return Err(format!(
            "Private key must be 32 bytes, got {}",
            priv_bytes.len()
        ));
    }

    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(&priv_bytes);
    let private_key = StaticSecret::from(priv_arr);

    // Parse peer public key (32 bytes)
    let peer_pub_bytes =
        hex::decode(peer_pub_hex).map_err(|e| format!("Invalid peer pub hex: {}", e))?;
    if peer_pub_bytes.len() != 32 {
        return Err(format!(
            "Peer public key must be 32 bytes, got {}",
            peer_pub_bytes.len()
        ));
    }

    let mut peer_pub_arr = [0u8; 32];
    peer_pub_arr.copy_from_slice(&peer_pub_bytes);
    let peer_public_key = PublicKey::from(peer_pub_arr);

    // Perform key exchange
    let shared_secret = private_key.diffie_hellman(&peer_public_key);

    writeln!(out, "SHARED_SECRET={}", hex::encode(shared_secret.as_bytes())).ok();
    writeln!(out, "STATUS=OK").ok();

    Ok(())
}

/// Handle hkdf-derive command.
/// Input: <secret_hex> [salt_hex]
/// Output: DERIVED_KEY=<hex>
fn handle_hkdf_derive(args: &str, out: &mut impl IoWrite) -> Result<(), String> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Usage: hkdf-derive <secret_hex> [salt_hex]".to_string());
    }

    let secret_hex = parts[0];
    let salt_hex = parts.get(1).copied();

    // Parse shared secret
    let secret_bytes = hex::decode(secret_hex).map_err(|e| format!("Invalid secret hex: {}", e))?;

    // Parse salt (optional)
    let salt = if let Some(hex) = salt_hex {
        Some(hex::decode(hex).map_err(|e| format!("Invalid salt hex: {}", e))?)
    } else {
        None
    };

    // Derive key using Python-compatible HKDF-SHA256
    let mut derived_key = [0u8; DERIVED_KEY_LENGTH];
    hkdf_into(&secret_bytes, salt.as_deref(), None, &mut derived_key);

    writeln!(out, "DERIVED_KEY={}", hex::encode(derived_key)).ok();
    writeln!(out, "STATUS=OK").ok();

    Ok(())
}
