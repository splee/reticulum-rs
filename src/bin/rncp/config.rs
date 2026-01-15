//! Configuration and identity management for rncp.
//!
//! This module handles:
//! - Config directory paths
//! - Identity file loading and creation
//! - Allowed identity list management
//! - Fetch server configuration

use std::path::{Path, PathBuf};

use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;

use super::APP_NAME;

/// Get the default Reticulum config directory.
///
/// Returns the override path if provided, otherwise defaults to ~/.reticulum.
pub fn get_config_dir(config_override: Option<&str>) -> PathBuf {
    if let Some(path) = config_override {
        PathBuf::from(path)
    } else {
        // Default: ~/.reticulum
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".reticulum")
    }
}

/// Get the identity file path.
///
/// Returns the override path if provided, otherwise defaults to
/// `{config_dir}/identities/{app_name}`.
pub fn get_identity_path(config_dir: &Path, identity_override: Option<&str>) -> PathBuf {
    if let Some(path) = identity_override {
        PathBuf::from(path)
    } else {
        config_dir.join("identities").join(APP_NAME)
    }
}

/// Load allowed identity hashes from config files.
///
/// Checks the following locations (in order of precedence):
/// - /etc/rncp/allowed_identities
/// - ~/.config/rncp/allowed_identities
/// - ~/.rncp/allowed_identities
///
/// Returns a list of 16-byte identity hashes parsed from the first found file.
pub fn load_allowed_identities() -> Vec<[u8; 16]> {
    let mut allowed = Vec::new();
    let allowed_file_name = "allowed_identities";

    // Possible config file locations (in order of precedence)
    let paths = [
        PathBuf::from("/etc/rncp").join(allowed_file_name),
        dirs::home_dir()
            .unwrap_or_default()
            .join(".config/rncp")
            .join(allowed_file_name),
        dirs::home_dir()
            .unwrap_or_default()
            .join(".rncp")
            .join(allowed_file_name),
    ];

    for path in &paths {
        if path.exists() {
            log::info!("Loading allowed identities from {}", path.display());
            if let Ok(contents) = std::fs::read_to_string(path) {
                for line in contents.lines() {
                    let line = line.trim();
                    // Skip comments and empty lines
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    // Parse hex hash (should be 32 hex chars = 16 bytes)
                    if line.len() == 32 {
                        if let Ok(bytes) = hex::decode(line) {
                            if bytes.len() == 16 {
                                let mut hash = [0u8; 16];
                                hash.copy_from_slice(&bytes);
                                allowed.push(hash);
                                log::debug!("Added allowed identity: {}", line);
                            }
                        }
                    }
                }
            }
            break; // Only use first found file
        }
    }

    allowed
}

/// Parse allowed identity hashes from CLI arguments.
///
/// Each argument should be a 32-character hex string representing a 16-byte hash.
pub fn parse_allowed_from_cli(allowed_args: Option<clap::parser::ValuesRef<String>>) -> Vec<[u8; 16]> {
    let mut allowed = Vec::new();

    if let Some(hashes) = allowed_args {
        for hash_str in hashes {
            let hash_str = hash_str.trim();
            if hash_str.len() == 32 {
                if let Ok(bytes) = hex::decode(hash_str) {
                    if bytes.len() == 16 {
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&bytes);
                        allowed.push(hash);
                        log::debug!("Added allowed identity from CLI: {}", hash_str);
                    }
                }
            } else {
                eprintln!("Warning: Invalid identity hash '{}' (must be 32 hex chars)", hash_str);
            }
        }
    }

    allowed
}

/// Load or create an identity, persisting to file.
///
/// If an identity file exists at the given path, attempts to load it.
/// Otherwise, creates a new identity and saves it.
pub fn prepare_identity(identity_path: &PathBuf) -> Result<PrivateIdentity, Box<dyn std::error::Error>> {
    // Try to load existing identity
    if identity_path.exists() {
        match std::fs::read_to_string(identity_path) {
            Ok(hex_string) => {
                let hex_string = hex_string.trim();
                match PrivateIdentity::new_from_hex_string(hex_string) {
                    Ok(identity) => {
                        log::info!(
                            "Loaded identity from {}",
                            identity_path.display()
                        );
                        return Ok(identity);
                    }
                    Err(e) => {
                        log::error!(
                            "Could not load identity from {}: {:?}",
                            identity_path.display(),
                            e
                        );
                        return Err(format!(
                            "Could not load identity for rncp. The identity file at \"{}\" may be corrupt or unreadable.",
                            identity_path.display()
                        ).into());
                    }
                }
            }
            Err(e) => {
                log::error!("Could not read identity file: {}", e);
                return Err(format!(
                    "Could not read identity file at \"{}\": {}",
                    identity_path.display(),
                    e
                ).into());
            }
        }
    }

    // Create new identity
    log::info!("No valid saved identity found, creating new...");
    let identity = PrivateIdentity::new_from_rand(OsRng);

    // Ensure parent directory exists
    if let Some(parent) = identity_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Save identity
    let hex_string = identity.to_hex_string();
    std::fs::write(identity_path, &hex_string)?;
    log::info!("Saved new identity to {}", identity_path.display());

    Ok(identity)
}

/// Configuration for listen mode fetch server.
pub struct FetchServerConfig {
    /// Whether to allow fetch requests.
    pub allow_fetch: bool,
    /// Whether to skip authentication.
    #[allow(dead_code)]
    pub no_auth: bool,
    /// Jail directory for fetch requests (files must be under this path).
    pub fetch_jail: Option<PathBuf>,
    /// List of allowed identity hashes for authentication.
    #[allow(dead_code)]
    pub allowed_identity_hashes: Vec<[u8; 16]>,
    /// Whether to auto-compress resources.
    pub auto_compress: bool,
}
