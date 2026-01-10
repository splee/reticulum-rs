//! Blackhole management for blocking specific identities.
//!
//! The blackhole system allows blocking specific identities from
//! interacting with the transport layer.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::error::RnsError;

/// Check interval for blackhole file changes
pub const BLACKHOLE_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Blackhole entry for a single identity
#[derive(Debug, Clone)]
pub struct BlackholeEntry {
    /// Identity hash that is blackholed
    pub identity_hash: AddressHash,
    /// When the entry was added
    pub added_at: Instant,
    /// Optional expiry time
    pub expires_at: Option<Instant>,
    /// Reason for blackholing (optional)
    pub reason: Option<String>,
}

impl BlackholeEntry {
    /// Create a new permanent blackhole entry
    pub fn new(identity_hash: AddressHash) -> Self {
        Self {
            identity_hash,
            added_at: Instant::now(),
            expires_at: None,
            reason: None,
        }
    }

    /// Create a new temporary blackhole entry
    pub fn with_expiry(identity_hash: AddressHash, duration: Duration) -> Self {
        Self {
            identity_hash,
            added_at: Instant::now(),
            expires_at: Some(Instant::now() + duration),
            reason: None,
        }
    }

    /// Add a reason to the entry
    pub fn with_reason(mut self, reason: String) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Check if entry has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Instant::now() > expires_at
        } else {
            false
        }
    }
}

/// Blackhole manager for managing blocked identities
#[derive(Debug)]
pub struct BlackholeManager {
    /// Map of identity hash -> blackhole entry
    entries: RwLock<HashMap<AddressHash, BlackholeEntry>>,
    /// Path to blackhole file (if persistence enabled)
    file_path: Option<String>,
    /// Last time the file was checked for changes
    last_checked: RwLock<Instant>,
    /// Last modification time of the file
    last_modified: RwLock<Option<std::time::SystemTime>>,
}

impl BlackholeManager {
    /// Create a new blackhole manager without persistence
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            file_path: None,
            last_checked: RwLock::new(Instant::now()),
            last_modified: RwLock::new(None),
        }
    }

    /// Create a new blackhole manager with persistence
    pub fn with_file(file_path: &str) -> Self {
        let manager = Self {
            entries: RwLock::new(HashMap::new()),
            file_path: Some(file_path.to_string()),
            last_checked: RwLock::new(Instant::now()),
            last_modified: RwLock::new(None),
        };

        // Try to load existing entries
        let _ = manager.reload();

        manager
    }

    /// Add an identity to the blackhole
    pub fn add(&self, identity_hash: AddressHash) {
        let entry = BlackholeEntry::new(identity_hash.clone());
        self.entries.write().unwrap().insert(identity_hash, entry);
    }

    /// Add an identity to the blackhole with expiry
    pub fn add_temporary(&self, identity_hash: AddressHash, duration: Duration) {
        let entry = BlackholeEntry::with_expiry(identity_hash.clone(), duration);
        self.entries.write().unwrap().insert(identity_hash, entry);
    }

    /// Remove an identity from the blackhole
    pub fn remove(&self, identity_hash: &AddressHash) -> Option<BlackholeEntry> {
        self.entries.write().unwrap().remove(identity_hash)
    }

    /// Check if an identity is blackholed
    pub fn is_blackholed(&self, identity_hash: &AddressHash) -> bool {
        let entries = self.entries.read().unwrap();
        if let Some(entry) = entries.get(identity_hash) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Get a blackhole entry
    pub fn get(&self, identity_hash: &AddressHash) -> Option<BlackholeEntry> {
        let entries = self.entries.read().unwrap();
        entries.get(identity_hash).cloned()
    }

    /// Clean up expired entries
    pub fn cleanup(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.retain(|_, entry| !entry.is_expired());
    }

    /// Check for file changes and reload if needed
    pub fn check_and_reload(&self) -> Result<bool, RnsError> {
        let should_check = {
            let last_checked = self.last_checked.read().unwrap();
            last_checked.elapsed() > BLACKHOLE_CHECK_INTERVAL
        };

        if !should_check {
            return Ok(false);
        }

        *self.last_checked.write().unwrap() = Instant::now();

        if let Some(ref path) = self.file_path {
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(modified) = metadata.modified() {
                    let last_modified = self.last_modified.read().unwrap().clone();
                    if last_modified.map(|m| modified != m).unwrap_or(true) {
                        *self.last_modified.write().unwrap() = Some(modified);
                        return self.reload().map(|_| true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Reload entries from file
    pub fn reload(&self) -> Result<(), RnsError> {
        let path = match &self.file_path {
            Some(p) => p,
            None => return Ok(()),
        };

        if !Path::new(path).exists() {
            return Ok(());
        }

        let file = File::open(path).map_err(|_| RnsError::InvalidArgument)?;
        let reader = BufReader::new(file);

        let mut new_entries = HashMap::new();

        for line in reader.lines() {
            if let Ok(line) = line {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Parse hex hash
                if let Ok(bytes) = hex_decode(line) {
                    if bytes.len() >= 16 {
                        let hash = AddressHash::new_from_slice(&bytes);
                        let entry = BlackholeEntry::new(hash.clone());
                        new_entries.insert(hash, entry);
                    }
                }
            }
        }

        *self.entries.write().unwrap() = new_entries;
        Ok(())
    }

    /// Save entries to file
    pub fn save(&self) -> Result<(), RnsError> {
        let path = match &self.file_path {
            Some(p) => p,
            None => return Err(RnsError::InvalidArgument),
        };

        let mut file = File::create(path).map_err(|_| RnsError::InvalidArgument)?;

        writeln!(file, "# Reticulum Blackhole File").map_err(|_| RnsError::InvalidArgument)?;
        writeln!(file, "# One identity hash per line (hex format)").map_err(|_| RnsError::InvalidArgument)?;
        writeln!(file).map_err(|_| RnsError::InvalidArgument)?;

        let entries = self.entries.read().unwrap();
        for (hash, _) in entries.iter() {
            let hex = hex_encode(hash.as_slice());
            writeln!(file, "{}", hex).map_err(|_| RnsError::InvalidArgument)?;
        }

        Ok(())
    }

    /// Get number of blackholed identities
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }

    /// List all blackholed identities
    pub fn list(&self) -> Vec<AddressHash> {
        self.entries
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }
}

impl Default for BlackholeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode bytes to hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }

    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blackhole_entry() {
        let hash = AddressHash::new_from_slice(&[1u8; 32]);
        let entry = BlackholeEntry::new(hash);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_blackhole_manager() {
        let manager = BlackholeManager::new();

        let hash = AddressHash::new_from_slice(&[1u8; 32]);
        manager.add(hash.clone());

        assert!(manager.is_blackholed(&hash));

        manager.remove(&hash);
        assert!(!manager.is_blackholed(&hash));
    }

    #[test]
    fn test_temporary_blackhole() {
        let manager = BlackholeManager::new();

        let hash = AddressHash::new_from_slice(&[1u8; 32]);
        manager.add_temporary(hash.clone(), Duration::from_secs(3600));

        assert!(manager.is_blackholed(&hash));
    }

    #[test]
    fn test_hex_encode_decode() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded, "0123456789abcdef");

        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }
}
