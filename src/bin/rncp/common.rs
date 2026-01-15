//! Common types and utilities shared across rncp modes.
//!
//! This module contains:
//! - Tracked resource types for managing in-flight transfers
//! - Path validation utilities for fetch server

use std::path::PathBuf;

use reticulum::destination::link::LinkId;
use reticulum::resource::Resource;

/// Tracked incoming resource with its link.
///
/// Used by listen mode to track resources being received from clients.
pub struct TrackedIncomingResource {
    /// The resource being received.
    pub resource: Resource,
    /// The link ID this resource is associated with.
    pub link_id: LinkId,
    /// Whether this resource has metadata (filename).
    pub has_metadata: bool,
}

/// Tracked outgoing resource for fetch server.
///
/// Used by listen mode to track resources being sent in response to fetch requests.
pub struct TrackedOutgoingResource {
    /// The resource being sent.
    pub resource: Resource,
    /// The link ID this resource is associated with.
    pub link_id: LinkId,
}

/// Validate a file path against the fetch jail.
///
/// Ensures the path is valid and (if a jail is specified) that the resolved
/// path is within the jail directory. Prevents path traversal attacks.
///
/// # Arguments
/// * `path_str` - The file path string to validate
/// * `jail` - Optional jail directory that the path must be within
///
/// # Returns
/// The validated and canonicalized path, or None if invalid
pub fn validate_fetch_path(path_str: &str, jail: Option<&PathBuf>) -> Option<PathBuf> {
    // Expand and canonicalize the path
    let expanded = if path_str.starts_with('~') {
        dirs::home_dir()
            .map(|h| h.join(&path_str[2..]))
            .unwrap_or_else(|| PathBuf::from(path_str))
    } else {
        PathBuf::from(path_str)
    };

    // If there's a jail, handle paths relative to it
    let file_path = if let Some(jail) = jail {
        // Strip jail prefix if present, then join with jail
        let stripped = if path_str.starts_with(jail.to_str().unwrap_or("")) {
            PathBuf::from(path_str.strip_prefix(jail.to_str().unwrap_or("")).unwrap_or(path_str).trim_start_matches('/'))
        } else {
            expanded.clone()
        };

        let joined = jail.join(&stripped);

        // Canonicalize to resolve symlinks
        match std::fs::canonicalize(&joined) {
            Ok(canonical) => {
                // Verify the resolved path is still within jail
                if canonical.starts_with(jail) {
                    canonical
                } else {
                    log::warn!(
                        "Fetch request for {} resolved to {} which is outside jail {}",
                        path_str,
                        canonical.display(),
                        jail.display()
                    );
                    return None;
                }
            }
            Err(e) => {
                log::debug!("Failed to canonicalize path {}: {}", joined.display(), e);
                return None;
            }
        }
    } else {
        // No jail, just use the expanded path
        match std::fs::canonicalize(&expanded) {
            Ok(canonical) => canonical,
            Err(_) => expanded,
        }
    };

    // Verify the file exists
    if !file_path.is_file() {
        log::debug!("Requested file does not exist: {}", file_path.display());
        return None;
    }

    Some(file_path)
}
