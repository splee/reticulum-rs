//! Integration tests for the rnpath CLI binary.
//!
//! These tests verify the command-line interface behavior by invoking
//! the compiled binary and checking outputs and exit codes.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

// Counter for unique temp directory names
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Get the path to the rnpath binary.
fn rnpath_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rnpath") {
        return PathBuf::from(path);
    }

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("rnpath");
    path
}

/// Create a temporary directory for test files.
fn temp_dir() -> PathBuf {
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "rnpath_test_{}_{}_{}",
        std::process::id(),
        count,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Clean up a temporary directory.
fn cleanup(dir: &PathBuf) {
    fs::remove_dir_all(dir).ok();
}

// =============================================================================
// Help and Version Tests
// =============================================================================

#[test]
fn test_help_flag() {
    let output = Command::new(rnpath_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnpath");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify key options are documented
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("-t, --table"));
    assert!(stdout.contains("-r, --rates"));
    assert!(stdout.contains("-d, --drop"));
    assert!(stdout.contains("-D, --drop-announces"));
    assert!(stdout.contains("-b, --blackholed"));
    assert!(stdout.contains("-B, --blackhole"));
    assert!(stdout.contains("-U, --unblackhole"));
    assert!(stdout.contains("-j, --json"));
}

#[test]
fn test_version_flag() {
    let output = Command::new(rnpath_binary())
        .arg("--version")
        .output()
        .expect("Failed to execute rnpath");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnpath"));
}

// =============================================================================
// Path Table Tests
// =============================================================================

#[test]
fn test_table_flag_in_help() {
    let output = Command::new(rnpath_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnpath");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-t, --table"));
}

#[test]
fn test_max_hops_flag_in_help() {
    let output = Command::new(rnpath_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnpath");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-m, --max"));
    assert!(stdout.contains("HOPS"));
}

// =============================================================================
// Rate Table Tests
// =============================================================================

#[test]
fn test_rates_flag_in_help() {
    let output = Command::new(rnpath_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnpath");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-r, --rates"));
}

// =============================================================================
// Drop Operations Tests
// =============================================================================

#[test]
fn test_drop_flags_in_help() {
    let output = Command::new(rnpath_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnpath");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-d, --drop"));
    assert!(stdout.contains("-D, --drop-announces"));
    assert!(stdout.contains("-x, --drop-via"));
}

// =============================================================================
// Blackhole Tests
// =============================================================================

#[test]
fn test_blackhole_flags_in_help() {
    let output = Command::new(rnpath_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnpath");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-b, --blackholed"));
    assert!(stdout.contains("-B, --blackhole"));
    assert!(stdout.contains("-U, --unblackhole"));
    assert!(stdout.contains("--duration"));
    assert!(stdout.contains("--reason"));
}

// =============================================================================
// Output Format Tests
// =============================================================================

#[test]
fn test_json_flag_in_help() {
    let output = Command::new(rnpath_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnpath");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-j, --json"));
}

// =============================================================================
// Remote Management Tests
// =============================================================================

#[test]
fn test_remote_flag_in_help() {
    let output = Command::new(rnpath_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnpath");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-R"));
    assert!(stdout.contains("-i"));
    assert!(stdout.contains("-W"));
}

// =============================================================================
// Config Tests
// =============================================================================

#[test]
fn test_invalid_config_path() {
    let output = Command::new(rnpath_binary())
        .args(["--config", "/nonexistent/config/path", "-t"])
        .output()
        .expect("Failed to execute rnpath");

    // Should fail with a config error
    assert!(!output.status.success());
}

// =============================================================================
// Timeout Tests
// =============================================================================

#[test]
fn test_timeout_flag_in_help() {
    let output = Command::new(rnpath_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnpath");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-w"));
}
