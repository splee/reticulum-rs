//! Integration tests for the rnstatus CLI binary.
//!
//! These tests verify the command-line interface behavior by invoking
//! the compiled binary and checking outputs and exit codes.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

// Counter for unique temp directory names
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Get the path to the rnstatus binary.
fn rnstatus_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rnstatus") {
        return PathBuf::from(path);
    }

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("rnstatus");
    path
}

/// Create a temporary directory for test files.
fn temp_dir() -> PathBuf {
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "rnstatus_test_{}_{}_{}",
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
    let output = Command::new(rnstatus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnstatus");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify key options are documented
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("-a, --all"));
    assert!(stdout.contains("-A, --announce-stats"));
    assert!(stdout.contains("-l, --link-stats"));
    assert!(stdout.contains("-t, --totals"));
    assert!(stdout.contains("-s, --sort"));
    assert!(stdout.contains("-j, --json"));
    assert!(stdout.contains("-m, --monitor"));
    assert!(stdout.contains("-d, --discovered"));
}

#[test]
fn test_version_flag() {
    let output = Command::new(rnstatus_binary())
        .arg("--version")
        .output()
        .expect("Failed to execute rnstatus");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnstatus"));
}

// =============================================================================
// Sort Field Tests
// =============================================================================

#[test]
fn test_sort_field_help() {
    let output = Command::new(rnstatus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnstatus");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Help should mention valid sort fields
    assert!(stdout.contains("rate"));
    assert!(stdout.contains("traffic"));
    assert!(stdout.contains("announces"));
}

// =============================================================================
// JSON Output Tests
// =============================================================================

#[test]
fn test_json_flag_in_help() {
    let output = Command::new(rnstatus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnstatus");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-j, --json"));
    assert!(stdout.contains("JSON"));
}

// =============================================================================
// Monitor Mode Tests
// =============================================================================

#[test]
fn test_monitor_flag_in_help() {
    let output = Command::new(rnstatus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnstatus");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-m, --monitor"));
}

#[test]
fn test_monitor_interval_flag_in_help() {
    let output = Command::new(rnstatus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnstatus");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-I, --monitor-interval"));
}

// =============================================================================
// Config Path Tests
// =============================================================================

#[test]
fn test_invalid_config_path() {
    let output = Command::new(rnstatus_binary())
        .args(["--config", "/nonexistent/config/path"])
        .output()
        .expect("Failed to execute rnstatus");

    // Should fail with exit code 1 (config error)
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn test_config_override_flag_in_help() {
    let output = Command::new(rnstatus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnstatus");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--config"));
}

// =============================================================================
// Verbosity Tests
// =============================================================================

#[test]
fn test_verbose_flag_in_help() {
    let output = Command::new(rnstatus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnstatus");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-v, --verbose"));
}

// =============================================================================
// Remote Query Tests
// =============================================================================

#[test]
fn test_remote_flag_in_help() {
    let output = Command::new(rnstatus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnstatus");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-R"));
}

#[test]
fn test_timeout_flag_in_help() {
    let output = Command::new(rnstatus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnstatus");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-w"));
    assert!(stdout.contains("SECONDS"));
}

// =============================================================================
// Discovered Interfaces Tests
// =============================================================================

#[test]
fn test_discovered_flag_in_help() {
    let output = Command::new(rnstatus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnstatus");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-d, --discovered"));
    assert!(stdout.contains("-D"));
}
