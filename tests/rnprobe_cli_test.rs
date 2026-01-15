//! Integration tests for the rnprobe CLI binary.
//!
//! These tests verify the command-line interface behavior by invoking
//! the compiled binary and checking outputs and exit codes.

use std::path::PathBuf;
use std::process::Command;

/// Get the path to the rnprobe binary.
fn rnprobe_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rnprobe") {
        return PathBuf::from(path);
    }

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("rnprobe");
    path
}

// =============================================================================
// Help and Version Tests
// =============================================================================

#[test]
fn test_help_flag() {
    let output = Command::new(rnprobe_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnprobe");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify key options are documented
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("-s, --size"));
    assert!(stdout.contains("-n, --probes"));
    assert!(stdout.contains("-t, --timeout"));
    assert!(stdout.contains("-w, --wait"));
    assert!(stdout.contains("-v, --verbose"));
}

#[test]
fn test_version_flag() {
    let output = Command::new(rnprobe_binary())
        .arg("--version")
        .output()
        .expect("Failed to execute rnprobe");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnprobe"));
}

// =============================================================================
// Parameter Tests
// =============================================================================

#[test]
fn test_size_parameter_in_help() {
    let output = Command::new(rnprobe_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnprobe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-s, --size"));
}

#[test]
fn test_probes_parameter_in_help() {
    let output = Command::new(rnprobe_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnprobe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-n, --probes"));
}

#[test]
fn test_timeout_parameter_in_help() {
    let output = Command::new(rnprobe_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnprobe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-t, --timeout"));
    assert!(stdout.contains("seconds"));
}

#[test]
fn test_wait_parameter_in_help() {
    let output = Command::new(rnprobe_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnprobe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-w, --wait"));
}

// =============================================================================
// Hash Validation Tests
// =============================================================================

#[test]
fn test_missing_destination() {
    let output = Command::new(rnprobe_binary())
        .output()
        .expect("Failed to execute rnprobe");

    // Should fail because destination is required
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // clap should show that destination is required
    assert!(stderr.contains("required") || stderr.contains("<DESTINATION>"));
}

#[test]
fn test_invalid_destination_hash_format() {
    // Invalid hash (too short)
    let output = Command::new(rnprobe_binary())
        .arg("abc123")
        .output()
        .expect("Failed to execute rnprobe");

    // Should fail with invalid hash
    assert!(!output.status.success());
}

// =============================================================================
// Config Tests
// =============================================================================

#[test]
fn test_invalid_config_path() {
    let output = Command::new(rnprobe_binary())
        .args(["--config", "/nonexistent/config/path", "abcdef0123456789abcdef0123456789"])
        .output()
        .expect("Failed to execute rnprobe");

    // Should fail with config error (exit 20)
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(20));
}

// =============================================================================
// Verbosity Tests
// =============================================================================

#[test]
fn test_verbose_flag_in_help() {
    let output = Command::new(rnprobe_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnprobe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-v, --verbose"));
}

// =============================================================================
// TCP Interface Tests
// =============================================================================

#[test]
fn test_tcp_interface_flags_in_help() {
    let output = Command::new(rnprobe_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnprobe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--tcp-client"));
    assert!(stdout.contains("--tcp-server"));
}
