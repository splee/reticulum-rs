//! Integration tests for the rncp CLI binary.
//!
//! These tests verify the command-line interface behavior by invoking
//! the compiled binary and checking outputs and exit codes.
//!
//! Note: rncp already has 41 unit tests in its modules. These tests
//! focus on CLI argument parsing and help output.

use std::path::PathBuf;
use std::process::Command;

/// Get the path to the rncp binary.
fn rncp_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rncp") {
        return PathBuf::from(path);
    }

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("rncp");
    path
}

// =============================================================================
// Help and Version Tests
// =============================================================================

#[test]
fn test_help_flag() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify key options are documented
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("-l, --listen"));
    assert!(stdout.contains("-f, --fetch"));
    assert!(stdout.contains("-p, --print-identity"));
    assert!(stdout.contains("-C, --no-compress"));
    assert!(stdout.contains("-n, --no-auth"));
    assert!(stdout.contains("-w"));
}

#[test]
fn test_version_flag() {
    let output = Command::new(rncp_binary())
        .arg("--version")
        .output()
        .expect("Failed to execute rncp");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rncp"));
}

// =============================================================================
// Mode Flag Tests
// =============================================================================

#[test]
fn test_listen_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-l, --listen"));
}

#[test]
fn test_fetch_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-f, --fetch"));
}

// =============================================================================
// Transfer Option Tests
// =============================================================================

#[test]
fn test_no_compress_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-C, --no-compress"));
}

#[test]
fn test_timeout_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-w"));
    assert!(stdout.contains("seconds"));
}

// =============================================================================
// Authentication Tests
// =============================================================================

#[test]
fn test_no_auth_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-n, --no-auth"));
}

#[test]
fn test_allowed_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-a"));
}

// =============================================================================
// Identity Tests
// =============================================================================

#[test]
fn test_print_identity_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-p, --print-identity"));
}

#[test]
fn test_identity_file_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-i"));
}

// =============================================================================
// Verbosity Tests
// =============================================================================

#[test]
fn test_verbose_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-v, --verbose"));
}

#[test]
fn test_quiet_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-q, --quiet"));
}

#[test]
fn test_silent_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-S, --silent"));
}

// =============================================================================
// Save/Overwrite Tests
// =============================================================================

#[test]
fn test_save_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-s, --save"));
}

#[test]
fn test_overwrite_flag_in_help() {
    let output = Command::new(rncp_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rncp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-O, --overwrite"));
}
