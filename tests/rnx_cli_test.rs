//! Integration tests for the rnx CLI binary.
//!
//! These tests verify the command-line interface behavior by invoking
//! the compiled binary and checking outputs and exit codes.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

// Counter for unique temp directory names
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Get the path to the rnx binary.
fn rnx_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rnx") {
        return PathBuf::from(path);
    }

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("rnx");
    path
}

/// Create a temporary directory for test files.
fn temp_dir() -> PathBuf {
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "rnx_test_{}_{}_{}",
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
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify key options are documented
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("-l, --listen"));
    assert!(stdout.contains("-p, --print-identity"));
    assert!(stdout.contains("-x, --interactive"));
    assert!(stdout.contains("-n, --noauth"));
    assert!(stdout.contains("-a"));
    assert!(stdout.contains("-w"));
}

#[test]
fn test_version_flag() {
    let output = Command::new(rnx_binary())
        .arg("--version")
        .output()
        .expect("Failed to execute rnx");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnx"));
}

// =============================================================================
// Mode Flag Tests
// =============================================================================

#[test]
fn test_listen_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-l, --listen"));
}

#[test]
fn test_interactive_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-x, --interactive"));
}

// =============================================================================
// Identity Tests
// =============================================================================

#[test]
fn test_print_identity_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-p, --print-identity"));
}

#[test]
fn test_identity_file_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-i"));
}

// =============================================================================
// Auth Flag Tests
// =============================================================================

#[test]
fn test_noauth_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-n, --noauth"));
}

#[test]
fn test_noid_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-N, --noid"));
}

#[test]
fn test_allowed_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-a"));
}

// =============================================================================
// Timeout Tests
// =============================================================================

#[test]
fn test_timeout_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-w"));
    assert!(stdout.contains("seconds"));
}

#[test]
fn test_result_timeout_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-W"));
}

// =============================================================================
// Config Tests
// =============================================================================

#[test]
fn test_config_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--config"));
}

// =============================================================================
// Verbosity Tests
// =============================================================================

#[test]
fn test_verbose_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-v, --verbose"));
}

#[test]
fn test_quiet_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-q, --quiet"));
}

// =============================================================================
// Output Options Tests
// =============================================================================

#[test]
fn test_detailed_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-d, --detailed"));
}

#[test]
fn test_mirror_flag_in_help() {
    let output = Command::new(rnx_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-m"));
}
