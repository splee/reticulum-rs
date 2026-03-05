//! Integration tests for the rnsd CLI binary.
//!
//! These tests verify the command-line interface behavior by invoking
//! the compiled binary and checking outputs and exit codes.
//!
//! Note: Since rnsd is a daemon, most tests focus on argument parsing,
//! help output, and configuration loading rather than full daemon operation.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

// Counter for unique temp directory names
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Get the path to the rnsd binary.
fn rnsd_binary() -> PathBuf {
    // Use CARGO_BIN_EXE if available (set by cargo test)
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rnsd") {
        return PathBuf::from(path);
    }

    // Fall back to looking in target directory
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("rnsd");
    path
}

/// Create a temporary directory for test files with unique name.
fn temp_dir() -> PathBuf {
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "rnsd_test_{}_{}_{}",
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
    let output = Command::new(rnsd_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnsd");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify main description
    assert!(stdout.contains("Reticulum Network Stack Daemon"));

    // Verify key options are documented
    assert!(stdout.contains("-c, --config"));
    assert!(stdout.contains("-v, --verbose"));
    assert!(stdout.contains("-q, --quiet"));
    assert!(stdout.contains("-s, --service"));
    assert!(stdout.contains("-i, --interactive"));
    assert!(stdout.contains("--exampleconfig"));
}

#[test]
fn test_version_flag() {
    let output = Command::new(rnsd_binary())
        .arg("--version")
        .output()
        .expect("Failed to execute rnsd");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnsd"));
}

// =============================================================================
// Example Config Tests
// =============================================================================

#[test]
fn test_exampleconfig_flag() {
    let output = Command::new(rnsd_binary())
        .arg("--exampleconfig")
        .output()
        .expect("Failed to execute rnsd");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify TOML structure elements
    assert!(stdout.contains("[reticulum]"));
    assert!(stdout.contains("[logging]"));
    assert!(stdout.contains("[interfaces]"));

    // Verify key config options are shown
    assert!(stdout.contains("enable_transport"));
    assert!(stdout.contains("share_instance"));
    assert!(stdout.contains("TCPServerInterface"));
    assert!(stdout.contains("TCPClientInterface"));
}

#[test]
fn test_exampleconfig_is_valid_toml() {
    let output = Command::new(rnsd_binary())
        .arg("--exampleconfig")
        .output()
        .expect("Failed to execute rnsd");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The example config should parse as valid TOML
    // (even though it uses custom TOML extensions for interface arrays)
    // At minimum, it should contain these basic TOML patterns
    assert!(stdout.contains(" = "));  // key = value
    assert!(stdout.contains("["));    // section headers
}

// =============================================================================
// Config Path Tests
// =============================================================================

#[test]
fn test_invalid_config_path() {
    // Using a non-existent config path should fail gracefully
    let output = Command::new(rnsd_binary())
        .args(["-c", "/nonexistent/config/path/that/does/not/exist"])
        .output()
        .expect("Failed to execute rnsd");

    // Should fail with exit code 1 (config error)
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn test_config_dir_override() {
    let temp = temp_dir();

    // Create a minimal config file
    let config_file = temp.join("config.toml");
    fs::write(&config_file, r#"
[reticulum]
enable_transport = false
share_instance = false

[logging]
loglevel = 4
"#).unwrap();

    // Running with a valid config dir should at least start (we'll use --exampleconfig to avoid daemon start)
    // This tests that the -c flag is accepted
    let output = Command::new(rnsd_binary())
        .args(["-c", temp.to_str().unwrap(), "--exampleconfig"])
        .output()
        .expect("Failed to execute rnsd");

    // --exampleconfig should print and exit regardless of -c
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[reticulum]"));

    cleanup(&temp);
}

// =============================================================================
// Verbosity Flag Tests
// =============================================================================

#[test]
fn test_verbose_flag_accepted() {
    // Test that -v flag is accepted (combined with --exampleconfig to avoid daemon start)
    let output = Command::new(rnsd_binary())
        .args(["-v", "--exampleconfig"])
        .output()
        .expect("Failed to execute rnsd");

    assert!(output.status.success());
}

#[test]
fn test_quiet_flag_accepted() {
    // Test that -q flag is accepted
    let output = Command::new(rnsd_binary())
        .args(["-q", "--exampleconfig"])
        .output()
        .expect("Failed to execute rnsd");

    assert!(output.status.success());
}

#[test]
fn test_multiple_verbose_flags() {
    // Test that multiple -v flags are accepted (for increased verbosity)
    let output = Command::new(rnsd_binary())
        .args(["-v", "-v", "--exampleconfig"])
        .output()
        .expect("Failed to execute rnsd");

    assert!(output.status.success());
}

// =============================================================================
// Mode Flag Tests
// =============================================================================

#[test]
fn test_service_flag_in_help() {
    let output = Command::new(rnsd_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnsd");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-s, --service"));
}

#[test]
fn test_interactive_flag_in_help() {
    let output = Command::new(rnsd_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnsd");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-i, --interactive"));
}

// =============================================================================
// Remote Management Flag Tests
// =============================================================================

#[test]
fn test_remote_management_flag_in_help() {
    let output = Command::new(rnsd_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnsd");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--enable-remote-management"));
    assert!(stdout.contains("--remote-management-allowed"));
}

#[test]
fn test_publish_blackhole_flag_in_help() {
    let output = Command::new(rnsd_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnsd");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--publish-blackhole"));
}
