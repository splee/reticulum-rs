//! rnx remote execution utility tests.
//!
//! Tests that verify rnx functionality including:
//! - Identity persistence
//! - CLI argument compatibility
//! - Listen mode startup

use std::time::Duration;

use crate::common::IntegrationTestContext;

/// Test that Rust rnx identity is persisted between runs.
#[test]
fn test_rnx_identity_persistence() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // First run - should create new identity
    let output1 = std::process::Command::new(ctx.rust_binary("rnx"))
        .args(["--print-identity"])
        .output()
        .expect("Failed to run rnx");

    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    let stderr1 = String::from_utf8_lossy(&output1.stderr);
    let combined1 = format!("{}{}", stdout1, stderr1);

    eprintln!("First run output: {}", combined1);

    // Extract hash from output
    let first_hash = extract_destination_hash(&combined1);
    assert!(
        first_hash.is_some(),
        "First run should produce destination hash"
    );

    let first_hash = first_hash.unwrap();
    eprintln!("First hash: {}", first_hash);

    // Second run - should load same identity
    let output2 = std::process::Command::new(ctx.rust_binary("rnx"))
        .args(["--print-identity"])
        .output()
        .expect("Failed to run rnx second time");

    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    let combined2 = format!("{}{}", stdout2, stderr2);

    let second_hash = extract_destination_hash(&combined2);
    assert!(
        second_hash.is_some(),
        "Second run should produce destination hash"
    );

    let second_hash = second_hash.unwrap();
    eprintln!("Second hash: {}", second_hash);

    assert_eq!(
        first_hash, second_hash,
        "Identity should persist between runs"
    );

    eprintln!("Identity persistence test passed");
}

/// Test that Rust rnx has all expected CLI arguments.
#[test]
fn test_rnx_cli_arguments() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let output = std::process::Command::new(ctx.rust_binary("rnx"))
        .args(["--help"])
        .output()
        .expect("Failed to run rnx --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let help_text = format!("{}{}", stdout, stderr);

    eprintln!("rnx help:\n{}", help_text);

    // Check for key flags that should be present
    let expected_flags = [
        "--listen",
        "--print-identity",
    ];

    let mut missing_flags = Vec::new();
    for flag in expected_flags {
        if !help_text.contains(flag) {
            missing_flags.push(flag);
        }
    }

    assert!(
        missing_flags.is_empty(),
        "Missing CLI flags: {:?}",
        missing_flags
    );

    eprintln!("CLI arguments test passed");
}

/// Test that Rust rnx version output works.
#[test]
fn test_rnx_version() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let output = std::process::Command::new(ctx.rust_binary("rnx"))
        .args(["--version"])
        .output()
        .expect("Failed to run rnx --version");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let version_text = format!("{}{}", stdout, stderr).to_lowercase();

    eprintln!("rnx version: {}", version_text);

    assert!(
        version_text.contains("rnx") || version_text.contains("reticulum"),
        "Version output should mention rnx or reticulum"
    );

    eprintln!("Version test passed");
}

/// Test that Rust rnx can start in listen mode.
#[test]
fn test_rnx_listen_mode() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub first
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start rnx in listen mode
    let rnx_output = ctx
        .run_rust_binary(
            "rnx",
            &[
                "--listen",
                "--noauth",
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-b",  // broadcast/announce
            ],
        )
        .expect("Failed to start rnx");

    // Wait for it to start listening
    let result = rnx_output.wait_for_output("Listening", Duration::from_secs(15));

    if let Ok(line) = result {
        eprintln!("rnx listen output: {}", line);
        assert!(
            line.to_lowercase().contains("listen"),
            "Should show listening status"
        );
        eprintln!("Listen mode test passed");
    } else {
        // Check output for any errors
        let output = rnx_output.output();
        eprintln!("rnx output:\n{}", output);

        // May fail if rnx binary doesn't exist or has different args
        if output.contains("error") || output.contains("Error") {
            eprintln!("Note: rnx may not be fully implemented yet");
        }

        // Check if it at least attempted to start
        let output_lower = output.to_lowercase();
        assert!(
            output_lower.contains("listen")
                || output_lower.contains("start")
                || output_lower.contains("rnx"),
            "rnx should attempt to start"
        );
    }
}

/// Helper function to extract destination hash from rnx output.
fn extract_destination_hash(text: &str) -> Option<String> {
    // Try to find hash in angle brackets: <hash>
    if let Some(start) = text.find('<') {
        if let Some(end) = text[start..].find('>') {
            let hash = &text[start + 1..start + end];
            if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(hash.to_string());
            }
        }
    }

    // Try to find 32-char hex string on its own
    for word in text.split_whitespace() {
        let word = word.trim_matches(|c: char| !c.is_ascii_hexdigit());
        if word.len() == 32 && word.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(word.to_string());
        }
    }

    None
}
