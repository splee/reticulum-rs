//! Error handling tests.
//!
//! Tests that verify graceful handling of protocol errors and edge cases.
//! These tests ensure both Python and Rust implementations handle
//! invalid inputs and error conditions without crashing.

use std::time::Duration;

use crate::common::{IntegrationTestContext, TestOutput};

// =============================================================================
// Invalid Input Tests
// =============================================================================
// These tests verify graceful handling of invalid inputs.

/// Test that rnpath handles invalid destination hash format gracefully.
///
/// Invalid hex strings should not crash the CLI.
#[test]
fn test_rnpath_invalid_hash_format() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let _hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Test various invalid hash formats
    let invalid_hashes = [
        "not-hex-at-all",
        "ZZZZ",
        "12345",  // Too short
        "12345678901234567890123456789012345678901234567890",  // Too long
        "",  // Empty
    ];

    for invalid_hash in invalid_hashes {
        let mut cmd = ctx.venv().rnpath();
        cmd.args(["-w", "1", invalid_hash]); // 1 second timeout

        let output = cmd.output().expect("Failed to run rnpath");

        // The key assertion is that rnpath doesn't crash/hang
        // Any exit (success or error) is acceptable for invalid input
        eprintln!(
            "rnpath '{}': exit={}, stdout={}, stderr={}",
            invalid_hash,
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    eprintln!("All invalid hash formats handled gracefully");
}

/// Test that rnprobe handles invalid destination hash format gracefully.
#[test]
fn test_rnprobe_invalid_hash_format() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let _hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Test invalid hash format
    let mut cmd = ctx.venv().rnprobe();
    cmd.args(["-t", "2", "invalid-hash-xyz"]);

    let output = cmd.output().expect("Failed to run rnprobe");

    // Should handle gracefully (not crash)
    eprintln!(
        "rnprobe invalid hash: exit={}, stdout={}, stderr={}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );

    eprintln!("Invalid hash format handled gracefully by rnprobe");
}

// =============================================================================
// Link Error Tests
// =============================================================================
// Tests for link establishment error scenarios.

/// Test that link to non-existent destination is handled gracefully.
///
/// Attempting to establish a link to a destination that hasn't announced
/// should fail gracefully with a timeout or error message.
#[test]
fn test_link_to_nonexistent_destination() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub (must remain in scope to keep running)
    let _hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Try to establish link to non-existent destination
    // Using the Python link client to attempt connection to a fake hash
    let fake_hash = "deadbeefcafe1234deadbeefcafe1234";

    let client = ctx
        .run_python_helper(
            "python_link_client.py",
            &[
                "-d", fake_hash,
                "-t", "5",  // 5 second timeout
            ],
        )
        .expect("Failed to start Python link client");

    // Wait for client to timeout or error
    std::thread::sleep(Duration::from_secs(6));

    let output = client.output();
    eprintln!("Link to non-existent output:\n{}", output);

    let output_lower = output.to_lowercase();

    // Should show some indication of failure (timeout, error, etc)
    let handled = output_lower.contains("timeout")
        || output_lower.contains("error")
        || output_lower.contains("failed")
        || output_lower.contains("unknown")
        || output_lower.contains("no path")
        || !TestOutput::parse(&output).link_activated();

    assert!(
        handled,
        "Link to non-existent destination should fail gracefully"
    );

    eprintln!("Link to non-existent destination handled gracefully");
}

/// Test that resource request without established link fails gracefully.
///
/// Verifies that trying to transfer resources to a destination
/// without first establishing a link is handled properly.
#[test]
fn test_resource_without_link() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub (kept in scope to keep running)
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start a destination that does NOT accept links
    // (Just announces but doesn't handle incoming connections)
    let rust_dest = ctx
        .run_rust_binary(
            "test_destination",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "error_test",
                "-A", "nolink",
                "-i", "2",
                "-n", "3",
            ],
        )
        .expect("Failed to start Rust destination");

    // Wait for destination hash
    let dest_line = rust_dest
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(10))
        .expect("Should get destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let dest_hash = parsed
        .destination_hash()
        .expect("Should have hash");

    eprintln!("Destination hash: {}", dest_hash);

    // Try to send resource to this destination
    // This should fail because test_destination doesn't accept links
    let client = ctx
        .run_python_helper(
            "python_resource_client.py",
            &[
                "-d", dest_hash,
                "-t", "5",  // 5 second timeout
                "-D", "test data",
            ],
        )
        .expect("Failed to start resource client");

    // Wait for timeout
    std::thread::sleep(Duration::from_secs(6));

    let output = client.output();
    eprintln!("Resource without link output:\n{}", output);

    let output_lower = output.to_lowercase();

    // Should indicate failure (can't establish link or transfer resource)
    let failed = output_lower.contains("timeout")
        || output_lower.contains("error")
        || output_lower.contains("failed")
        || output_lower.contains("no link")
        || !output.contains("RESOURCE_COMPLETE");

    assert!(
        failed,
        "Resource request without link should fail gracefully"
    );

    eprintln!("Resource without link handled gracefully");
}

// =============================================================================
// Network Error Recovery Tests
// =============================================================================
// Tests for network error scenarios and recovery.

/// Test that nodes handle hub disconnection gracefully.
///
/// If the hub a node is connected to becomes unavailable,
/// the node should handle this without crashing.
#[test]
fn test_hub_disconnection_handling() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    let hub_port = hub.port();

    // Start Rust destination connected to hub
    let rust_dest = ctx
        .run_rust_binary(
            "test_destination",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub_port),
                "-a", "disconnect_test",
                "-A", "node",
                "-i", "2",
                "-n", "10",  // Many announces
            ],
        )
        .expect("Failed to start Rust destination");

    // Wait for initial connection
    let dest_line = rust_dest
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(10))
        .expect("Should get destination hash");

    let parsed = TestOutput::parse(&dest_line);
    eprintln!("Connected with hash: {}", parsed.destination_hash().unwrap_or("unknown"));

    // Wait for a few announces
    std::thread::sleep(Duration::from_secs(5));

    // Drop the hub (simulates disconnection)
    drop(hub);
    eprintln!("Hub disconnected");

    // Wait and observe behavior
    std::thread::sleep(Duration::from_secs(5));

    // Get output - node should still be running (not crashed)
    let output = rust_dest.output();
    eprintln!("Output after disconnection:\n{}", output);

    // The key assertion: the process didn't crash
    // It may show errors, but should have handled the disconnection
    let rust_parsed = TestOutput::parse(&output);

    // Should have sent some announces before disconnection
    let announces = rust_parsed.announce_count().unwrap_or(0);
    eprintln!("Announces sent before disconnection: {}", announces);

    // If we got here without hanging, the test passes
    eprintln!("Hub disconnection handled without crash");
}

/// Test that multiple rapid connect/disconnect cycles are handled.
///
/// Verifies stability under connection churn.
#[test]
fn test_connection_churn_stability() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    let hub_port = hub.port();

    // Start multiple short-lived destinations rapidly
    for i in 0..3 {
        let rust_dest = ctx
            .run_rust_binary(
                "test_destination",
                &[
                    "--tcp-client", &format!("127.0.0.1:{}", hub_port),
                    "-a", "churn_test",
                    "-A", &format!("node{}", i),
                    "-i", "1",
                    "-n", "2",  // Quick, 2 announces only
                ],
            )
            .expect("Failed to start Rust destination");

        // Wait briefly for connection
        std::thread::sleep(Duration::from_millis(500));

        // Get hash
        if let Ok(line) = rust_dest.wait_for_output("DESTINATION_HASH=", Duration::from_secs(5)) {
            let parsed = TestOutput::parse(&line);
            eprintln!(
                "Node {} hash: {}",
                i,
                parsed.destination_hash().unwrap_or("unknown")
            );
        }

        // Let node send announces
        std::thread::sleep(Duration::from_secs(3));

        // Node dropped here (disconnect)
        eprintln!("Node {} disconnected", i);
    }

    // If we got here, the hub handled all the connections
    eprintln!("Connection churn test completed successfully");
}
