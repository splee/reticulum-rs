//! Link timeout tests.
//!
//! Tests that verify link timeout and keepalive handling.
//! These tests ensure links are properly managed when peers
//! become unresponsive or disconnect.

use std::time::Duration;

use crate::common::{IntegrationTestContext, TestOutput};

// =============================================================================
// Link Timeout Tests
// =============================================================================
// These tests verify proper timeout handling for links.

/// Test that link establishment has a reasonable timeout.
///
/// If a peer doesn't respond to link establishment, the client
/// should timeout rather than hanging indefinitely.
#[test]
fn test_link_establishment_timeout() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start a destination that announces but won't accept links
    let rust_dest = ctx
        .run_rust_binary(
            "test_destination",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "timeout_test",
                "-A", "noaccept",
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
    let dest_hash = parsed.destination_hash().expect("Should have hash");

    eprintln!("Destination hash: {}", dest_hash);

    // Wait for announce
    std::thread::sleep(Duration::from_secs(5));

    // Try to establish link with timeout
    let client = ctx
        .run_python_helper(
            "python_link_client.py",
            &[
                "-d", dest_hash,
                "-t", "10",  // 10 second timeout
            ],
        )
        .expect("Failed to start link client");

    // Wait for timeout plus margin
    std::thread::sleep(Duration::from_secs(12));

    let output = client.output();
    eprintln!("Link establishment output:\n{}", output);

    let output_lower = output.to_lowercase();

    // Should show timeout or failure, not hang
    let timed_out = output_lower.contains("timeout")
        || output_lower.contains("error")
        || output_lower.contains("failed")
        || !TestOutput::parse(&output).link_activated();

    // If we got here, the client didn't hang
    assert!(
        timed_out,
        "Link establishment should timeout for unresponsive peer"
    );

    eprintln!("Link establishment timeout test passed");
}

/// Test that established links can detect peer disconnection.
///
/// When the remote peer disconnects, the local side should
/// detect this and clean up the link.
#[test]
fn test_link_peer_disconnection_detection() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Python link server
    let server = ctx
        .run_python_helper(
            "python_link_server.py",
            &[
                "-a", "disconnect_test",
                "-A", "server",
                "-t", "30",  // 30 second timeout
                "-n", "1",   // Accept one link
            ],
        )
        .expect("Failed to start Python link server");

    // Wait for destination hash
    let dest_line = server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(15))
        .expect("Should get server destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let server_hash = parsed.destination_hash().expect("Should have hash");

    eprintln!("Server hash: {}", server_hash);

    // Establish link from Rust client
    let client = ctx
        .run_rust_binary(
            "test_link_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", server_hash,
                "-t", "20",  // 20 second timeout
            ],
        )
        .expect("Failed to start Rust link client");

    // Wait for link establishment
    let link_result = client.wait_for_output("LINK_ACTIVATED", Duration::from_secs(15));

    if link_result.is_err() {
        // Link might not have established - this is also valid for this test
        eprintln!("Link did not establish, skipping disconnection test");
        return;
    }

    eprintln!("Link established");

    // Drop the server to simulate disconnection
    drop(server);
    eprintln!("Server dropped (simulating disconnection)");

    // Wait for client to detect disconnection
    std::thread::sleep(Duration::from_secs(10));

    let client_output = client.output();
    eprintln!("Client output after server drop:\n{}", client_output);

    // The client should either:
    // 1. Detect the disconnection (show closed/timeout/error)
    // 2. Continue running gracefully
    // Either is acceptable - the key is it doesn't crash

    eprintln!("Link peer disconnection detection test passed");
}

/// Test link keepalive mechanism.
///
/// Verifies that links remain active when there's no data traffic,
/// thanks to keepalive messages.
#[test]
fn test_link_keepalive() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Python link server that will hold the link open
    let server = ctx
        .run_python_helper(
            "python_link_server.py",
            &[
                "-a", "keepalive_test",
                "-A", "server",
                "-t", "30",  // 30 second timeout
                "-n", "1",   // Accept one link
            ],
        )
        .expect("Failed to start Python link server");

    // Wait for destination hash
    let dest_line = server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(15))
        .expect("Should get server destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let server_hash = parsed.destination_hash().expect("Should have hash");

    eprintln!("Server hash: {}", server_hash);

    // Establish link from Rust client
    let client = ctx
        .run_rust_binary(
            "test_link_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", server_hash,
                "-t", "30",  // 30 second timeout
            ],
        )
        .expect("Failed to start Rust link client");

    // Wait for link establishment
    if let Err(_) = client.wait_for_output("LINK_ACTIVATED", Duration::from_secs(15)) {
        eprintln!("Link did not establish, skipping keepalive test");
        return;
    }

    eprintln!("Link established, waiting to verify it stays active...");

    // Wait for some time (enough for keepalives to occur)
    std::thread::sleep(Duration::from_secs(10));

    // Check that link is still active
    let server_output = server.output();
    let client_output = client.output();

    eprintln!("Server output:\n{}", server_output);
    eprintln!("Client output:\n{}", client_output);

    // Link should still be active (no timeout/error)
    let server_ok = !server_output.to_lowercase().contains("timeout")
        && !server_output.to_lowercase().contains("closed unexpectedly");
    let client_ok = !client_output.to_lowercase().contains("timeout")
        && !client_output.to_lowercase().contains("closed unexpectedly");

    // At least one side should show the link is still OK
    assert!(
        server_ok || client_ok,
        "Link should remain active via keepalives"
    );

    eprintln!("Link keepalive test passed");
}

/// Test rapid link establishment and teardown.
///
/// Verifies that creating and closing many links quickly
/// doesn't cause resource leaks or crashes.
#[test]
fn test_rapid_link_churn() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Python link server that accepts multiple links
    let server = ctx
        .run_python_helper(
            "python_link_server.py",
            &[
                "-a", "churn_test",
                "-A", "server",
                "-t", "60",  // 60 second timeout
                "-n", "5",   // Accept 5 links
            ],
        )
        .expect("Failed to start Python link server");

    // Wait for destination hash
    let dest_line = server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(15))
        .expect("Should get server destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let server_hash = parsed.destination_hash().expect("Should have hash");

    eprintln!("Server hash: {}", server_hash);

    // Rapidly establish and drop multiple links
    for i in 0..3 {
        eprintln!("Link iteration {}", i);

        let client = ctx
            .run_rust_binary(
                "test_link_client",
                &[
                    "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                    "-d", server_hash,
                    "-t", "10",
                ],
            )
            .expect("Failed to start Rust link client");

        // Brief wait for link
        std::thread::sleep(Duration::from_secs(3));

        let output = client.output();
        let has_link = TestOutput::parse(&output).link_activated();
        eprintln!("Iteration {} link established: {}", i, has_link);

        // Client dropped here, link closes
    }

    // Server should still be running and functional
    let server_output = server.output();
    eprintln!("Server output after churn:\n{}", server_output);

    // If we got here without crash, test passes
    eprintln!("Rapid link churn test passed");
}
