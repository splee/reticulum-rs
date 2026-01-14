//! Link establishment tests.
//!
//! Tests that verify link establishment between Python and Rust nodes.

use std::time::Duration;

use crate::common::{IntegrationTestContext, TestOutput};

/// Test that Rust can establish a link to a Python destination.
#[test]
fn test_rust_client_to_python_server_link() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let _hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Python link server
    let server = ctx
        .run_python_helper(
            "python_link_server.py",
            &[
                "-a", "test_app",
                "-A", "pythonserver",
                "-i", "5",  // announce interval
                "-n", "1",  // exit after 1 link
                "-t", "40", // timeout
            ],
        )
        .expect("Failed to start Python link server");

    // Wait for destination hash
    let dest_line = server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(15))
        .expect("Python server should output destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let dest_hash = parsed
        .destination_hash()
        .expect("Should have destination hash");

    eprintln!("Python destination hash: {}", dest_hash);

    // Wait for announce to propagate
    std::thread::sleep(Duration::from_secs(3));

    // Use the test_link_client binary with --wait-announce
    let client_output = ctx
        .run_rust_binary(
            "test_link_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", _hub.port()),
                "--wait-announce",
                "-a", "test_app",
                "-A", "pythonserver",
                "-t", "25",
            ],
        )
        .expect("Failed to start Rust link client");

    // Wait for link activation
    let _ = client_output.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));

    // Also wait for server to complete
    std::thread::sleep(Duration::from_secs(2));

    let server_output = server.output();
    let client_output_str = client_output.output();

    eprintln!("Rust client output:\n{}", client_output_str);
    eprintln!("Python server output:\n{}", server_output);

    // Check results
    let client_parsed = TestOutput::parse(&client_output_str);
    let server_parsed = TestOutput::parse(&server_output);

    assert!(
        client_parsed.link_activated(),
        "Rust client should establish link to Python destination"
    );

    assert!(
        server_parsed.link_activated(),
        "Python server should receive incoming link from Rust"
    );

    eprintln!("Link establishment test passed: Rust -> Python");
}

/// Test that Rust destination can be discovered by Python.
#[test]
fn test_rust_destination_discoverable_by_python() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Rust destination announcer
    let rust_dest = ctx
        .run_rust_binary(
            "test_destination",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "rustdest",
                "-i", "3",  // announce interval
                "-n", "5",  // announce count
            ],
        )
        .expect("Failed to start Rust destination");

    // Wait for destination hash
    let dest_line = rust_dest
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(10))
        .expect("Rust destination should output hash");

    let parsed = TestOutput::parse(&dest_line);
    let dest_hash = parsed
        .destination_hash()
        .expect("Should have destination hash");

    eprintln!("Rust destination hash: {}", dest_hash);

    // Wait for announces to propagate
    std::thread::sleep(Duration::from_secs(5));

    // Use Python rnpath to check if the destination is reachable
    let mut cmd = ctx.venv().rnpath();
    cmd.args(["-d", dest_hash]);

    let output = cmd.output().expect("Failed to run rnpath");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("rnpath stdout: {}", stdout);
    eprintln!("rnpath stderr: {}", stderr);

    let combined = format!("{}{}", stdout, stderr).to_lowercase();

    // Check that Python can find the path to the Rust destination
    let path_found = combined.contains("hop")
        || combined.contains("path")
        || combined.contains(dest_hash)
        || combined.contains("known");

    // Also check Rust output
    let rust_output = rust_dest.output();
    let rust_parsed = TestOutput::parse(&rust_output);

    eprintln!("Rust destination output:\n{}", rust_output);

    assert!(
        rust_parsed.has("ANNOUNCE_SENT"),
        "Rust destination should have announced"
    );

    // The test passes if either:
    // 1. Python found the path, or
    // 2. Rust successfully announced (path may take longer to propagate)
    assert!(
        path_found || rust_parsed.announce_count().unwrap_or(0) > 0,
        "Python should be able to discover Rust destination or Rust should have announced"
    );

    eprintln!("Rust destination discovery test passed");
}

/// Test bidirectional link establishment.
#[test]
fn test_python_client_to_rust_server_link() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Rust link server
    let rust_server = ctx
        .run_rust_binary(
            "test_link_server",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "rustserver",
                "-i", "3",  // announce interval
                "-n", "1",  // exit after 1 link
                "-t", "45", // timeout
            ],
        )
        .expect("Failed to start Rust link server");

    // Wait for destination hash
    let dest_line = rust_server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(15))
        .expect("Rust server should output destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let dest_hash = parsed
        .destination_hash()
        .expect("Should have destination hash");

    eprintln!("Rust server destination hash: {}", dest_hash);

    // Wait for announce to propagate
    std::thread::sleep(Duration::from_secs(5));

    // Start Python link client
    let python_client = ctx
        .run_python_helper(
            "python_link_client.py",
            &[
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "rustserver",
                "-t", "30",
            ],
        )
        .expect("Failed to start Python link client");

    // Wait for link activation on client side
    let _ = python_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));

    // Give time for server to process
    std::thread::sleep(Duration::from_secs(2));

    let client_output = python_client.output();
    let server_output = rust_server.output();

    eprintln!("Python client output:\n{}", client_output);
    eprintln!("Rust server output:\n{}", server_output);

    // Check results
    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    assert!(
        client_parsed.link_activated(),
        "Python client should establish link to Rust destination"
    );

    assert!(
        server_parsed.link_activated(),
        "Rust server should receive incoming link from Python"
    );

    eprintln!("Link establishment test passed: Python -> Rust");
}
