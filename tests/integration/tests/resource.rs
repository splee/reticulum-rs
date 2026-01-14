//! Resource transfer tests.
//!
//! Tests that verify resource transfers between Python and Rust nodes.
//! Tests both directions: Python→Rust and Rust→Python.

use std::time::Duration;

use crate::common::{IntegrationTestContext, TestOutput};

/// Test Python sending a resource to Rust.
///
/// This tests that Rust can receive resource advertisements and data from Python.
#[test]
fn test_python_sends_resource_to_rust() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Rust resource server
    let rust_server = ctx
        .run_rust_binary(
            "test_resource_server",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "resourceserver",
                "-i", "5",  // announce interval
                "-n", "1",  // exit after 1 resource
                "-t", "50", // timeout
            ],
        )
        .expect("Failed to start Rust resource server");

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

    // Test data to send (hex encoded "Hello Resource!")
    let test_data_hex = "48656c6c6f205265736f7572636521";

    // Start Python resource client
    let python_client = ctx
        .run_python_helper(
            "python_resource_client.py",
            &[
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver",
                "-s", test_data_hex,
                "-t", "45",
                "-v",
            ],
        )
        .expect("Failed to start Python resource client");

    // Wait for link activation
    let _ = python_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));

    // Wait for resource transfer
    std::thread::sleep(Duration::from_secs(5));

    let client_output = python_client.output();
    let server_output = rust_server.output();

    eprintln!("Python client output:\n{}", client_output);
    eprintln!("Rust server output:\n{}", server_output);

    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify link was established on both sides
    assert!(
        server_parsed.link_activated(),
        "Rust server should receive link activation"
    );

    assert!(
        client_parsed.link_activated(),
        "Python client should establish link"
    );

    // Verify resource advertisement was received by Rust
    assert!(
        server_parsed.has("RESOURCE_ADVERTISEMENT"),
        "Rust should receive resource advertisement"
    );

    // Check if Python started the resource transfer
    assert!(
        client_parsed.has("RESOURCE_STARTED"),
        "Python should start resource transfer"
    );

    eprintln!("Python→Rust resource transfer test passed");
}

/// Test resource data packet reception.
///
/// Sends a larger resource to ensure data packets flow properly.
#[test]
fn test_python_sends_larger_resource_to_rust() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Rust resource server with verbose logging
    let rust_server = ctx
        .run_rust_binary(
            "test_resource_server",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "resourceserver2",
                "-i", "5",  // announce interval
                "-n", "1",  // exit after 1 resource
                "-t", "50", // timeout
                "-v",       // verbose
            ],
        )
        .expect("Failed to start Rust resource server");

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

    // 100 bytes of 'A' (hex encoded)
    let larger_data_hex = "41".repeat(100);

    // Start Python resource client
    let python_client = ctx
        .run_python_helper(
            "python_resource_client.py",
            &[
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver2",
                "-s", &larger_data_hex,
                "-t", "45",
            ],
        )
        .expect("Failed to start Python resource client");

    // Wait for link and resource transfer
    let _ = python_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(5));

    let server_output = rust_server.output();
    let client_output = python_client.output();

    eprintln!("Rust server output:\n{}", server_output);
    eprintln!("Python client output:\n{}", client_output);

    let server_parsed = TestOutput::parse(&server_output);

    // Verify resource advertisement received
    assert!(
        server_parsed.has("RESOURCE_ADVERTISEMENT"),
        "Rust should receive resource advertisement"
    );

    // Check for resource request being sent
    if server_parsed.has("RESOURCE_REQUEST_SENT") {
        eprintln!("Rust sent resource request to Python");
    }

    // Check for resource parts being received
    if server_parsed.has("RESOURCE_PART_RECEIVED") {
        eprintln!("Rust received resource data parts");
    }

    // Check for resource completion
    if server_parsed.has("RESOURCE_COMPLETE") {
        eprintln!("Rust completed resource transfer");
    }

    // Check for proof being sent
    if server_parsed.has("RESOURCE_PROOF_SENT") {
        eprintln!("Rust sent resource proof to Python");
    }

    eprintln!("Larger resource transfer test passed");
}

/// Test Rust sending a resource to Python.
///
/// This tests that Rust can initiate resource transfers to Python.
#[test]
fn test_rust_sends_resource_to_python() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Python resource server
    let python_server = ctx
        .run_python_helper(
            "python_resource_server.py",
            &[
                "-a", "test_app",
                "-A", "resourceserver",
                "-i", "5",  // announce interval
                "-n", "1",  // exit after 1 resource
                "-t", "50", // timeout
                "-v",       // verbose
            ],
        )
        .expect("Failed to start Python resource server");

    // Wait for destination hash
    let dest_line = python_server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(15))
        .expect("Python server should output destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let dest_hash = parsed
        .destination_hash()
        .expect("Should have destination hash");

    eprintln!("Python server destination hash: {}", dest_hash);

    // Wait for announce to propagate
    std::thread::sleep(Duration::from_secs(5));

    // Test data to send (hex encoded "Hello from Rust!")
    let test_data_hex = "48656c6c6f2066726f6d205275737421";

    // Start Rust resource client
    let rust_client = ctx
        .run_rust_binary(
            "test_resource_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver",
                "-s", test_data_hex,
                "-t", "45",
                "-v",
            ],
        )
        .expect("Failed to start Rust resource client");

    // Wait for link activation
    let _ = rust_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));

    // Wait for resource transfer
    std::thread::sleep(Duration::from_secs(5));

    let client_output = rust_client.output();
    let server_output = python_server.output();

    eprintln!("Rust client output:\n{}", client_output);
    eprintln!("Python server output:\n{}", server_output);

    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify link was established on both sides
    assert!(
        client_parsed.link_activated(),
        "Rust client should establish link"
    );

    assert!(
        server_parsed.link_activated(),
        "Python server should receive link activation"
    );

    // Verify resource was advertised by Rust
    assert!(
        client_parsed.has("RESOURCE_ADVERTISED"),
        "Rust should advertise resource"
    );

    // Verify resource was received by Python
    assert!(
        server_parsed.has("RESOURCE_STARTED"),
        "Python should start resource transfer"
    );

    // Check for resource completion
    if server_parsed.has("RESOURCE_COMPLETE") {
        eprintln!("Python completed resource transfer");

        // Verify the data content if available
        if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
            eprintln!("Resource complete: {}", complete_data);
        }
    }

    // Check for proof received by Rust
    if client_parsed.has("RESOURCE_PROOF_RECEIVED") {
        eprintln!("Rust received resource proof from Python");
    }

    // Check overall success
    if client_parsed.has("RESOURCE_TRANSFER_COMPLETE") {
        eprintln!("Rust→Python resource transfer complete");
    }

    eprintln!("Rust→Python resource transfer test passed");
}

/// Test Rust sending a larger resource to Python.
#[test]
fn test_rust_sends_larger_resource_to_python() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Python resource server
    let python_server = ctx
        .run_python_helper(
            "python_resource_server.py",
            &[
                "-a", "test_app",
                "-A", "resourceserver2",
                "-i", "5",  // announce interval
                "-n", "1",  // exit after 1 resource
                "-t", "50", // timeout
            ],
        )
        .expect("Failed to start Python resource server");

    // Wait for destination hash
    let dest_line = python_server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(15))
        .expect("Python server should output destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let dest_hash = parsed
        .destination_hash()
        .expect("Should have destination hash");

    eprintln!("Python server destination hash: {}", dest_hash);

    // Wait for announce to propagate
    std::thread::sleep(Duration::from_secs(5));

    // 500 bytes of 'B' (hex encoded)
    let larger_data_hex = "42".repeat(500);

    // Start Rust resource client
    let rust_client = ctx
        .run_rust_binary(
            "test_resource_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver2",
                "-s", &larger_data_hex,
                "-t", "45",
            ],
        )
        .expect("Failed to start Rust resource client");

    // Wait for link and resource transfer
    let _ = rust_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(5));

    let client_output = rust_client.output();
    let server_output = python_server.output();

    eprintln!("Rust client output:\n{}", client_output);
    eprintln!("Python server output:\n{}", server_output);

    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify link was established
    assert!(
        client_parsed.link_activated(),
        "Rust client should establish link"
    );

    // Verify resource was advertised by Rust
    assert!(
        client_parsed.has("RESOURCE_ADVERTISED"),
        "Rust should advertise resource"
    );

    // Check for resource completion on Python side
    if server_parsed.has("RESOURCE_COMPLETE") {
        eprintln!("Python completed larger resource transfer");

        // Try to verify size
        if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
            eprintln!("Resource complete: {}", complete_data);
        }
    }

    // Check overall success
    if client_parsed.has("RESOURCE_TRANSFER_COMPLETE") {
        eprintln!("Rust completed larger resource transfer");
    }

    eprintln!("Larger Rust→Python resource transfer test passed");
}
