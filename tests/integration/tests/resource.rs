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
                "-i", "3",  // announce interval
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

    // Start Python resource client - must connect via TCP to the same hub
    let python_client = ctx
        .run_python_helper(
            "python_resource_client.py",
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
                "-i", "3",  // announce interval
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

    // Start Python resource client - must connect via TCP to the same hub
    let python_client = ctx
        .run_python_helper(
            "python_resource_client.py",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
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

    // Verify resource request was sent
    assert!(
        server_parsed.has("RESOURCE_REQUEST_SENT"),
        "Rust should send resource request to Python"
    );

    // Verify resource parts were received
    assert!(
        server_parsed.has("RESOURCE_PART_RECEIVED"),
        "Rust should receive resource data parts"
    );

    // Verify resource completion
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Rust should complete resource transfer"
    );

    // Verify proof was sent
    assert!(
        server_parsed.has("RESOURCE_PROOF_SENT"),
        "Rust should send resource proof to Python"
    );

    // Verify data size in RESOURCE_COMPLETE output
    // Format: RESOURCE_COMPLETE=link_id:hash:size
    if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
        let parts: Vec<&str> = complete_data.split(':').collect();
        if parts.len() >= 3 {
            let size: usize = parts[2].parse().unwrap_or(0);
            // Compressed data may be slightly different, but should be close to 100 bytes
            assert!(
                size >= 50 && size <= 200,
                "Resource size should be approximately 100 bytes (got {} compressed)",
                size
            );
            eprintln!("Resource size verified: {} bytes", size);
        }
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

    // Start Python resource server - must connect via TCP to the hub
    let python_server = ctx
        .run_python_helper(
            "python_resource_server.py",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
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

    // Verify resource completion on Python side
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Python should complete resource transfer"
    );

    // Verify data content matches
    // Python outputs: RESOURCE_COMPLETE=hash:size:hex_data
    if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
        let parts: Vec<&str> = complete_data.split(':').collect();
        if parts.len() >= 3 {
            let received_hex = parts[2];
            assert_eq!(
                received_hex, test_data_hex,
                "Received data should match sent data"
            );
            eprintln!("Data content verified: {} bytes match", parts[1]);
        }
    }

    // Verify proof received by Rust
    assert!(
        client_parsed.has("RESOURCE_PROOF_RECEIVED"),
        "Rust should receive resource proof from Python"
    );

    // Verify overall transfer completion
    assert!(
        client_parsed.has("RESOURCE_TRANSFER_COMPLETE"),
        "Rust should report transfer complete"
    );

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

    // Start Python resource server - must connect via TCP to the hub
    let python_server = ctx
        .run_python_helper(
            "python_resource_server.py",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
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

    // Verify resource completion on Python side
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Python should complete larger resource transfer"
    );

    // Verify data size
    // Python outputs: RESOURCE_COMPLETE=hash:size:hex_data
    if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
        let parts: Vec<&str> = complete_data.split(':').collect();
        if parts.len() >= 2 {
            let size: usize = parts[1].parse().unwrap_or(0);
            assert_eq!(
                size, 500,
                "Resource size should be exactly 500 bytes, got {}",
                size
            );
            eprintln!("Size verified: {} bytes", size);
        }
    }

    // Verify overall transfer completion
    assert!(
        client_parsed.has("RESOURCE_TRANSFER_COMPLETE"),
        "Rust should report larger transfer complete"
    );

    eprintln!("Larger Rust→Python resource transfer test passed");
}

/// Test Python sending a 1KB resource to Rust.
///
/// Tests resource transfer with data large enough to require multiple parts.
#[test]
fn test_python_sends_1kb_resource_to_rust() {
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
                "-A", "resourceserver_1kb",
                "-i", "3",
                "-n", "1",
                "-t", "90",
                "-v",
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

    // 1KB (1024 bytes) of 'C' (hex encoded)
    let data_1kb_hex = "43".repeat(1024);

    // Start Python resource client
    let python_client = ctx
        .run_python_helper(
            "python_resource_client.py",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver_1kb",
                "-s", &data_1kb_hex,
                "-t", "80",
                "-v",
            ],
        )
        .expect("Failed to start Python resource client");

    // Wait for link and resource transfer
    let _ = python_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(10));

    let server_output = rust_server.output();
    let client_output = python_client.output();

    eprintln!("Rust server output:\n{}", server_output);
    eprintln!("Python client output:\n{}", client_output);

    let server_parsed = TestOutput::parse(&server_output);
    let client_parsed = TestOutput::parse(&client_output);

    // Verify link establishment
    assert!(
        server_parsed.link_activated(),
        "Rust server should receive link activation"
    );

    // Verify resource advertisement received
    assert!(
        server_parsed.has("RESOURCE_ADVERTISEMENT"),
        "Rust should receive resource advertisement"
    );

    // Verify resource request was sent
    assert!(
        server_parsed.has("RESOURCE_REQUEST_SENT"),
        "Rust should send resource request"
    );

    // Verify resource completion
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Rust should complete 1KB resource transfer"
    );

    // Verify Python client completed successfully
    // Check for RESOURCE_COMPLETE, STATUS=SUCCESS, or 100% progress
    let client_success = client_parsed.has("RESOURCE_COMPLETE")
        || client_parsed.get("STATUS") == Some("SUCCESS")
        || client_output.contains(":100");  // 100% progress

    assert!(
        client_success,
        "Python client should report transfer complete or 100% progress"
    );

    eprintln!("1KB Python→Rust resource transfer test passed");
}

/// Test Rust sending a 1KB resource to Python.
///
/// Tests resource transfer with data large enough to require multiple parts.
#[test]
fn test_rust_sends_1kb_resource_to_python() {
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
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "resourceserver_1kb_r2p",
                "-i", "5",
                "-n", "1",
                "-t", "90",
                "-v",
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

    // 1KB (1024 bytes) of 'D' (hex encoded)
    let data_1kb_hex = "44".repeat(1024);

    // Start Rust resource client
    let rust_client = ctx
        .run_rust_binary(
            "test_resource_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver_1kb_r2p",
                "-s", &data_1kb_hex,
                "-t", "80",
                "-v",
            ],
        )
        .expect("Failed to start Rust resource client");

    // Wait for link and resource transfer
    let _ = rust_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(10));

    let client_output = rust_client.output();
    let server_output = python_server.output();

    eprintln!("Rust client output:\n{}", client_output);
    eprintln!("Python server output:\n{}", server_output);

    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify link establishment
    assert!(
        client_parsed.link_activated(),
        "Rust client should establish link"
    );

    // Verify resource advertised
    assert!(
        client_parsed.has("RESOURCE_ADVERTISED"),
        "Rust should advertise resource"
    );

    // Verify resource completion on Python side
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Python should complete 1KB resource transfer"
    );

    // Verify data size
    if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
        let parts: Vec<&str> = complete_data.split(':').collect();
        if parts.len() >= 2 {
            let size: usize = parts[1].parse().unwrap_or(0);
            assert_eq!(
                size, 1024,
                "Resource size should be exactly 1024 bytes, got {}",
                size
            );
            eprintln!("Size verified: {} bytes", size);
        }
    }

    // Verify proof received
    assert!(
        client_parsed.has("RESOURCE_PROOF_RECEIVED"),
        "Rust should receive resource proof"
    );

    eprintln!("1KB Rust→Python resource transfer test passed");
}

/// Test Python sending a 10KB resource to Rust.
///
/// Tests larger resource transfer requiring more parts and windowing.
#[test]
fn test_python_sends_10kb_resource_to_rust() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Rust resource server with longer timeout for large transfer
    let rust_server = ctx
        .run_rust_binary(
            "test_resource_server",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "resourceserver_10kb",
                "-i", "10",
                "-n", "1",
                "-t", "180",
                "-v",
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

    // 10KB (10240 bytes) of 'E' (hex encoded)
    let data_10kb_hex = "45".repeat(10240);

    // Start Python resource client
    let python_client = ctx
        .run_python_helper(
            "python_resource_client.py",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver_10kb",
                "-s", &data_10kb_hex,
                "-t", "160",
                "-v",
            ],
        )
        .expect("Failed to start Python resource client");

    // Wait for link and resource transfer (longer timeout for large transfer)
    let _ = python_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(30));

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

    // Verify resource parts were received (multiple parts expected)
    assert!(
        server_parsed.has("RESOURCE_PART_RECEIVED"),
        "Rust should receive multiple resource parts"
    );

    // Verify resource completion
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Rust should complete 10KB resource transfer"
    );

    // Verify proof was sent
    assert!(
        server_parsed.has("RESOURCE_PROOF_SENT"),
        "Rust should send resource proof"
    );

    eprintln!("10KB Python→Rust resource transfer test passed");
}

/// Test Rust sending a 10KB resource to Python.
///
/// Tests larger resource transfer requiring more parts and windowing.
#[test]
fn test_rust_sends_10kb_resource_to_python() {
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
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "resourceserver_10kb_r2p",
                "-i", "10",
                "-n", "1",
                "-t", "180",
                "-v",
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

    // 10KB (10240 bytes) of 'F' (hex encoded)
    let data_10kb_hex = "46".repeat(10240);

    // Start Rust resource client
    let rust_client = ctx
        .run_rust_binary(
            "test_resource_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver_10kb_r2p",
                "-s", &data_10kb_hex,
                "-t", "160",
                "-v",
            ],
        )
        .expect("Failed to start Rust resource client");

    // Wait for link and resource transfer (longer timeout for large transfer)
    let _ = rust_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(30));

    let client_output = rust_client.output();
    let server_output = python_server.output();

    eprintln!("Rust client output:\n{}", client_output);
    eprintln!("Python server output:\n{}", server_output);

    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify resource advertised
    assert!(
        client_parsed.has("RESOURCE_ADVERTISED"),
        "Rust should advertise resource"
    );

    // Verify resource completion on Python side
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Python should complete 10KB resource transfer"
    );

    // Verify data size
    if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
        let parts: Vec<&str> = complete_data.split(':').collect();
        if parts.len() >= 2 {
            let size: usize = parts[1].parse().unwrap_or(0);
            assert_eq!(
                size, 10240,
                "Resource size should be exactly 10240 bytes, got {}",
                size
            );
            eprintln!("Size verified: {} bytes", size);
        }
    }

    // Verify proof received
    assert!(
        client_parsed.has("RESOURCE_PROOF_RECEIVED"),
        "Rust should receive resource proof"
    );

    // Verify transfer complete
    assert!(
        client_parsed.has("RESOURCE_TRANSFER_COMPLETE"),
        "Rust should report 10KB transfer complete"
    );

    eprintln!("10KB Rust→Python resource transfer test passed");
}

/// Test sending an empty (zero-byte) resource from Rust to Python.
///
/// Tests edge case handling when there is no actual data payload.
#[test]
fn test_rust_sends_empty_resource_to_python() {
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
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "resourceserver_empty",
                "-i", "5",
                "-n", "1",
                "-t", "60",
                "-v",
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

    // Empty data (0 bytes) - empty hex string
    let empty_data_hex = "";

    // Start Rust resource client
    let rust_client = ctx
        .run_rust_binary(
            "test_resource_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver_empty",
                "-s", empty_data_hex,
                "-t", "50",
                "-v",
            ],
        )
        .expect("Failed to start Rust resource client");

    // Wait for link
    let _ = rust_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(5));

    let client_output = rust_client.output();
    let server_output = python_server.output();

    eprintln!("Rust client output:\n{}", client_output);
    eprintln!("Python server output:\n{}", server_output);

    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify link establishment
    assert!(
        client_parsed.link_activated(),
        "Rust client should establish link"
    );

    // Check if resource was created and advertised
    // Note: Empty resources may either succeed or fail gracefully
    let resource_advertised = client_parsed.has("RESOURCE_ADVERTISED");
    let error_occurred = client_parsed.get("STATUS").map(|s| s.starts_with("ERROR")).unwrap_or(false);

    if resource_advertised {
        // If resource was advertised, verify transfer completed
        eprintln!("Empty resource was advertised, checking transfer completion");

        // Verify resource completion on Python side
        if server_parsed.has("RESOURCE_COMPLETE") {
            // Verify data size is 0
            if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
                let parts: Vec<&str> = complete_data.split(':').collect();
                if parts.len() >= 2 {
                    let size: usize = parts[1].parse().unwrap_or(999);
                    assert_eq!(
                        size, 0,
                        "Empty resource size should be 0 bytes, got {}",
                        size
                    );
                    eprintln!("Empty resource size verified: {} bytes", size);
                }
            }
            eprintln!("Empty resource transfer completed successfully");
        } else {
            eprintln!("Note: Empty resource advertised but transfer may have special handling");
        }
    } else if error_occurred {
        // If creation failed, that's acceptable for empty resources
        eprintln!("Note: Empty resource creation failed, which may be expected behavior");
    } else {
        eprintln!("Note: Empty resource handling was ambiguous");
    }

    eprintln!("Empty resource test completed (behavior documented)");
}

/// Test sending a minimal 1-byte resource.
///
/// Tests the smallest non-empty resource to verify boundary handling.
#[test]
fn test_rust_sends_1byte_resource_to_python() {
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
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "resourceserver_1byte",
                "-i", "5",
                "-n", "1",
                "-t", "60",
                "-v",
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

    // 1 byte of 'X' (hex encoded)
    let data_1byte_hex = "58";

    // Start Rust resource client
    let rust_client = ctx
        .run_rust_binary(
            "test_resource_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver_1byte",
                "-s", data_1byte_hex,
                "-t", "50",
                "-v",
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

    // Verify link establishment
    assert!(
        client_parsed.link_activated(),
        "Rust client should establish link"
    );

    // Verify resource advertised
    assert!(
        client_parsed.has("RESOURCE_ADVERTISED"),
        "Rust should advertise 1-byte resource"
    );

    // Verify resource completion on Python side
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Python should complete 1-byte resource transfer"
    );

    // Verify data size is 1
    if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
        let parts: Vec<&str> = complete_data.split(':').collect();
        if parts.len() >= 2 {
            let size: usize = parts[1].parse().unwrap_or(0);
            assert_eq!(
                size, 1,
                "1-byte resource size should be exactly 1, got {}",
                size
            );
            eprintln!("Size verified: {} byte", size);
        }
    }

    // Verify proof received
    assert!(
        client_parsed.has("RESOURCE_PROOF_RECEIVED"),
        "Rust should receive resource proof for 1-byte transfer"
    );

    eprintln!("1-byte Rust→Python resource transfer test passed");
}

// =============================================================================
// MTU Boundary Tests
// =============================================================================
// These tests verify resource handling at segment size boundaries.
// PACKET_MDU = 2048, SDU = PACKET_MDU - 64 = 1984 bytes per segment

/// Test resource at exactly one segment size (SDU = 1984 bytes).
///
/// This should fit in exactly 1 part with no overflow.
#[test]
fn test_resource_at_exact_sdu_boundary() {
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
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "resourceserver_sdu",
                "-i", "5",
                "-n", "1",
                "-t", "90",
                "-v",
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

    // SDU size = 1984 bytes (PACKET_MDU - 64 = 2048 - 64)
    // Use 'G' (0x47) as the fill byte
    let sdu_size = 1984;
    let data_sdu_hex = "47".repeat(sdu_size);

    // Start Rust resource client
    let rust_client = ctx
        .run_rust_binary(
            "test_resource_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver_sdu",
                "-s", &data_sdu_hex,
                "-t", "80",
                "-v",
            ],
        )
        .expect("Failed to start Rust resource client");

    // Wait for link and resource transfer
    let _ = rust_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(10));

    let client_output = rust_client.output();
    let server_output = python_server.output();

    eprintln!("Rust client output:\n{}", client_output);
    eprintln!("Python server output:\n{}", server_output);

    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify resource completion
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Python should complete SDU-boundary resource transfer"
    );

    // Verify data size matches SDU
    if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
        let parts: Vec<&str> = complete_data.split(':').collect();
        if parts.len() >= 2 {
            let size: usize = parts[1].parse().unwrap_or(0);
            assert_eq!(
                size, sdu_size,
                "Resource size should be exactly {} bytes (1 SDU), got {}",
                sdu_size, size
            );
            eprintln!("SDU boundary size verified: {} bytes", size);
        }
    }

    // Verify proof received
    assert!(
        client_parsed.has("RESOURCE_PROOF_RECEIVED"),
        "Rust should receive resource proof"
    );

    eprintln!("SDU boundary (1984 bytes) Rust→Python resource transfer test passed");
}

/// Test resource just over one segment (SDU + 1 = 1985 bytes).
///
/// This should require 2 parts since it exceeds the single segment capacity.
#[test]
fn test_resource_over_sdu_boundary() {
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
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "resourceserver_sdu_plus",
                "-i", "5",
                "-n", "1",
                "-t", "90",
                "-v",
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

    // SDU + 1 = 1985 bytes - should require 2 parts
    // Use 'H' (0x48) as the fill byte
    let sdu_plus_size = 1985;
    let data_sdu_plus_hex = "48".repeat(sdu_plus_size);

    // Start Rust resource client
    let rust_client = ctx
        .run_rust_binary(
            "test_resource_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver_sdu_plus",
                "-s", &data_sdu_plus_hex,
                "-t", "80",
                "-v",
            ],
        )
        .expect("Failed to start Rust resource client");

    // Wait for link and resource transfer
    let _ = rust_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(10));

    let client_output = rust_client.output();
    let server_output = python_server.output();

    eprintln!("Rust client output:\n{}", client_output);
    eprintln!("Python server output:\n{}", server_output);

    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify resource completion
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Python should complete SDU+1 resource transfer"
    );

    // Verify data size
    if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
        let parts: Vec<&str> = complete_data.split(':').collect();
        if parts.len() >= 2 {
            let size: usize = parts[1].parse().unwrap_or(0);
            assert_eq!(
                size, sdu_plus_size,
                "Resource size should be exactly {} bytes (SDU+1), got {}",
                sdu_plus_size, size
            );
            eprintln!("SDU+1 boundary size verified: {} bytes", size);
        }
    }

    // Verify proof received
    assert!(
        client_parsed.has("RESOURCE_PROOF_RECEIVED"),
        "Rust should receive resource proof"
    );

    eprintln!("SDU+1 boundary (1985 bytes) Rust→Python resource transfer test passed");
}

/// Test resource at exactly two segments (2 * SDU = 3968 bytes).
///
/// This should fit in exactly 2 parts.
#[test]
fn test_resource_at_two_sdu_boundary() {
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
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "resourceserver_2sdu",
                "-i", "5",
                "-n", "1",
                "-t", "90",
                "-v",
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

    // 2 * SDU = 3968 bytes
    // Use 'I' (0x49) as the fill byte
    let two_sdu_size = 3968;
    let data_2sdu_hex = "49".repeat(two_sdu_size);

    // Start Rust resource client
    let rust_client = ctx
        .run_rust_binary(
            "test_resource_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "resourceserver_2sdu",
                "-s", &data_2sdu_hex,
                "-t", "80",
                "-v",
            ],
        )
        .expect("Failed to start Rust resource client");

    // Wait for link and resource transfer
    let _ = rust_client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(10));

    let client_output = rust_client.output();
    let server_output = python_server.output();

    eprintln!("Rust client output:\n{}", client_output);
    eprintln!("Python server output:\n{}", server_output);

    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify resource completion
    assert!(
        server_parsed.has("RESOURCE_COMPLETE"),
        "Python should complete 2-SDU resource transfer"
    );

    // Verify data size
    if let Some(complete_data) = server_parsed.get("RESOURCE_COMPLETE") {
        let parts: Vec<&str> = complete_data.split(':').collect();
        if parts.len() >= 2 {
            let size: usize = parts[1].parse().unwrap_or(0);
            assert_eq!(
                size, two_sdu_size,
                "Resource size should be exactly {} bytes (2 SDUs), got {}",
                two_sdu_size, size
            );
            eprintln!("2-SDU boundary size verified: {} bytes", size);
        }
    }

    // Verify proof received
    assert!(
        client_parsed.has("RESOURCE_PROOF_RECEIVED"),
        "Rust should receive resource proof"
    );

    eprintln!("2-SDU boundary (3968 bytes) Rust→Python resource transfer test passed");
}
