//! Link data exchange tests.
//!
//! Tests that verify data can be sent over links between Python and Rust.

use std::time::Duration;

use crate::common::{IntegrationTestContext, TestOutput};

/// Test that Rust client can send data to Python server over a link.
#[test]
fn test_rust_sends_data_to_python() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Python link server (infinite links, timeout-based exit)
    // Must connect via TCP to the same hub as the Rust client
    let server = ctx
        .run_python_helper(
            "python_link_server.py",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "dataserver",
                "-n", "0",  // infinite links
                "-t", "30", // timeout
                "-i", "5",  // announce interval
            ],
        )
        .expect("Failed to start Python link server");

    // Wait for destination hash
    let dest_line = server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(10))
        .expect("Python server should output destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let dest_hash = parsed
        .destination_hash()
        .expect("Should have destination hash");

    eprintln!("Python destination hash: {}", dest_hash);

    // Wait for announce to propagate
    std::thread::sleep(Duration::from_secs(3));

    // Test data to send (hex encoded "Hello from Rust!")
    let test_data_hex = "48656c6c6f2066726f6d205275737421";

    // Start Rust link client with data to send
    let client = ctx
        .run_rust_binary(
            "test_link_client",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "--destination", dest_hash,
                "--send-data", test_data_hex,
                "-t", "20",
            ],
        )
        .expect("Failed to start Rust link client");

    // Wait for link activation and data sent
    let _ = client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(20));

    // Give time for data to be sent and received
    std::thread::sleep(Duration::from_secs(3));

    let client_output = client.output();
    let server_output = server.output();

    eprintln!("Rust client output:\n{}", client_output);
    eprintln!("Python server output:\n{}", server_output);

    // Parse outputs
    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify link was established
    assert!(
        client_parsed.link_activated(),
        "Rust client should establish link"
    );

    // Verify data was sent
    assert!(
        client_parsed.has("DATA_SENT"),
        "Rust client should report data sent"
    );

    // Verify Python received the data
    assert!(
        server_parsed.has("DATA_RECEIVED"),
        "Python server should receive data"
    );

    // Check if received data matches (format: DATA_RECEIVED=link_id:size:hex_data)
    if let Some(data_received) = server_parsed.get("DATA_RECEIVED") {
        let parts: Vec<&str> = data_received.split(':').collect();
        if parts.len() >= 3 {
            let received_hex = parts[2];
            assert_eq!(
                received_hex, test_data_hex,
                "Received data should match sent data"
            );
            eprintln!("Data verified: sent {} == received {}", test_data_hex, received_hex);
        }
    }

    eprintln!("Rust -> Python data exchange test passed");
}

/// Test that Python client can send data to Rust server over a link.
#[test]
#[ignore = "flaky: link establishment times out under announce rate limiting"]
fn test_python_sends_data_to_rust() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Rust link server
    let server = ctx
        .run_rust_binary(
            "test_link_server",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-a", "test_app",
                "-A", "rustdataserver",
                "-n", "0",  // infinite links
                "-t", "45", // timeout
                "-i", "5",  // announce interval
            ],
        )
        .expect("Failed to start Rust link server");

    // Wait for destination hash
    let dest_line = server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(15))
        .expect("Rust server should output destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let dest_hash = parsed
        .destination_hash()
        .expect("Should have destination hash");

    eprintln!("Rust server destination hash: {}", dest_hash);

    // Wait for announce to propagate
    std::thread::sleep(Duration::from_secs(5));

    // Test data to send (hex encoded "Hello from Python!")
    let test_data_hex = "48656c6c6f2066726f6d20507974686f6e21";

    // Start Python link client with data to send
    // Must connect via TCP to the same hub as the Rust server
    let client = ctx
        .run_python_helper(
            "python_link_client.py",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-d", dest_hash,
                "-a", "test_app",
                "-A", "rustdataserver",
                "-s", test_data_hex,
                "-t", "30",
                "-v",
            ],
        )
        .expect("Failed to start Python link client");

    // Wait for link activation
    let _ = client.wait_for_output("LINK_ACTIVATED=", Duration::from_secs(25));

    // Give time for data exchange
    std::thread::sleep(Duration::from_secs(3));

    let client_output = client.output();
    let server_output = server.output();

    eprintln!("Python client output:\n{}", client_output);
    eprintln!("Rust server output:\n{}", server_output);

    // Parse outputs
    let client_parsed = TestOutput::parse(&client_output);
    let server_parsed = TestOutput::parse(&server_output);

    // Verify link was established
    assert!(
        client_parsed.link_activated(),
        "Python client should establish link"
    );

    // Verify data was sent
    assert!(
        client_parsed.has("DATA_SENT"),
        "Python client should report data sent"
    );

    // Verify Rust received the data
    assert!(
        server_parsed.has("DATA_RECEIVED"),
        "Rust server should receive data"
    );

    // Check if received data matches
    if let Some(data_received) = server_parsed.get("DATA_RECEIVED") {
        let parts: Vec<&str> = data_received.split(':').collect();
        if parts.len() >= 3 {
            let received_hex = parts[2];
            assert_eq!(
                received_hex, test_data_hex,
                "Received data should match sent data"
            );
            eprintln!("Data verified: sent {} == received {}", test_data_hex, received_hex);
        }
    }

    eprintln!("Python -> Rust data exchange test passed");
}
