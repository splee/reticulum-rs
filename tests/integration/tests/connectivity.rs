//! Basic connectivity tests.
//!
//! These tests verify that the Python and Rust implementations can
//! start and establish basic network connectivity.

use std::time::Duration;

use crate::common::{IntegrationTestContext, TestConfig, TestOutput};

/// Test that the Python virtual environment is properly set up.
#[test]
fn test_python_venv_setup() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Verify venv is accessible
    let venv = ctx.venv();
    assert!(venv.python().exists(), "Python binary should exist in venv");
}

/// Test that Python rnsd can be invoked with --help.
#[test]
fn test_python_rnsd_help() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let mut cmd = ctx.venv().rnsd();
    cmd.arg("--help");

    let output = cmd.output().expect("Failed to run rnsd --help");
    assert!(output.status.success(), "rnsd --help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Reticulum") || stdout.contains("rnsd"),
        "Help output should mention Reticulum or rnsd"
    );
}

/// Test that a Python hub can start and listen on a TCP port.
#[test]
fn test_python_hub_starts() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    let port = hub.port();
    assert!(port > 0, "Hub should have a valid port");

    // The hub should be running
    // Note: We can't easily check if it's listening without a client,
    // but if spawn succeeded and we waited, it should be ready
    eprintln!("Python hub started on port {}", port);

    // Hub is automatically cleaned up when ctx is dropped
    drop(hub);
}

/// Test that configuration files are generated correctly.
#[test]
fn test_config_generation() {
    let python_config = TestConfig::python_hub().expect("Failed to create Python hub config");

    // Check that config file exists
    assert!(
        python_config.config_file().exists(),
        "Config file should exist"
    );

    // Read and verify content
    let content =
        std::fs::read_to_string(python_config.config_file()).expect("Failed to read config");

    assert!(
        content.contains("TCPServerInterface"),
        "Should have TCP server interface"
    );
    assert!(
        content.contains(&format!("listen_port = {}", python_config.tcp_port)),
        "Should have correct port"
    );

    // Test Rust node config
    let rust_config =
        TestConfig::rust_node(python_config.tcp_port, None).expect("Failed to create Rust config");

    let rust_content =
        std::fs::read_to_string(rust_config.config_file()).expect("Failed to read Rust config");

    assert!(
        rust_content.contains("TCPClientInterface"),
        "Should have TCP client interface"
    );
    assert!(
        rust_content.contains(&format!("target_port = {}", python_config.tcp_port)),
        "Should connect to hub port"
    );
}

/// Test that a Python link server helper can start and output its destination hash.
#[test]
fn test_python_link_server_outputs_destination() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start a Python hub first (must remain in scope to keep running)
    let _hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Run the Python link server helper
    let server = ctx
        .run_python_helper(
            "python_link_server.py",
            &[
                "-a",
                "test_app",
                "-A",
                "testaspect",
                "-t",
                "10", // 10 second timeout
                "-n",
                "0",  // Don't wait for links, just start
            ],
        )
        .expect("Failed to start Python link server");

    // Wait for destination hash to be output
    let line = server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(15))
        .expect("Should output destination hash");

    // Parse and verify
    let parsed = TestOutput::parse(&line);
    let dest_hash = parsed.destination_hash().expect("Should have destination hash");

    assert!(
        dest_hash.len() == 32,
        "Destination hash should be 32 hex chars (16 bytes), got {} chars",
        dest_hash.len()
    );

    assert!(
        dest_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "Destination hash should be hex"
    );

    eprintln!("Python link server destination: {}", dest_hash);
}

/// Test that KEY=VALUE output parsing works correctly.
#[test]
fn test_output_parsing() {
    let output = r#"
Some log message here
DESTINATION_HASH=abc123def456abc1
ANNOUNCE_SENT=1
Another log line
LINK_ACTIVATED=linkid123
ANNOUNCE_SENT=2
STATUS=RUNNING
"#;

    let parsed = TestOutput::parse(output);

    assert_eq!(
        parsed.destination_hash(),
        Some("abc123def456abc1"),
        "Should parse destination hash"
    );
    assert!(parsed.link_activated(), "Should detect link activation");
    assert_eq!(parsed.link_id(), Some("linkid123"), "Should get link ID");
    assert_eq!(parsed.status(), Some("RUNNING"), "Should get status");

    // Multiple ANNOUNCE_SENT values
    let announces = parsed.get_all("ANNOUNCE_SENT");
    assert_eq!(announces, &["1", "2"], "Should collect multiple values");
    assert_eq!(parsed.announce_count(), Some(2), "Should count announces");
}
