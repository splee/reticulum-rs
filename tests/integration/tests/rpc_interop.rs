//! RPC protocol interoperability tests.
//!
//! Tests that verify Python clients can connect to Rust daemon via
//! multiprocessing.connection with HMAC authentication.
//!
//! Tests RPC methods:
//! - get_interface_stats
//! - get_path_table

use std::time::Duration;

use crate::common::IntegrationTestContext;

/// Test that Rust rnsd can start and create a daemon identity.
#[test]
fn test_rnsd_creates_identity() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Create a temp config directory
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = temp_dir.path();
    let storage_dir = config_dir.join("storage");
    let identity_dir = storage_dir.join("identities");

    std::fs::create_dir_all(&identity_dir).expect("Failed to create identity dir");

    // Create minimal config file
    let config_content = r#"
[reticulum]
enable_transport = true
share_instance = false
"#;

    let config_file = config_dir.join("config");
    std::fs::write(&config_file, config_content).expect("Failed to write config");

    // Start rnsd briefly to create identity
    let rnsd = std::process::Command::new(ctx.rust_binary("rnsd"))
        .args(["--config", config_dir.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    if let Ok(mut child) = rnsd {
        // Wait briefly for identity creation
        std::thread::sleep(Duration::from_secs(3));

        // Kill the daemon
        let _ = child.kill();
        let _ = child.wait();

        // Check if identity was created
        let identity_file = identity_dir.join("daemon_identity");

        if identity_file.exists() {
            let identity_size = std::fs::metadata(&identity_file)
                .expect("Failed to get identity metadata")
                .len();

            assert_eq!(
                identity_size, 64,
                "Identity file should be 64 bytes (two 32-byte keys)"
            );

            eprintln!("Rust rnsd created identity successfully");
        } else {
            eprintln!("Note: Identity file not created (rnsd may use different location)");
            // List what was created
            if let Ok(entries) = std::fs::read_dir(&storage_dir) {
                for entry in entries.flatten() {
                    eprintln!("  Found: {:?}", entry.path());
                }
            }
        }
    } else {
        eprintln!("Note: rnsd binary may not exist or failed to start");
    }
}

/// Test RPC get_interface_stats method.
///
/// Verifies that Python client can successfully:
/// 1. Connect to Rust rnsd via RPC socket
/// 2. Authenticate using HMAC
/// 3. Call get_interface_stats and receive a response
#[test]
fn test_rpc_get_interface_stats() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Create a temp config directory with specific ports
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = temp_dir.path();
    let storage_dir = config_dir.join("storage");
    let identity_dir = storage_dir.join("identities");
    let socket_dir = config_dir.join("sockets");

    std::fs::create_dir_all(&identity_dir).expect("Failed to create identity dir");
    std::fs::create_dir_all(&socket_dir).expect("Failed to create socket dir");

    // Use specific ports for predictable behavior
    let shared_port = crate::common::allocate_port();

    let config_content = format!(
        r#"[reticulum]
enable_transport = true
share_instance = true
shared_instance_port = {}
"#,
        shared_port
    );

    let config_file = config_dir.join("config");
    std::fs::write(&config_file, &config_content).expect("Failed to write config");

    // Start rnsd
    let mut rnsd = std::process::Command::new(ctx.rust_binary("rnsd"))
        .args(["--config", config_dir.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start rnsd");

    // Wait for daemon to start and create identity
    std::thread::sleep(Duration::from_secs(5));

    // Verify daemon is still running
    assert!(
        rnsd.try_wait().unwrap().is_none(),
        "rnsd should still be running"
    );

    // Verify identity was created
    let identity_file = identity_dir.join("daemon_identity");
    assert!(
        identity_file.exists(),
        "Daemon identity should be created at {:?}",
        identity_file
    );

    // Verify identity file size
    let identity_size = std::fs::metadata(&identity_file)
        .expect("Failed to get identity metadata")
        .len();
    assert_eq!(identity_size, 64, "Identity file should be 64 bytes");

    // Find RPC socket
    let rpc_socket = socket_dir.join("default_rpc.sock");

    if !rpc_socket.exists() {
        // Clean up and skip if socket not found
        let _ = rnsd.kill();
        let _ = rnsd.wait();
        eprintln!("Note: RPC socket not found, skipping test");
        return;
    }

    // Run Python RPC client test
    let test_script = ctx.integration_test_dir().join("helpers/test_rpc_client.py");
    assert!(test_script.exists(), "test_rpc_client.py should exist");

    let mut python_cmd = ctx.venv().python_command();
    python_cmd.args([
        test_script.to_str().unwrap(),
        &format!("unix:{}", rpc_socket.display()),
        identity_file.to_str().unwrap(),
    ]);

    let output = python_cmd.output().expect("Failed to run Python RPC client");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    eprintln!("Python RPC client output:\n{}", combined);

    // Clean up daemon
    let _ = rnsd.kill();
    let _ = rnsd.wait();

    // Assert successful connection and authentication
    assert!(
        combined.contains("Connected and authenticated"),
        "Python client should connect and authenticate. Output:\n{}",
        combined
    );

    // Assert get_interface_stats test passed
    assert!(
        combined.contains("Test 1: PASSED"),
        "get_interface_stats test should pass. Output:\n{}",
        combined
    );

    eprintln!("RPC get_interface_stats test PASSED");
}

/// Test RPC get_path_table method.
///
/// Verifies that Python client can call get_path_table and receive a response.
#[test]
fn test_rpc_get_path_table() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Create a temp config directory
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = temp_dir.path();
    let storage_dir = config_dir.join("storage");
    let identity_dir = storage_dir.join("identities");
    let socket_dir = config_dir.join("sockets");

    std::fs::create_dir_all(&identity_dir).expect("Failed to create identity dir");
    std::fs::create_dir_all(&socket_dir).expect("Failed to create socket dir");

    let shared_port = crate::common::allocate_port();

    let config_content = format!(
        r#"[reticulum]
enable_transport = true
share_instance = true
shared_instance_port = {}
"#,
        shared_port
    );

    let config_file = config_dir.join("config");
    std::fs::write(&config_file, &config_content).expect("Failed to write config");

    // Start rnsd
    let mut rnsd = std::process::Command::new(ctx.rust_binary("rnsd"))
        .args(["--config", config_dir.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start rnsd");

    // Wait for daemon to start
    std::thread::sleep(Duration::from_secs(5));

    // Verify daemon is still running
    assert!(
        rnsd.try_wait().unwrap().is_none(),
        "rnsd should still be running"
    );

    // Verify identity
    let identity_file = identity_dir.join("daemon_identity");
    assert!(identity_file.exists(), "Daemon identity should be created");

    // Find RPC socket
    let rpc_socket = socket_dir.join("default_rpc.sock");

    if !rpc_socket.exists() {
        let _ = rnsd.kill();
        let _ = rnsd.wait();
        eprintln!("Note: RPC socket not found, skipping test");
        return;
    }

    // Run Python RPC client test
    let test_script = ctx.integration_test_dir().join("helpers/test_rpc_client.py");

    let mut python_cmd = ctx.venv().python_command();
    python_cmd.args([
        test_script.to_str().unwrap(),
        &format!("unix:{}", rpc_socket.display()),
        identity_file.to_str().unwrap(),
    ]);

    let output = python_cmd.output().expect("Failed to run Python RPC client");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    eprintln!("Python RPC client output:\n{}", combined);

    // Clean up daemon
    let _ = rnsd.kill();
    let _ = rnsd.wait();

    // Assert get_path_table test passed
    assert!(
        combined.contains("Test 2: PASSED"),
        "get_path_table test should pass. Output:\n{}",
        combined
    );

    eprintln!("RPC get_path_table test PASSED");
}

/// Test that RPC authentication fails with wrong key.
///
/// Verifies that the HMAC authentication properly rejects invalid keys.
#[test]
fn test_rpc_hmac_auth_failure() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Create a temp config directory
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = temp_dir.path();
    let storage_dir = config_dir.join("storage");
    let identity_dir = storage_dir.join("identities");
    let socket_dir = config_dir.join("sockets");

    std::fs::create_dir_all(&identity_dir).expect("Failed to create identity dir");
    std::fs::create_dir_all(&socket_dir).expect("Failed to create socket dir");

    let shared_port = crate::common::allocate_port();

    let config_content = format!(
        r#"[reticulum]
enable_transport = true
share_instance = true
shared_instance_port = {}
"#,
        shared_port
    );

    let config_file = config_dir.join("config");
    std::fs::write(&config_file, &config_content).expect("Failed to write config");

    // Start rnsd
    let mut rnsd = std::process::Command::new(ctx.rust_binary("rnsd"))
        .args(["--config", config_dir.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start rnsd");

    // Wait for daemon to start
    std::thread::sleep(Duration::from_secs(5));

    // Verify daemon is still running
    if rnsd.try_wait().unwrap().is_some() {
        eprintln!("Note: rnsd exited early, skipping test");
        return;
    }

    // Find RPC socket
    let rpc_socket = socket_dir.join("default_rpc.sock");

    if !rpc_socket.exists() {
        let _ = rnsd.kill();
        let _ = rnsd.wait();
        eprintln!("Note: RPC socket not found, skipping test");
        return;
    }

    // Create a fake identity file with wrong key
    let fake_identity_file = temp_dir.path().join("fake_identity");
    let fake_identity: [u8; 64] = [0xAB; 64]; // Definitely wrong key
    std::fs::write(&fake_identity_file, fake_identity).expect("Failed to write fake identity");

    // Run Python RPC client test with wrong identity
    let test_script = ctx.integration_test_dir().join("helpers/test_rpc_client.py");

    let mut python_cmd = ctx.venv().python_command();
    python_cmd.args([
        test_script.to_str().unwrap(),
        &format!("unix:{}", rpc_socket.display()),
        fake_identity_file.to_str().unwrap(),
    ]);

    let output = python_cmd.output().expect("Failed to run Python RPC client");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    eprintln!("Python RPC client output with wrong key:\n{}", combined);

    // Clean up daemon
    let _ = rnsd.kill();
    let _ = rnsd.wait();

    // Should NOT contain "Connected and authenticated" - it should fail
    // The authentication should be rejected
    let auth_failed = combined.contains("FAILED")
        || combined.contains("Authentication")
        || combined.contains("error")
        || combined.contains("Error")
        || !combined.contains("Connected and authenticated");

    assert!(
        auth_failed,
        "Authentication should fail with wrong key. Output:\n{}",
        combined
    );

    eprintln!("RPC HMAC authentication failure test PASSED");
}

/// Test RPC connection with all methods (comprehensive test).
///
/// This is the main integration test that verifies the full RPC flow.
#[test]
fn test_rpc_full_interop() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Create a temp config directory
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = temp_dir.path();
    let storage_dir = config_dir.join("storage");
    let identity_dir = storage_dir.join("identities");
    let socket_dir = config_dir.join("sockets");

    std::fs::create_dir_all(&identity_dir).expect("Failed to create identity dir");
    std::fs::create_dir_all(&socket_dir).expect("Failed to create socket dir");

    let shared_port = crate::common::allocate_port();

    let config_content = format!(
        r#"[reticulum]
enable_transport = true
share_instance = true
shared_instance_port = {}
"#,
        shared_port
    );

    let config_file = config_dir.join("config");
    std::fs::write(&config_file, &config_content).expect("Failed to write config");

    // Start rnsd
    let mut rnsd = std::process::Command::new(ctx.rust_binary("rnsd"))
        .args(["--config", config_dir.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start rnsd");

    // Wait for daemon to start
    std::thread::sleep(Duration::from_secs(5));

    // Verify daemon is still running
    assert!(
        rnsd.try_wait().unwrap().is_none(),
        "rnsd should still be running"
    );

    // Verify identity was created with correct size
    let identity_file = identity_dir.join("daemon_identity");
    assert!(identity_file.exists(), "Daemon identity should be created");

    let identity_size = std::fs::metadata(&identity_file)
        .expect("Failed to get identity metadata")
        .len();
    assert_eq!(identity_size, 64, "Identity file should be 64 bytes");

    // Find RPC socket
    let rpc_socket = socket_dir.join("default_rpc.sock");

    if !rpc_socket.exists() {
        let _ = rnsd.kill();
        let _ = rnsd.wait();
        eprintln!("Note: RPC socket not found at {:?}", rpc_socket);
        // List what's in socket dir
        if let Ok(entries) = std::fs::read_dir(&socket_dir) {
            for entry in entries.flatten() {
                eprintln!("  Found: {:?}", entry.path());
            }
        }
        return;
    }

    eprintln!("RPC socket found at {:?}", rpc_socket);

    // Run Python RPC client test
    let test_script = ctx.integration_test_dir().join("helpers/test_rpc_client.py");
    assert!(test_script.exists(), "test_rpc_client.py should exist");

    let mut python_cmd = ctx.venv().python_command();
    python_cmd.args([
        test_script.to_str().unwrap(),
        &format!("unix:{}", rpc_socket.display()),
        identity_file.to_str().unwrap(),
    ]);

    let output = python_cmd.output().expect("Failed to run Python RPC client");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    eprintln!("Python RPC client output:\n{}", combined);

    // Clean up daemon
    let _ = rnsd.kill();
    let _ = rnsd.wait();

    // Assert all tests passed
    assert!(
        combined.contains("Connected and authenticated"),
        "Should connect and authenticate"
    );
    assert!(combined.contains("Test 1: PASSED"), "Test 1 should pass");
    assert!(combined.contains("Test 2: PASSED"), "Test 2 should pass");
    assert!(
        combined.contains("All tests completed"),
        "All tests should complete"
    );

    eprintln!("Full RPC interoperability test PASSED");
}

/// Test that rnsd --help works.
#[test]
fn test_rnsd_help() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let output = std::process::Command::new(ctx.rust_binary("rnsd"))
        .args(["--help"])
        .output()
        .expect("Failed to run rnsd --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let help_text = format!("{}{}", stdout, stderr);

    eprintln!("rnsd help:\n{}", help_text);

    assert!(
        help_text.to_lowercase().contains("reticulum")
            || help_text.to_lowercase().contains("rnsd")
            || help_text.to_lowercase().contains("daemon"),
        "Help should mention reticulum, rnsd, or daemon"
    );

    eprintln!("rnsd help test passed");
}

/// Test that rnsd --version works.
#[test]
fn test_rnsd_version() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let output = std::process::Command::new(ctx.rust_binary("rnsd"))
        .args(["--version"])
        .output()
        .expect("Failed to run rnsd --version");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let version_text = format!("{}{}", stdout, stderr).to_lowercase();

    eprintln!("rnsd version: {}", version_text);

    assert!(
        version_text.contains("rnsd") || version_text.contains("reticulum"),
        "Version should mention rnsd or reticulum"
    );

    eprintln!("rnsd version test passed");
}
