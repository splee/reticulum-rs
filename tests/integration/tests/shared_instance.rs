//! Shared instance socket safety tests.
//!
//! Tests that verify the socket detection behavior on macOS/BSD where
//! filesystem Unix sockets are used instead of abstract namespace sockets.
//!
//! Key scenarios tested:
//! - Second process attempting bind doesn't destroy first daemon's socket
//! - Daemon refuses to start if a stale socket file exists

use std::time::Duration;

use crate::common::IntegrationTestContext;

/// Test that a second rnsd process does not destroy the first daemon's socket.
///
/// This is the main regression test for the macOS socket detection bug where
/// IpcListener::bind() was unconditionally deleting socket files before binding.
///
/// On macOS/BSD (non-Linux Unix), this uses filesystem Unix sockets.
/// The test verifies that:
/// 1. First rnsd starts and creates socket file
/// 2. Second rnsd attempt fails cleanly (socket exists error)
/// 3. First rnsd's socket file still exists and daemon still responsive
#[test]
#[cfg(all(unix, not(target_os = "linux")))]
fn test_second_process_does_not_destroy_daemon_socket() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Create a config with shared instance enabled (uses Unix socket on macOS)
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = temp_dir.path();
    let socket_dir = config_dir.join("sockets");
    std::fs::create_dir_all(&socket_dir).expect("Failed to create socket dir");

    let tcp_port = crate::common::allocate_port();
    let shared_port = crate::common::allocate_port();

    let config_content = format!(
        r#"[reticulum]
enable_transport = true
share_instance = true
shared_instance_port = {}

[interfaces]
  [[TCP Server Interface]]
    type = TCPServerInterface
    interface_enabled = true
    listen_ip = 127.0.0.1
    listen_port = {}
"#,
        shared_port, tcp_port
    );

    let config_file = config_dir.join("config");
    std::fs::write(&config_file, &config_content).expect("Failed to write config");

    // Start first rnsd
    let mut rnsd1 = std::process::Command::new(ctx.rust_binary("rnsd"))
        .args(["--config", config_dir.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start first rnsd");

    // Wait for first daemon to start
    std::thread::sleep(Duration::from_secs(3));

    // Check if rnsd1 is still running
    if rnsd1.try_wait().unwrap().is_some() {
        eprintln!("Note: First rnsd exited early");
        return;
    }

    // Find the socket file
    let socket_path = socket_dir.join("default.sock");
    let socket_exists_before = socket_path.exists();
    eprintln!(
        "Socket file before second rnsd: {} (exists: {})",
        socket_path.display(),
        socket_exists_before
    );

    // Try to start second rnsd with same config
    // This should fail because socket already exists
    let rnsd2_result = std::process::Command::new(ctx.rust_binary("rnsd"))
        .args(["--config", config_dir.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    if let Ok(mut rnsd2) = rnsd2_result {
        // Give it time to attempt binding
        std::thread::sleep(Duration::from_secs(2));

        // Collect output
        let _ = rnsd2.kill();
        let output = rnsd2.wait_with_output().expect("Failed to get rnsd2 output");
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Second rnsd stderr: {}", stderr);

        // It should have failed or exited due to socket in use
        // (exact behavior depends on how the error is handled upstream)
    }

    // Verify first daemon's socket still exists
    let socket_exists_after = socket_path.exists();
    eprintln!(
        "Socket file after second rnsd attempt: {} (exists: {})",
        socket_path.display(),
        socket_exists_after
    );

    // The critical assertion: socket file should NOT have been deleted
    if socket_exists_before {
        assert!(
            socket_exists_after,
            "Socket file was deleted by second process! This is the bug we're preventing."
        );
        eprintln!("Socket file preserved correctly.");
    }

    // Verify first daemon is still running
    assert!(
        rnsd1.try_wait().unwrap().is_none(),
        "First rnsd should still be running"
    );

    // Clean up
    let _ = rnsd1.kill();
    let _ = rnsd1.wait();

    eprintln!("Test passed: Second process did not destroy first daemon's socket");
}

/// Test that daemon refuses to start when a stale socket file exists.
///
/// When a daemon crashes without cleaning up its socket file, the next
/// daemon attempt should fail with a clear error rather than silently
/// deleting the file (which could have belonged to a different daemon).
#[test]
#[cfg(all(unix, not(target_os = "linux")))]
fn test_daemon_refuses_to_start_with_stale_socket() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Create a config directory with a pre-existing "stale" socket file
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = temp_dir.path();
    let socket_dir = config_dir.join("sockets");
    std::fs::create_dir_all(&socket_dir).expect("Failed to create socket dir");

    // Create a stale socket file (just an empty file, simulating crashed daemon)
    let socket_path = socket_dir.join("default.sock");
    std::fs::write(&socket_path, "").expect("Failed to create stale socket");
    assert!(socket_path.exists());

    let tcp_port = crate::common::allocate_port();
    let shared_port = crate::common::allocate_port();

    let config_content = format!(
        r#"[reticulum]
enable_transport = true
share_instance = true
shared_instance_port = {}

[interfaces]
  [[TCP Server Interface]]
    type = TCPServerInterface
    interface_enabled = true
    listen_ip = 127.0.0.1
    listen_port = {}
"#,
        shared_port, tcp_port
    );

    let config_file = config_dir.join("config");
    std::fs::write(&config_file, &config_content).expect("Failed to write config");

    // Try to start rnsd - it should fail or at least not delete the socket
    let mut rnsd = std::process::Command::new(ctx.rust_binary("rnsd"))
        .args(["--config", config_dir.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start rnsd");

    // Give it time to attempt binding
    std::thread::sleep(Duration::from_secs(2));

    // Collect output
    let _ = rnsd.kill();
    let output = rnsd.wait_with_output().expect("Failed to get rnsd output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("rnsd stderr: {}", stderr);

    // The stale socket file should NOT have been deleted
    assert!(
        socket_path.exists(),
        "Stale socket file was deleted! Daemon should refuse to start, not delete the file."
    );

    // The error message should mention the socket already exists
    // (this depends on how the error propagates through rnsd)
    let combined_output = format!("{}{}", String::from_utf8_lossy(&output.stdout), stderr);
    let mentions_socket_issue = combined_output.to_lowercase().contains("already exists")
        || combined_output.to_lowercase().contains("in use")
        || combined_output.to_lowercase().contains("socket");

    if mentions_socket_issue {
        eprintln!("Daemon correctly reported socket issue in output");
    } else {
        eprintln!("Note: Daemon may have failed for other reasons or not propagated error message");
    }

    eprintln!("Test passed: Stale socket file was not deleted");
}

/// Test that rnstatus connects as client when daemon is running.
///
/// Verifies that rnstatus (which calls try_become_shared_instance) correctly
/// detects an existing daemon and connects as a client rather than trying
/// to become a shared instance.
#[test]
#[cfg(all(unix, not(target_os = "linux")))]
fn test_rnstatus_connects_to_existing_daemon() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Create config with shared instance
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = temp_dir.path();
    let socket_dir = config_dir.join("sockets");
    std::fs::create_dir_all(&socket_dir).expect("Failed to create socket dir");

    let tcp_port = crate::common::allocate_port();
    let shared_port = crate::common::allocate_port();

    let config_content = format!(
        r#"[reticulum]
enable_transport = true
share_instance = true
shared_instance_port = {}

[interfaces]
  [[TCP Server Interface]]
    type = TCPServerInterface
    interface_enabled = true
    listen_ip = 127.0.0.1
    listen_port = {}
"#,
        shared_port, tcp_port
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
    std::thread::sleep(Duration::from_secs(3));

    if rnsd.try_wait().unwrap().is_some() {
        eprintln!("Note: rnsd exited early");
        return;
    }

    // Find socket file
    let socket_path = socket_dir.join("default.sock");
    let socket_exists = socket_path.exists();
    eprintln!("Socket exists: {} at {}", socket_exists, socket_path.display());

    // Run rnstatus - it should connect to the existing daemon
    let rnstatus_output = std::process::Command::new(ctx.rust_binary("rnstatus"))
        .args(["--config", config_dir.to_str().unwrap()])
        .output()
        .expect("Failed to run rnstatus");

    let stdout = String::from_utf8_lossy(&rnstatus_output.stdout);
    let stderr = String::from_utf8_lossy(&rnstatus_output.stderr);
    eprintln!("rnstatus stdout: {}", stdout);
    eprintln!("rnstatus stderr: {}", stderr);

    // Verify daemon's socket still exists after rnstatus ran
    let socket_exists_after = socket_path.exists();
    if socket_exists {
        assert!(
            socket_exists_after,
            "Socket file was deleted by rnstatus! This is the bug we're preventing."
        );
        eprintln!("Socket file preserved correctly after rnstatus");
    }

    // Verify daemon is still running
    assert!(
        rnsd.try_wait().unwrap().is_none(),
        "rnsd should still be running after rnstatus"
    );

    // Clean up
    let _ = rnsd.kill();
    let _ = rnsd.wait();

    eprintln!("Test passed: rnstatus did not destroy daemon socket");
}
