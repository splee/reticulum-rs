//! rncp file transfer utility tests.
//!
//! Tests that verify rncp functionality including:
//! - Identity persistence
//! - CLI argument compatibility
//! - File transfer between Python and Rust implementations with checksum verification

use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::common::{IntegrationTestContext, TestOutput};

/// Test that Rust rncp identity is persisted between runs.
#[test]
fn test_rncp_identity_persistence() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // First run - should create new identity
    let output1 = std::process::Command::new(ctx.rust_binary("rncp"))
        .args(["--print-identity"])
        .output()
        .expect("Failed to run rncp");

    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    let stderr1 = String::from_utf8_lossy(&output1.stderr);
    let combined1 = format!("{}{}", stdout1, stderr1);

    eprintln!("First run output: {}", combined1);

    // Extract hash from output (format: "Listening on <hash>" or just the hash)
    let first_hash = extract_destination_hash(&combined1);
    assert!(
        first_hash.is_some(),
        "First run should produce destination hash"
    );

    let first_hash = first_hash.unwrap();
    eprintln!("First hash: {}", first_hash);

    // Second run - should load same identity
    let output2 = std::process::Command::new(ctx.rust_binary("rncp"))
        .args(["--print-identity"])
        .output()
        .expect("Failed to run rncp second time");

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

/// Test that Rust rncp has all expected CLI arguments.
#[test]
fn test_rncp_cli_arguments() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let output = std::process::Command::new(ctx.rust_binary("rncp"))
        .args(["--help"])
        .output()
        .expect("Failed to run rncp --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let help_text = format!("{}{}", stdout, stderr);

    eprintln!("rncp help:\n{}", help_text);

    // Check for key flags that should be present (matching Python rncp)
    let expected_flags = [
        "--listen",
        "--fetch",
        "--save",
        "--overwrite",
        "--no-auth",
        "--print-identity",
        "--no-compress",
        "--allow-fetch",
        "--jail",
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

/// Test that Rust rncp version output works.
#[test]
fn test_rncp_version() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let output = std::process::Command::new(ctx.rust_binary("rncp"))
        .args(["--version"])
        .output()
        .expect("Failed to run rncp --version");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let version_text = format!("{}{}", stdout, stderr).to_lowercase();

    eprintln!("rncp version: {}", version_text);

    assert!(
        version_text.contains("rncp") || version_text.contains("reticulum"),
        "Version output should mention rncp or reticulum"
    );

    eprintln!("Version test passed");
}

/// Test that Rust rncp can start in listen mode.
#[test]
fn test_rncp_listen_mode() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub first
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start rncp in listen mode
    let rncp_output = ctx
        .run_rust_binary(
            "rncp",
            &[
                "--listen",
                "--no-auth",
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-b", "3",  // announce every 3 seconds
            ],
        )
        .expect("Failed to start rncp");

    // Wait for it to start listening
    let result = rncp_output.wait_for_output("listening on", Duration::from_secs(15));

    if let Ok(line) = result {
        eprintln!("rncp listen output: {}", line);
        assert!(
            line.to_lowercase().contains("listening"),
            "Should show listening status"
        );
        eprintln!("Listen mode test passed");
    } else {
        // Check output for any errors
        let output = rncp_output.output();
        eprintln!("rncp output:\n{}", output);

        // May fail if rncp binary doesn't exist or has different args
        if output.contains("error") || output.contains("Error") {
            eprintln!("Note: rncp may not be fully implemented yet");
        }

        assert!(
            output.to_lowercase().contains("listen") || output.contains("Listening"),
            "rncp should attempt to listen"
        );
    }
}

/// Test file transfer from Python to Rust with checksum verification.
///
/// This test:
/// 1. Starts Rust rncp in listen mode with a save directory
/// 2. Creates a test file with known content and calculates its SHA256
/// 3. Sends the file using Python rncp
/// 4. Verifies the received file exists and has matching checksum
#[test]
fn test_rncp_python_to_rust_with_checksum() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Create directories for sending and receiving
    let send_dir = tempfile::tempdir().expect("Failed to create send temp dir");
    let recv_dir = tempfile::tempdir().expect("Failed to create recv temp dir");

    // Create test file with known content
    let test_filename = "test_python_to_rust.txt";
    let test_content = format!(
        "Hello from Python rncp test!\nTimestamp: {}\nThis is a test file for checksum verification.",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let test_file_path = send_dir.path().join(test_filename);
    std::fs::write(&test_file_path, &test_content).expect("Failed to write test file");

    // Calculate expected SHA256
    let expected_checksum = calculate_sha256(test_content.as_bytes());
    eprintln!("Test file checksum: {}", expected_checksum);
    eprintln!("Test file size: {} bytes", test_content.len());

    // Start Rust rncp in listen mode
    let rust_rncp = ctx
        .run_rust_binary(
            "rncp",
            &[
                "--listen",
                "--no-auth",
                "--save", recv_dir.path().to_str().unwrap(),
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-b", "3",
            ],
        )
        .expect("Failed to start Rust rncp");

    // Wait for destination hash
    let listen_result = rust_rncp.wait_for_output("listening on", Duration::from_secs(15));

    if listen_result.is_err() {
        let output = rust_rncp.output();
        eprintln!("Rust rncp output:\n{}", output);
        panic!("Rust rncp failed to start listening");
    }

    let listen_line = listen_result.unwrap();
    let rust_hash = extract_destination_hash(&listen_line)
        .expect("Should extract destination hash from listen output");

    eprintln!("Rust rncp destination: {}", rust_hash);

    // Wait for announce to propagate
    std::thread::sleep(Duration::from_secs(5));

    // Set up Python config to use the hub
    let python_config_dir = tempfile::tempdir().expect("Failed to create python config dir");
    let python_config = format!(
        r#"[reticulum]
enable_transport = false
share_instance = false

[interfaces]
  [[TCP Client Interface]]
    type = TCPClientInterface
    interface_enabled = true
    target_host = 127.0.0.1
    target_port = {}
"#,
        hub.port()
    );
    std::fs::write(
        python_config_dir.path().join("config"),
        &python_config,
    )
    .expect("Failed to write Python config");

    // Send file using Python rncp
    // IMPORTANT: Use --config argument, not RNS_CONFIG_DIR env var
    // (Python RNS doesn't recognize the env var)
    let mut python_cmd = ctx.venv().python_command();
    python_cmd.args([
        "-m", "RNS.Utilities.rncp",
        "--config", python_config_dir.path().to_str().unwrap(),
        "-w", "30",  // path request timeout
        "-v",  // verbose for debugging
        test_file_path.to_str().unwrap(),
        &rust_hash,
    ]);

    eprintln!("Sending file with Python rncp...");
    let python_output = python_cmd.output().expect("Failed to run Python rncp");

    let stdout = String::from_utf8_lossy(&python_output.stdout);
    let stderr = String::from_utf8_lossy(&python_output.stderr);
    eprintln!("Python rncp stdout:\n{}", stdout);
    eprintln!("Python rncp stderr:\n{}", stderr);

    // Wait for transfer to complete
    std::thread::sleep(Duration::from_secs(10));

    // Check Rust rncp output
    let rust_output = rust_rncp.output();
    eprintln!("Rust rncp output:\n{}", rust_output);

    // Find received file in the save directory
    let received_files: Vec<_> = std::fs::read_dir(recv_dir.path())
        .expect("Failed to read recv directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();

    eprintln!("Files in recv directory: {:?}", received_files);

    assert!(
        !received_files.is_empty(),
        "Should have received at least one file. Rust output:\n{}",
        rust_output
    );

    // Find the test file (may have been renamed)
    let received_path = received_files
        .iter()
        .find(|f| f.file_name().to_string_lossy().contains("test_python_to_rust"))
        .map(|f| f.path())
        .unwrap_or_else(|| received_files[0].path());

    // Read and verify checksum
    let received_content = std::fs::read(&received_path).expect("Failed to read received file");
    let received_checksum = calculate_sha256(&received_content);

    eprintln!("Received file: {:?}", received_path);
    eprintln!("Received checksum: {}", received_checksum);
    eprintln!("Received size: {} bytes", received_content.len());

    assert_eq!(
        expected_checksum, received_checksum,
        "File checksums must match"
    );
    assert_eq!(
        test_content.len(),
        received_content.len(),
        "File sizes must match"
    );

    eprintln!("Python→Rust file transfer with checksum verification PASSED");
}

/// Test file transfer from Rust to Python with checksum verification.
///
/// This test:
/// 1. Starts Python rncp receiver in listen mode
/// 2. Creates a test file with known content and calculates its SHA256
/// 3. Sends the file using Rust rncp
/// 4. Verifies the received file via the Python helper's checksum output
#[test]
fn test_rncp_rust_to_python_with_checksum() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Create directory for receiving and sending
    let recv_dir = tempfile::tempdir().expect("Failed to create recv temp dir");
    let send_dir = tempfile::tempdir().expect("Failed to create send temp dir");

    // Create test file with known content
    let test_filename = "test_rust_to_python.txt";
    let test_content = format!(
        "Hello from Rust rncp test!\nTimestamp: {}\nThis is a test file for checksum verification.",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let test_file_path = send_dir.path().join(test_filename);
    std::fs::write(&test_file_path, &test_content).expect("Failed to write test file");

    // Calculate expected SHA256
    let expected_checksum = calculate_sha256(test_content.as_bytes());
    eprintln!("Test file checksum: {}", expected_checksum);
    eprintln!("Test file size: {} bytes", test_content.len());

    // Start Python rncp receiver using our helper
    let python_receiver = ctx
        .run_python_helper(
            "python_rncp_receiver.py",
            &[
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "--save-dir", recv_dir.path().to_str().unwrap(),
                "--timeout", "60",
                "--announce-interval", "3",
                "--no-auth",
                "-v",
            ],
        )
        .expect("Failed to start Python rncp receiver");

    // Wait for destination hash
    let dest_result = python_receiver.wait_for_output("DESTINATION_HASH=", Duration::from_secs(20));

    if dest_result.is_err() {
        let output = python_receiver.output();
        eprintln!("Python receiver output:\n{}", output);
        panic!("Python rncp receiver failed to start");
    }

    let dest_line = dest_result.unwrap();
    let parsed = TestOutput::parse(&dest_line);
    let python_hash = parsed
        .destination_hash()
        .expect("Should have destination hash");

    eprintln!("Python rncp destination: {}", python_hash);

    // Wait for STATUS=READY and announce propagation
    let _ = python_receiver.wait_for_output("STATUS=READY", Duration::from_secs(5));
    std::thread::sleep(Duration::from_secs(5));

    // Send file using Rust rncp
    let rust_sender = ctx
        .run_rust_binary(
            "rncp",
            &[
                test_file_path.to_str().unwrap(),
                &python_hash,
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-v",
            ],
        )
        .expect("Failed to start Rust rncp sender");

    // Wait for transfer to complete
    std::thread::sleep(Duration::from_secs(15));

    // Check outputs
    let rust_output = rust_sender.output();
    let python_output = python_receiver.output();

    eprintln!("Rust sender output:\n{}", rust_output);
    eprintln!("Python receiver output:\n{}", python_output);

    // Parse Python output for FILE_RECEIVED
    let python_parsed = TestOutput::parse(&python_output);

    if let Some(file_info) = python_parsed.get("FILE_RECEIVED") {
        // Format: filename:size:sha256
        let parts: Vec<&str> = file_info.split(':').collect();
        assert!(parts.len() >= 3, "FILE_RECEIVED should have filename:size:sha256 format");

        let received_size: usize = parts[1].parse().expect("Should parse size");
        let received_checksum = parts[2];

        eprintln!("Received file: {}", parts[0]);
        eprintln!("Received size: {} bytes", received_size);
        eprintln!("Received checksum: {}", received_checksum);

        assert_eq!(
            expected_checksum, received_checksum,
            "File checksums must match"
        );
        assert_eq!(
            test_content.len(), received_size,
            "File sizes must match"
        );

        eprintln!("Rust→Python file transfer with checksum verification PASSED");
    } else {
        // Fallback: check files directly in recv_dir
        let received_files: Vec<_> = std::fs::read_dir(recv_dir.path())
            .expect("Failed to read recv directory")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .collect();

        eprintln!("Files in recv directory: {:?}", received_files);

        assert!(
            !received_files.is_empty(),
            "Should have received at least one file. Python output:\n{}",
            python_output
        );

        // Verify first received file
        let received_path = &received_files[0].path();
        let received_content = std::fs::read(received_path).expect("Failed to read received file");
        let received_checksum = calculate_sha256(&received_content);

        assert_eq!(
            expected_checksum, received_checksum,
            "File checksums must match"
        );

        eprintln!("Rust→Python file transfer with checksum verification PASSED (via direct file check)");
    }
}

/// Test large file transfer with checksum verification.
///
/// Transfers a 100KB+ file to verify multi-part resource handling.
#[test]
fn test_rncp_large_file_transfer() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Create directories
    let send_dir = tempfile::tempdir().expect("Failed to create send temp dir");
    let recv_dir = tempfile::tempdir().expect("Failed to create recv temp dir");

    // Create large test file (100KB)
    let test_filename = "large_test_file.bin";
    let test_content: Vec<u8> = (0..102400_u32)
        .map(|i| ((i % 256) as u8))
        .collect();
    let test_file_path = send_dir.path().join(test_filename);
    std::fs::write(&test_file_path, &test_content).expect("Failed to write test file");

    // Calculate expected SHA256
    let expected_checksum = calculate_sha256(&test_content);
    eprintln!("Large file checksum: {}", expected_checksum);
    eprintln!("Large file size: {} bytes", test_content.len());

    // Start Rust rncp in listen mode
    let rust_rncp = ctx
        .run_rust_binary(
            "rncp",
            &[
                "--listen",
                "--no-auth",
                "--save", recv_dir.path().to_str().unwrap(),
                "--tcp-client", &format!("127.0.0.1:{}", hub.port()),
                "-b", "3",
            ],
        )
        .expect("Failed to start Rust rncp");

    // Wait for destination hash
    let listen_result = rust_rncp.wait_for_output("listening on", Duration::from_secs(15));

    if listen_result.is_err() {
        let output = rust_rncp.output();
        eprintln!("Rust rncp output:\n{}", output);
        panic!("Rust rncp failed to start listening");
    }

    let listen_line = listen_result.unwrap();
    let rust_hash = extract_destination_hash(&listen_line)
        .expect("Should extract destination hash");

    eprintln!("Rust rncp destination: {}", rust_hash);

    // Wait for announce propagation
    std::thread::sleep(Duration::from_secs(5));

    // Set up Python config
    let python_config_dir = tempfile::tempdir().expect("Failed to create python config dir");
    let python_config = format!(
        r#"[reticulum]
enable_transport = false
share_instance = false

[interfaces]
  [[TCP Client Interface]]
    type = TCPClientInterface
    interface_enabled = true
    target_host = 127.0.0.1
    target_port = {}
"#,
        hub.port()
    );
    std::fs::write(python_config_dir.path().join("config"), &python_config)
        .expect("Failed to write Python config");

    // Send file using Python rncp
    // IMPORTANT: Use --config argument, not RNS_CONFIG_DIR env var
    let mut python_cmd = ctx.venv().python_command();
    python_cmd.args([
        "-m", "RNS.Utilities.rncp",
        "--config", python_config_dir.path().to_str().unwrap(),
        "-w", "60",  // longer timeout for large file
        "-v",
        test_file_path.to_str().unwrap(),
        &rust_hash,
    ]);

    eprintln!("Sending large file with Python rncp...");
    let python_output = python_cmd.output().expect("Failed to run Python rncp");

    let stdout = String::from_utf8_lossy(&python_output.stdout);
    let stderr = String::from_utf8_lossy(&python_output.stderr);
    eprintln!("Python rncp output:\n{}{}", stdout, stderr);

    // Wait for transfer to complete (longer for large file)
    std::thread::sleep(Duration::from_secs(30));

    // Check Rust rncp output
    let rust_output = rust_rncp.output();
    eprintln!("Rust rncp output:\n{}", rust_output);

    // Find received file
    let received_files: Vec<_> = std::fs::read_dir(recv_dir.path())
        .expect("Failed to read recv directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();

    assert!(
        !received_files.is_empty(),
        "Should have received the large file"
    );

    // Verify checksum
    let received_path = &received_files[0].path();
    let received_content = std::fs::read(received_path).expect("Failed to read received file");
    let received_checksum = calculate_sha256(&received_content);

    eprintln!("Received file size: {} bytes", received_content.len());
    eprintln!("Received checksum: {}", received_checksum);

    assert_eq!(
        test_content.len(),
        received_content.len(),
        "File sizes must match"
    );
    assert_eq!(
        expected_checksum, received_checksum,
        "File checksums must match"
    );

    eprintln!("Large file transfer (100KB) with checksum verification PASSED");
}

/// Helper function to extract destination hash from rncp output.
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

/// Calculate SHA256 hash of data and return as hex string.
fn calculate_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}
