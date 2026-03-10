//! GROUP destination encryption interoperability tests.
//!
//! Tests that verify AES-256-CBC encryption/decryption compatibility
//! between Python and Rust implementations. Also tests key format
//! compatibility and address hash derivation.

use crate::common::IntegrationTestContext;

/// Fixed 64-byte key for reproducibility (128 hex chars)
const TEST_KEY: &str = "5ea11018b20f83455bf49ae8e2b7a1315ea11018b20f83455bf49ae8e2b7a1315ea11018b20f83455bf49ae8e2b7a1315ea11018b20f83455bf49ae8e2b7a131";

/// Second 64-byte key for multi-key testing
const TEST_KEY_2: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";

/// Test plaintext: "Hello, GROUP world!" in hex
const TEST_PLAINTEXT: &str = "48656c6c6f2c2047524f555020776f726c6421";

/// Run a command on the Python group crypto helper and return stdout.
fn run_python_command(ctx: &IntegrationTestContext, input: &str) -> String {
    let mut guard = ctx
        .spawn_child(
            ctx.venv()
                .python_command()
                .arg(ctx.helpers_dir().join("python_group_crypto.py"))
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped()),
        )
        .expect("Failed to spawn Python");
    {
        use std::io::Write;
        let stdin = guard.child_mut().stdin.as_mut().expect("Failed to get stdin");
        stdin.write_all(input.as_bytes()).expect("Failed to write to stdin");
    }
    let output = guard
        .take_child()
        .unwrap()
        .wait_with_output()
        .expect("Failed to get Python output");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("Python stdout: {}", stdout);
    eprintln!("Python stderr: {}", stderr);

    assert!(
        stdout.contains("STATUS=OK"),
        "Python command failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
    stdout
}

/// Run a command on the Rust group crypto binary and return stdout.
fn run_rust_command(ctx: &IntegrationTestContext, input: &str) -> String {
    let mut guard = ctx
        .spawn_child(
            std::process::Command::new(ctx.rust_binary("test_group_crypto"))
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped()),
        )
        .expect("Failed to spawn Rust");
    {
        use std::io::Write;
        let stdin = guard.child_mut().stdin.as_mut().expect("Failed to get stdin");
        stdin.write_all(input.as_bytes()).expect("Failed to write to stdin");
    }
    let output = guard
        .take_child()
        .unwrap()
        .wait_with_output()
        .expect("Failed to get Rust output");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("Rust stdout: {}", stdout);
    eprintln!("Rust stderr: {}", stderr);

    assert!(
        stdout.contains("STATUS=OK"),
        "Rust command failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
    stdout
}

/// Extract a value from output lines by prefix (e.g., "RESULT=").
fn extract_value<'a>(stdout: &'a str, prefix: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("Expected output line starting with '{}'", prefix))
        .trim_start_matches(prefix)
}

/// Test that Python can encrypt and Rust can decrypt.
#[test]
fn test_python_encrypts_rust_decrypts() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Python encrypt
    let python_input = format!("encrypt\n{}\n{}\n", TEST_KEY, TEST_PLAINTEXT);
    let python_stdout = run_python_command(&ctx, &python_input);
    let python_ciphertext = extract_value(&python_stdout, "RESULT=");

    // Rust decrypt
    let rust_input = format!("decrypt\n{}\n{}\n", TEST_KEY, python_ciphertext);
    let rust_stdout = run_rust_command(&ctx, &rust_input);
    let rust_decrypted = extract_value(&rust_stdout, "RESULT=");

    assert_eq!(
        rust_decrypted, TEST_PLAINTEXT,
        "Python→Rust: Decrypted data should match original plaintext"
    );
}

/// Test that Rust can encrypt and Python can decrypt.
#[test]
fn test_rust_encrypts_python_decrypts() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Rust encrypt
    let rust_input = format!("encrypt\n{}\n{}\n", TEST_KEY, TEST_PLAINTEXT);
    let rust_stdout = run_rust_command(&ctx, &rust_input);
    let rust_ciphertext = extract_value(&rust_stdout, "RESULT=");

    // Python decrypt
    let python_input = format!("decrypt\n{}\n{}\n", TEST_KEY, rust_ciphertext);
    let python_stdout = run_python_command(&ctx, &python_input);
    let python_decrypted = extract_value(&python_stdout, "RESULT=");

    assert_eq!(
        python_decrypted, TEST_PLAINTEXT,
        "Rust→Python: Decrypted data should match original plaintext"
    );
}

/// Test that both implementations split a 64-byte key into the same
/// signing (first 32 bytes) and encryption (last 32 bytes) halves.
#[test]
fn test_key_format_compatibility() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    for (label, key) in [("key1", TEST_KEY), ("key2", TEST_KEY_2)] {
        let input = format!("key-split\n{}\n", key);

        let python_stdout = run_python_command(&ctx, &input);
        let rust_stdout = run_rust_command(&ctx, &input);

        let py_signing = extract_value(&python_stdout, "SIGNING_KEY=");
        let py_encryption = extract_value(&python_stdout, "ENCRYPTION_KEY=");
        let rs_signing = extract_value(&rust_stdout, "SIGNING_KEY=");
        let rs_encryption = extract_value(&rust_stdout, "ENCRYPTION_KEY=");

        assert_eq!(
            py_signing, rs_signing,
            "{}: Signing key halves should match between Python and Rust",
            label
        );
        assert_eq!(
            py_encryption, rs_encryption,
            "{}: Encryption key halves should match between Python and Rust",
            label
        );

        // Verify the halves correspond to the correct portions of the full key
        assert_eq!(
            py_signing,
            &key[..64],
            "{}: Signing key should be first 32 bytes of full key",
            label
        );
        assert_eq!(
            py_encryption,
            &key[64..],
            "{}: Encryption key should be last 32 bytes of full key",
            label
        );
    }
}

/// Test that both implementations derive identical address hashes from
/// the same key + app_name + aspects inputs.
#[test]
fn test_address_hash_derivation() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Test with multiple key/name combinations
    let test_cases = [
        (TEST_KEY, "test_app", "group.test"),
        (TEST_KEY_2, "my_application", "messaging.v1"),
        (TEST_KEY, "reticulum", "transport.group"),
    ];

    for (key, app_name, aspects) in test_cases {
        let input = format!("address-hash\n{}\n{}\n{}\n", key, app_name, aspects);

        let python_stdout = run_python_command(&ctx, &input);
        let rust_stdout = run_rust_command(&ctx, &input);

        let py_hash = extract_value(&python_stdout, "ADDRESS_HASH=");
        let rs_hash = extract_value(&rust_stdout, "ADDRESS_HASH=");

        assert_eq!(
            py_hash, rs_hash,
            "Address hash should match for key={:.16}..., app_name={}, aspects={}",
            key, app_name, aspects
        );

        // Verify address hash is 16 bytes (32 hex chars)
        assert_eq!(
            rs_hash.len(),
            32,
            "Address hash should be 16 bytes (32 hex chars)"
        );
    }
}
