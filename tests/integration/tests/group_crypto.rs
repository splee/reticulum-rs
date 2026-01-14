//! GROUP destination encryption interoperability tests.
//!
//! Tests that verify AES-256-CBC encryption/decryption compatibility
//! between Python and Rust implementations.

use std::process::Command;

use crate::common::IntegrationTestContext;

/// Fixed 64-byte key for reproducibility (128 hex chars)
const TEST_KEY: &str = "5ea11018b20f83455bf49ae8e2b7a1315ea11018b20f83455bf49ae8e2b7a1315ea11018b20f83455bf49ae8e2b7a1315ea11018b20f83455bf49ae8e2b7a131";

/// Test plaintext: "Hello, GROUP world!" in hex
const TEST_PLAINTEXT: &str = "48656c6c6f2c2047524f555020776f726c6421";

/// Test that Python can encrypt and Rust can decrypt.
#[test]
fn test_python_encrypts_rust_decrypts() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Python encrypt
    let python_input = format!("encrypt\n{}\n{}\n", TEST_KEY, TEST_PLAINTEXT);
    let mut python_cmd = ctx.venv().python_command();
    python_cmd
        .arg(ctx.helpers_dir().join("python_group_crypto.py"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut python_child = python_cmd.spawn().expect("Failed to spawn Python");
    {
        use std::io::Write;
        let stdin = python_child.stdin.as_mut().expect("Failed to get stdin");
        stdin.write_all(python_input.as_bytes()).expect("Failed to write to stdin");
    }
    let python_output = python_child.wait_with_output().expect("Failed to get Python output");

    let stdout = String::from_utf8_lossy(&python_output.stdout);
    let stderr = String::from_utf8_lossy(&python_output.stderr);

    eprintln!("Python encrypt stdout: {}", stdout);
    eprintln!("Python encrypt stderr: {}", stderr);

    // Extract ciphertext from RESULT= line
    let python_ciphertext = stdout
        .lines()
        .find(|l| l.starts_with("RESULT="))
        .map(|l| l.trim_start_matches("RESULT="))
        .expect("Python should output RESULT=");

    eprintln!("Python ciphertext: {}...", &python_ciphertext[..32.min(python_ciphertext.len())]);

    // Rust decrypt
    let rust_input = format!("decrypt\n{}\n{}\n", TEST_KEY, python_ciphertext);
    let mut rust_cmd = Command::new(ctx.rust_binary("test_group_crypto"));
    rust_cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut rust_child = rust_cmd.spawn().expect("Failed to spawn Rust");
    {
        use std::io::Write;
        let stdin = rust_child.stdin.as_mut().expect("Failed to get stdin");
        stdin.write_all(rust_input.as_bytes()).expect("Failed to write to stdin");
    }
    let rust_output = rust_child.wait_with_output().expect("Failed to get Rust output");

    let stdout = String::from_utf8_lossy(&rust_output.stdout);
    let stderr = String::from_utf8_lossy(&rust_output.stderr);

    eprintln!("Rust decrypt stdout: {}", stdout);
    eprintln!("Rust decrypt stderr: {}", stderr);

    // Extract decrypted text from RESULT= line
    let rust_decrypted = stdout
        .lines()
        .find(|l| l.starts_with("RESULT="))
        .map(|l| l.trim_start_matches("RESULT="))
        .expect("Rust should output RESULT=");

    eprintln!("Rust decrypted: {}", rust_decrypted);

    assert_eq!(
        rust_decrypted, TEST_PLAINTEXT,
        "Python→Rust: Decrypted data should match original plaintext"
    );

    eprintln!("Python→Rust encryption interop test passed");
}

/// Test that Rust can encrypt and Python can decrypt.
#[test]
fn test_rust_encrypts_python_decrypts() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Rust encrypt
    let rust_input = format!("encrypt\n{}\n{}\n", TEST_KEY, TEST_PLAINTEXT);
    let mut rust_cmd = Command::new(ctx.rust_binary("test_group_crypto"));
    rust_cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut rust_child = rust_cmd.spawn().expect("Failed to spawn Rust");
    {
        use std::io::Write;
        let stdin = rust_child.stdin.as_mut().expect("Failed to get stdin");
        stdin.write_all(rust_input.as_bytes()).expect("Failed to write to stdin");
    }
    let rust_output = rust_child.wait_with_output().expect("Failed to get Rust output");

    let stdout = String::from_utf8_lossy(&rust_output.stdout);
    let stderr = String::from_utf8_lossy(&rust_output.stderr);

    eprintln!("Rust encrypt stdout: {}", stdout);
    eprintln!("Rust encrypt stderr: {}", stderr);

    // Extract ciphertext from RESULT= line
    let rust_ciphertext = stdout
        .lines()
        .find(|l| l.starts_with("RESULT="))
        .map(|l| l.trim_start_matches("RESULT="))
        .expect("Rust should output RESULT=");

    eprintln!("Rust ciphertext: {}...", &rust_ciphertext[..32.min(rust_ciphertext.len())]);

    // Python decrypt
    let python_input = format!("decrypt\n{}\n{}\n", TEST_KEY, rust_ciphertext);
    let mut python_cmd = ctx.venv().python_command();
    python_cmd
        .arg(ctx.helpers_dir().join("python_group_crypto.py"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut python_child = python_cmd.spawn().expect("Failed to spawn Python");
    {
        use std::io::Write;
        let stdin = python_child.stdin.as_mut().expect("Failed to get stdin");
        stdin.write_all(python_input.as_bytes()).expect("Failed to write to stdin");
    }
    let python_output = python_child.wait_with_output().expect("Failed to get Python output");

    let stdout = String::from_utf8_lossy(&python_output.stdout);
    let stderr = String::from_utf8_lossy(&python_output.stderr);

    eprintln!("Python decrypt stdout: {}", stdout);
    eprintln!("Python decrypt stderr: {}", stderr);

    // Extract decrypted text from RESULT= line
    let python_decrypted = stdout
        .lines()
        .find(|l| l.starts_with("RESULT="))
        .map(|l| l.trim_start_matches("RESULT="))
        .expect("Python should output RESULT=");

    eprintln!("Python decrypted: {}", python_decrypted);

    assert_eq!(
        python_decrypted, TEST_PLAINTEXT,
        "Rust→Python: Decrypted data should match original plaintext"
    );

    eprintln!("Rust→Python encryption interop test passed");
}
