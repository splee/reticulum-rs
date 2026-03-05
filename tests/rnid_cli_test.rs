//! Integration tests for the rnid CLI binary.
//!
//! These tests verify the command-line interface behavior by invoking
//! the compiled binary and checking outputs and exit codes.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

// Counter for unique temp directory names
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Get the path to the rnid binary
fn rnid_binary() -> PathBuf {
    // Use CARGO_BIN_EXE if available (set by cargo test)
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rnid") {
        return PathBuf::from(path);
    }

    // Fall back to looking in target directory
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("rnid");
    path
}

/// Create a temporary directory for test files with unique name
fn temp_dir() -> PathBuf {
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "rnid_test_{}_{}_{}",
        std::process::id(),
        count,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Clean up a temporary directory
fn cleanup(dir: &PathBuf) {
    fs::remove_dir_all(dir).ok();
}

// =============================================================================
// Help and Version Tests
// =============================================================================

#[test]
fn test_help_flag() {
    let output = Command::new(rnid_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute rnid");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Manage Reticulum identities"));
    assert!(stdout.contains("-g, --generate"));
    assert!(stdout.contains("-s, --sign"));
    assert!(stdout.contains("-e, --encrypt"));
}

#[test]
fn test_version_flag() {
    let output = Command::new(rnid_binary())
        .arg("--version")
        .output()
        .expect("Failed to execute rnid");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnid"));
}

// =============================================================================
// Identity Generation Tests
// =============================================================================

#[test]
fn test_generate_identity() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");

    // Generate identity with -p to print info
    let output = Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap(), "-p"])
        .output()
        .expect("Failed to execute rnid");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Address Hash:"));
    assert!(stdout.contains("Public Key:"));
    assert!(stdout.contains("Verifying Key:"));

    cleanup(&temp);
}

#[test]
fn test_generate_and_save_identity() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");

    let output = Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute rnid");

    assert!(output.status.success());
    assert!(identity_file.exists());

    // Verify file is 64 bytes (correct identity format)
    let metadata = fs::metadata(&identity_file).unwrap();
    assert_eq!(metadata.len(), 64);

    cleanup(&temp);
}

#[test]
fn test_generate_with_base64_export() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");

    // Generate identity first
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity");

    // Export as base64
    let output = Command::new(rnid_binary())
        .args(["-i", identity_file.to_str().unwrap(), "-x", "-b"])
        .output()
        .expect("Failed to execute rnid");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Output should contain base64 encoded identity (88 chars for 64 bytes + newlines)
    // Base64 encodes 64 bytes to 88 characters (with padding)
    let lines: Vec<&str> = stdout.lines().collect();
    // The export line should be base64 (only alphanumeric, +, /, =)
    let has_base64 = lines.iter().any(|line| {
        line.len() > 80 && line.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
    });
    assert!(has_base64);

    cleanup(&temp);
}

// =============================================================================
// Identity Import/Export Tests
// =============================================================================

#[test]
fn test_print_identity_info() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");

    // Generate identity
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity");

    // Print identity info
    let output = Command::new(rnid_binary())
        .args(["-i", identity_file.to_str().unwrap(), "-p"])
        .output()
        .expect("Failed to execute rnid");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Address Hash:"));
    assert!(stdout.contains("Public Key:"));

    cleanup(&temp);
}

#[test]
fn test_export_hex_format() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");

    // Generate identity
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity");

    // Export as hex
    let output = Command::new(rnid_binary())
        .args(["-i", identity_file.to_str().unwrap(), "-x"])
        .output()
        .expect("Failed to execute rnid");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Hex output should be 128 characters (64 bytes * 2)
    let lines: Vec<&str> = stdout.lines().collect();
    let has_hex = lines.iter().any(|line| {
        line.len() == 128 && line.chars().all(|c| c.is_ascii_hexdigit())
    });
    assert!(has_hex);

    cleanup(&temp);
}

// =============================================================================
// Signing and Verification Tests
// =============================================================================

#[test]
fn test_sign_and_verify_file() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");
    let message_file = temp.join("message.txt");
    let signature_file = temp.join("message.txt.rsg");

    // Generate identity
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity");

    // Create message file
    fs::write(&message_file, b"Test message for signing").unwrap();

    // Sign the file
    let sign_output = Command::new(rnid_binary())
        .args([
            "-i", identity_file.to_str().unwrap(),
            "-s", message_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to sign file");

    assert!(sign_output.status.success());
    assert!(signature_file.exists());

    // Verify signature file is 64 bytes (Ed25519 signature)
    let sig_metadata = fs::metadata(&signature_file).unwrap();
    assert_eq!(sig_metadata.len(), 64);

    // Verify the signature
    let verify_output = Command::new(rnid_binary())
        .args([
            "-i", identity_file.to_str().unwrap(),
            "-V", signature_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to verify signature");

    assert!(verify_output.status.success());
    let stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(stdout.contains("is valid"));

    cleanup(&temp);
}

#[test]
fn test_verify_invalid_signature() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");
    let message_file = temp.join("message.txt");
    let signature_file = temp.join("message.txt.rsg");

    // Generate identity
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity");

    // Create message file
    fs::write(&message_file, b"Test message").unwrap();

    // Sign the file
    Command::new(rnid_binary())
        .args([
            "-i", identity_file.to_str().unwrap(),
            "-s", message_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to sign file");

    // Modify the message
    fs::write(&message_file, b"Modified message").unwrap();

    // Verification should fail
    let verify_output = Command::new(rnid_binary())
        .args([
            "-i", identity_file.to_str().unwrap(),
            "-V", signature_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to verify signature");

    assert!(!verify_output.status.success());
    // "INVALID" message is printed to stderr
    let stderr = String::from_utf8_lossy(&verify_output.stderr);
    assert!(stderr.contains("INVALID"));

    cleanup(&temp);
}

// =============================================================================
// Encryption and Decryption Tests
// =============================================================================

#[test]
fn test_encrypt_and_decrypt_file() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");
    let plaintext_file = temp.join("secret.txt");
    let encrypted_file = temp.join("secret.txt.rfe");
    let decrypted_file = temp.join("decrypted.txt");

    // Generate identity
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity");

    // Create plaintext file
    let original_content = b"This is a secret message for encryption testing!";
    fs::write(&plaintext_file, original_content).unwrap();

    // Encrypt the file
    let encrypt_output = Command::new(rnid_binary())
        .args([
            "-i", identity_file.to_str().unwrap(),
            "-e", plaintext_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to encrypt file");

    assert!(encrypt_output.status.success());
    assert!(encrypted_file.exists());

    // Encrypted file should be larger than plaintext (due to overhead)
    let enc_metadata = fs::metadata(&encrypted_file).unwrap();
    assert!(enc_metadata.len() > original_content.len() as u64);

    // Decrypt the file
    let decrypt_output = Command::new(rnid_binary())
        .args([
            "-i", identity_file.to_str().unwrap(),
            "-d", encrypted_file.to_str().unwrap(),
            "-w", decrypted_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to decrypt file");

    assert!(decrypt_output.status.success());
    assert!(decrypted_file.exists());

    // Verify decrypted content matches original
    let decrypted_content = fs::read(&decrypted_file).unwrap();
    assert_eq!(original_content.as_slice(), decrypted_content.as_slice());

    cleanup(&temp);
}

#[test]
fn test_decrypt_with_wrong_identity_fails() {
    let temp = temp_dir();
    let identity1_file = temp.join("identity1.dat");
    let identity2_file = temp.join("identity2.dat");
    let plaintext_file = temp.join("secret.txt");
    let encrypted_file = temp.join("secret.txt.rfe");
    let decrypted_file = temp.join("decrypted.txt");

    // Generate two different identities
    Command::new(rnid_binary())
        .args(["-g", identity1_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity1");

    Command::new(rnid_binary())
        .args(["-g", identity2_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity2");

    // Create and encrypt with identity1
    fs::write(&plaintext_file, b"Secret message").unwrap();

    Command::new(rnid_binary())
        .args([
            "-i", identity1_file.to_str().unwrap(),
            "-e", plaintext_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to encrypt file");

    // Try to decrypt with identity2 - should fail
    let decrypt_output = Command::new(rnid_binary())
        .args([
            "-i", identity2_file.to_str().unwrap(),
            "-d", encrypted_file.to_str().unwrap(),
            "-w", decrypted_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute decrypt command");

    assert!(!decrypt_output.status.success());

    cleanup(&temp);
}

// =============================================================================
// Destination Hash Tests
// =============================================================================

#[test]
fn test_destination_hash() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");

    // Generate identity
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity");

    // Compute destination hash
    let output = Command::new(rnid_binary())
        .args([
            "-i", identity_file.to_str().unwrap(),
            "-H", "myapp.test.aspect",
        ])
        .output()
        .expect("Failed to compute destination hash");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("myapp.test.aspect"));
    assert!(stdout.contains("destination"));
    // Hash should be in <hash> format
    assert!(stdout.contains('<'));
    assert!(stdout.contains('>'));

    cleanup(&temp);
}

#[test]
fn test_destination_hash_deterministic() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");

    // Generate identity
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity");

    // Compute hash twice
    let output1 = Command::new(rnid_binary())
        .args([
            "-i", identity_file.to_str().unwrap(),
            "-H", "myapp.aspect",
        ])
        .output()
        .expect("Failed to compute hash");

    let output2 = Command::new(rnid_binary())
        .args([
            "-i", identity_file.to_str().unwrap(),
            "-H", "myapp.aspect",
        ])
        .output()
        .expect("Failed to compute hash");

    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert_eq!(stdout1, stdout2);

    cleanup(&temp);
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
fn test_no_action_shows_usage() {
    let output = Command::new(rnid_binary())
        .output()
        .expect("Failed to execute rnid");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No action specified"));
    assert!(stderr.contains("--help"));
}

#[test]
fn test_missing_identity_file() {
    let output = Command::new(rnid_binary())
        .args(["-i", "/nonexistent/path/identity.dat", "-p"])
        .output()
        .expect("Failed to execute rnid");

    assert!(!output.status.success());
}

#[test]
fn test_sign_without_identity() {
    let temp = temp_dir();
    let message_file = temp.join("message.txt");
    fs::write(&message_file, b"Test").unwrap();

    let output = Command::new(rnid_binary())
        .args(["-s", message_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute rnid");

    assert!(!output.status.success());

    cleanup(&temp);
}

#[test]
fn test_force_overwrite() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");

    // Generate first identity
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate first identity");

    let first_content = fs::read(&identity_file).unwrap();

    // Try to generate again without -f (should fail or warn)
    let output_no_force = Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute rnid");

    assert!(!output_no_force.status.success());

    // Generate with -f (should succeed)
    let output_force = Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap(), "-f"])
        .output()
        .expect("Failed to execute rnid");

    assert!(output_force.status.success());

    // Content should be different (new identity)
    let second_content = fs::read(&identity_file).unwrap();
    assert_ne!(first_content, second_content);

    cleanup(&temp);
}

// =============================================================================
// Encoding Format Tests
// =============================================================================

#[test]
fn test_base32_encoding() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");

    // Generate identity
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity");

    // Export as base32
    let output = Command::new(rnid_binary())
        .args(["-i", identity_file.to_str().unwrap(), "-x", "-B"])
        .output()
        .expect("Failed to execute rnid");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Base32 output should contain only valid base32 characters
    let lines: Vec<&str> = stdout.lines().collect();
    let has_base32 = lines.iter().any(|line| {
        line.len() > 80 && line.chars().all(|c| {
            c.is_ascii_uppercase() || ('2'..='7').contains(&c) || c == '='
        })
    });
    assert!(has_base32);

    cleanup(&temp);
}

// =============================================================================
// Private Key Display Tests
// =============================================================================

#[test]
fn test_print_private_key() {
    let temp = temp_dir();
    let identity_file = temp.join("test_identity.dat");

    // Generate identity
    Command::new(rnid_binary())
        .args(["-g", identity_file.to_str().unwrap()])
        .output()
        .expect("Failed to generate identity");

    // Print without -P (should not show private keys)
    let output_no_priv = Command::new(rnid_binary())
        .args(["-i", identity_file.to_str().unwrap(), "-p"])
        .output()
        .expect("Failed to execute rnid");

    let stdout_no_priv = String::from_utf8_lossy(&output_no_priv.stdout);
    assert!(!stdout_no_priv.contains("Private Key:"));
    assert!(!stdout_no_priv.contains("Signing Key:"));

    // Print with -P (should show private keys)
    let output_with_priv = Command::new(rnid_binary())
        .args(["-i", identity_file.to_str().unwrap(), "-p", "-P"])
        .output()
        .expect("Failed to execute rnid");

    let stdout_with_priv = String::from_utf8_lossy(&output_with_priv.stdout);
    assert!(stdout_with_priv.contains("Private Key:"));
    assert!(stdout_with_priv.contains("Signing Key:"));

    cleanup(&temp);
}
