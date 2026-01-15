//! Identity interoperability tests.
//!
//! Tests that verify identity format compatibility between
//! Python and Rust implementations.

use crate::common::IntegrationTestContext;

/// Test that Rust rnid can generate an identity with correct format.
#[test]
fn test_rust_identity_generation() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Generate identity with Rust rnid
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let identity_path = temp_dir.path().join("test_identity.dat");

    let output = ctx
        .run_to_completion(
            std::process::Command::new(ctx.rust_binary("rnid"))
                .args(["-g", identity_path.to_str().unwrap()]),
        )
        .expect("Failed to run rnid");

    assert!(output.status.success(), "rnid -g should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("rnid output:\n{}", stdout);

    // Extract address hash - should be 32 hex chars in angle brackets
    let address = stdout
        .lines()
        .find_map(|line| {
            if let Some(start) = line.find('<') {
                if let Some(end) = line.find('>') {
                    let hash = &line[start + 1..end];
                    if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(hash.to_string());
                    }
                }
            }
            None
        })
        .expect("Should find address hash in output");

    assert_eq!(address.len(), 32, "Address hash should be 32 hex chars");
    eprintln!("Rust generated identity with address: {}", address);

    // Verify identity file was created
    assert!(identity_path.exists(), "Identity file should be created");

    // Identity file should be 64 bytes (two 32-byte keys)
    let metadata = std::fs::metadata(&identity_path).expect("Failed to get file metadata");
    assert_eq!(metadata.len(), 64, "Identity file should be 64 bytes");
}

/// Test that Python rnid can generate an identity.
#[test]
fn test_python_identity_generation() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Generate identity with Python rnid (requires file path argument)
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let identity_path = temp_dir.path().join("python_identity.dat");

    let output = ctx
        .run_to_completion(ctx.venv().rnid().args(["-g", identity_path.to_str().unwrap()]))
        .expect("Failed to run Python rnid");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("Python rnid stdout:\n{}", stdout);
    eprintln!("Python rnid stderr:\n{}", stderr);

    // Python rnid outputs to stdout or stderr depending on version
    let combined = format!("{}{}", stdout, stderr);

    // Look for a 32-character hex hash or verify file was created
    let has_hash = combined.lines().any(|line| {
        line.split_whitespace().any(|word| {
            let word = word.trim_matches(|c: char| !c.is_ascii_hexdigit());
            word.len() == 32 && word.chars().all(|c| c.is_ascii_hexdigit())
        })
    });

    // Identity file should be created
    let file_created = identity_path.exists();

    assert!(
        has_hash || file_created,
        "Python rnid should output an address hash or create identity file"
    );

    if file_created {
        eprintln!("Python identity file created at {:?}", identity_path);
    }
}

/// Test that Rust-generated identity files can be read by Python.
#[test]
fn test_rust_identity_readable_by_python() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Generate identity with Rust
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let identity_path = temp_dir.path().join("rust_identity.dat");

    let output = ctx
        .run_to_completion(
            std::process::Command::new(ctx.rust_binary("rnid"))
                .args(["-g", identity_path.to_str().unwrap()]),
        )
        .expect("Failed to run rnid");

    assert!(output.status.success(), "Rust rnid should succeed");

    // Extract Rust-generated address
    let rust_stdout = String::from_utf8_lossy(&output.stdout);
    let rust_address = rust_stdout
        .lines()
        .find_map(|line| {
            if let Some(start) = line.find('<') {
                if let Some(end) = line.find('>') {
                    let hash = &line[start + 1..end];
                    if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(hash.to_string());
                    }
                }
            }
            None
        })
        .expect("Should find Rust address hash");

    eprintln!("Rust identity address: {}", rust_address);

    // Read identity with Python
    let python_script = format!(
        r#"
import RNS
identity = RNS.Identity.from_file("{}")
print("ADDRESS=" + identity.hexhash)
"#,
        identity_path.to_str().unwrap()
    );

    let output = ctx
        .run_to_completion(ctx.venv().python_command().args(["-c", &python_script]))
        .expect("Failed to run Python");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("Python stdout: {}", stdout);
    eprintln!("Python stderr: {}", stderr);

    assert!(output.status.success(), "Python should read identity successfully");

    // Extract Python-read address
    let python_address = stdout
        .lines()
        .find_map(|line| {
            if line.starts_with("ADDRESS=") {
                Some(line.trim_start_matches("ADDRESS=").to_string())
            } else {
                None
            }
        })
        .expect("Python should output ADDRESS=");

    assert_eq!(
        rust_address, python_address,
        "Python should read the same address as Rust generated"
    );

    eprintln!(
        "Identity interop verified: Rust {} == Python {}",
        rust_address, python_address
    );
}

/// Test that Python-generated identity files can be read by Rust.
#[test]
fn test_python_identity_readable_by_rust() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let identity_path = temp_dir.path().join("python_identity.dat");

    // Generate identity with Python and save to file
    let python_script = format!(
        r#"
import RNS
identity = RNS.Identity()
identity.to_file("{}")
print("ADDRESS=" + identity.hexhash)
"#,
        identity_path.to_str().unwrap()
    );

    let output = ctx
        .run_to_completion(ctx.venv().python_command().args(["-c", &python_script]))
        .expect("Failed to run Python");
    assert!(output.status.success(), "Python should generate identity");

    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("Python output: {}", stdout);

    // Extract Python-generated address
    let python_address = stdout
        .lines()
        .find_map(|line| {
            if line.starts_with("ADDRESS=") {
                Some(line.trim_start_matches("ADDRESS=").to_string())
            } else {
                None
            }
        })
        .expect("Python should output ADDRESS=");

    eprintln!("Python identity address: {}", python_address);

    // Read identity with Rust rnid
    let output = ctx
        .run_to_completion(
            std::process::Command::new(ctx.rust_binary("rnid"))
                .args(["-i", identity_path.to_str().unwrap(), "-p"]),
        )
        .expect("Failed to run Rust rnid");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("Rust rnid stdout: {}", stdout);
    eprintln!("Rust rnid stderr: {}", stderr);

    assert!(output.status.success(), "Rust should read Python identity");

    // Extract Rust-read address (in angle brackets)
    let rust_address = stdout
        .lines()
        .find_map(|line| {
            if let Some(start) = line.find('<') {
                if let Some(end) = line.find('>') {
                    let hash = &line[start + 1..end];
                    if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(hash.to_string());
                    }
                }
            }
            None
        })
        .expect("Rust should output address hash");

    assert_eq!(
        python_address, rust_address,
        "Rust should read the same address as Python generated"
    );

    eprintln!(
        "Identity interop verified: Python {} == Rust {}",
        python_address, rust_address
    );
}
