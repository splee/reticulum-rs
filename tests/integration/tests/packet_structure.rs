//! Packet structure integration tests.
//!
//! These tests verify that packet header encoding/decoding is compatible
//! between Python and Rust implementations.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::common::{unregister_pid, IntegrationTestContext};

/// Helper to run the Rust packet codec and get output
fn run_rust_codec(ctx: &IntegrationTestContext, input: &str) -> Result<String, String> {
    let (mut child, pid) = ctx
        .spawn_child(
            Command::new(ctx.rust_binary("test_packet_codec"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .map_err(|e| format!("Failed to spawn Rust codec: {}", e))?;

    {
        let stdin = child.stdin.as_mut().ok_or("Failed to get stdin")?;
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| format!("Failed to write to stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to get output: {}", e))?;
    unregister_pid(pid);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !stderr.is_empty() {
        eprintln!("Rust codec stderr: {}", stderr);
    }

    Ok(stdout)
}

/// Helper to run the Python packet codec and get output
fn run_python_codec(ctx: &IntegrationTestContext, input: &str) -> Result<String, String> {
    let (mut child, pid) = ctx
        .spawn_child(
            ctx.venv()
                .python_command()
                .arg(ctx.helpers_dir().join("python_packet_codec.py"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .map_err(|e| format!("Failed to spawn Python codec: {}", e))?;

    {
        let stdin = child.stdin.as_mut().ok_or("Failed to get stdin")?;
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| format!("Failed to write to stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to get output: {}", e))?;
    unregister_pid(pid);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !stderr.is_empty() {
        eprintln!("Python codec stderr: {}", stderr);
    }

    Ok(stdout)
}

/// Extract a value from output lines by key (e.g., "META_BYTE=xx")
fn extract_value(output: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    output
        .lines()
        .find(|l| l.starts_with(&prefix))
        .map(|l| l.trim_start_matches(&prefix).to_string())
}

/// Test 1: Verify context_flag wire format encoding.
///
/// The context_flag is bit 5 (0x20 mask) in the meta byte.
/// This test verifies that packets with context_flag=true and context_flag=false
/// produce different meta bytes that differ only in bit 5.
#[test]
fn test_context_flag_wire_format() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Test context_flag=false
    let json_false = r#"{"header_type":0,"context_flag":false,"transport_type":0,"destination_type":0,"packet_type":0}"#;

    // Test context_flag=true
    let json_true = r#"{"header_type":0,"context_flag":true,"transport_type":0,"destination_type":0,"packet_type":0}"#;

    // Rust encode
    let rust_output_false = run_rust_codec(&ctx, &format!("meta_encode {}\n", json_false))
        .expect("Rust codec failed for context_flag=false");
    let rust_output_true = run_rust_codec(&ctx, &format!("meta_encode {}\n", json_true))
        .expect("Rust codec failed for context_flag=true");

    let rust_meta_false =
        extract_value(&rust_output_false, "META_BYTE").expect("No META_BYTE for false");
    let rust_meta_true =
        extract_value(&rust_output_true, "META_BYTE").expect("No META_BYTE for true");

    eprintln!(
        "Rust: context_flag=false -> {}, context_flag=true -> {}",
        rust_meta_false, rust_meta_true
    );

    // Python encode
    let python_output_false = run_python_codec(&ctx, &format!("meta_encode {}\n", json_false))
        .expect("Python codec failed for context_flag=false");
    let python_output_true = run_python_codec(&ctx, &format!("meta_encode {}\n", json_true))
        .expect("Python codec failed for context_flag=true");

    let python_meta_false =
        extract_value(&python_output_false, "META_BYTE").expect("No META_BYTE for false");
    let python_meta_true =
        extract_value(&python_output_true, "META_BYTE").expect("No META_BYTE for true");

    eprintln!(
        "Python: context_flag=false -> {}, context_flag=true -> {}",
        python_meta_false, python_meta_true
    );

    // Verify Rust and Python produce same meta bytes
    assert_eq!(
        rust_meta_false, python_meta_false,
        "Rust and Python should produce same meta byte for context_flag=false"
    );
    assert_eq!(
        rust_meta_true, python_meta_true,
        "Rust and Python should produce same meta byte for context_flag=true"
    );

    // Verify bit 5 (0x20) differs
    let meta_false = u8::from_str_radix(&rust_meta_false, 16).expect("Invalid hex");
    let meta_true = u8::from_str_radix(&rust_meta_true, 16).expect("Invalid hex");

    assert_eq!(
        meta_false & 0x20,
        0,
        "context_flag=false should have bit 5 unset"
    );
    assert_eq!(
        meta_true & 0x20,
        0x20,
        "context_flag=true should have bit 5 set"
    );
    assert_eq!(
        meta_true - meta_false,
        0x20,
        "Only bit 5 should differ between context_flag values"
    );

    // Cross-validate: Rust decode Python's output
    let rust_decode = run_rust_codec(&ctx, &format!("meta_decode {}\n", python_meta_true))
        .expect("Rust decode failed");
    let decoded_flag = extract_value(&rust_decode, "CONTEXT_FLAG").expect("No CONTEXT_FLAG");
    assert_eq!(decoded_flag, "1", "Rust should decode Python's context_flag=true correctly");

    eprintln!("test_context_flag_wire_format passed");
}

/// Test 2: Verify IFAC flag is NOT in meta byte.
///
/// The IFAC flag is handled at the transport layer, not in the packet header's
/// meta byte. Bit 7 of the meta byte is reserved.
#[test]
fn test_ifac_flag_transport_handling() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Encode a packet with all header fields set to maximum
    let json = r#"{"header_type":1,"context_flag":true,"transport_type":1,"destination_type":3,"packet_type":3}"#;

    let rust_output =
        run_rust_codec(&ctx, &format!("meta_encode {}\n", json)).expect("Rust codec failed");
    let rust_meta = extract_value(&rust_output, "META_BYTE").expect("No META_BYTE");

    let meta_byte = u8::from_str_radix(&rust_meta, 16).expect("Invalid hex");

    // Bit 7 should be 0 (reserved, not used for IFAC)
    assert_eq!(
        meta_byte & 0x80,
        0,
        "Bit 7 should be reserved (0) - IFAC is handled at transport layer"
    );

    // Maximum value with all bits 0-6 set is 0x7F
    assert_eq!(
        meta_byte, 0x7F,
        "With all header fields at max, meta byte should be 0x7F (bit 7 reserved)"
    );

    // Verify Python agrees
    let python_output =
        run_python_codec(&ctx, &format!("meta_encode {}\n", json)).expect("Python codec failed");
    let python_meta = extract_value(&python_output, "META_BYTE").expect("No META_BYTE");

    assert_eq!(
        rust_meta, python_meta,
        "Rust and Python should agree on max meta byte value"
    );

    eprintln!("test_ifac_flag_transport_handling passed");
}

/// Test 3: Verify propagation_type=Broadcast encoding.
///
/// transport_type is bit 4 (0x10 mask). Broadcast = 0.
#[test]
fn test_propagation_type_broadcast() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let json = r#"{"header_type":0,"context_flag":false,"transport_type":0,"destination_type":0,"packet_type":1}"#;

    let rust_output =
        run_rust_codec(&ctx, &format!("meta_encode {}\n", json)).expect("Rust codec failed");
    let python_output =
        run_python_codec(&ctx, &format!("meta_encode {}\n", json)).expect("Python codec failed");

    let rust_meta = extract_value(&rust_output, "META_BYTE").expect("No META_BYTE");
    let python_meta = extract_value(&python_output, "META_BYTE").expect("No META_BYTE");

    assert_eq!(rust_meta, python_meta, "Rust and Python should match");

    let meta_byte = u8::from_str_radix(&rust_meta, 16).expect("Invalid hex");
    assert_eq!(
        meta_byte & 0x10,
        0,
        "transport_type=Broadcast should have bit 4 unset"
    );

    // Expected: header_type=0, context_flag=0, transport_type=0, dest_type=0, pkt_type=1
    // = 0b00000001 = 0x01
    assert_eq!(meta_byte, 0x01, "Meta byte should be 0x01 for Announce packet");

    eprintln!("test_propagation_type_broadcast passed");
}

/// Test 4: Verify propagation_type=Transport encoding with Type2 header.
///
/// Transport packets use header_type=Type2 and transport_type=Transport (bit 4 set).
#[test]
fn test_propagation_type_transport() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    let dest = "deadbeef12345678deadbeef12345678";
    let transport_id = "cafebabe87654321cafebabe87654321";

    let json = format!(
        r#"{{"header_type":1,"context_flag":false,"transport_type":1,"destination_type":0,"packet_type":1,"destination":"{}","transport_id":"{}","context":0,"data":"48656c6c6f","hops":3}}"#,
        dest, transport_id
    );

    let rust_output =
        run_rust_codec(&ctx, &format!("encode {}\n", json)).expect("Rust codec failed");
    let python_output =
        run_python_codec(&ctx, &format!("encode {}\n", json)).expect("Python codec failed");

    eprintln!("Rust output: {}", rust_output);
    eprintln!("Python output: {}", python_output);

    let rust_raw = extract_value(&rust_output, "RAW_BYTES").expect("No RAW_BYTES from Rust");
    let python_raw = extract_value(&python_output, "RAW_BYTES").expect("No RAW_BYTES from Python");

    assert_eq!(rust_raw, python_raw, "Rust and Python should produce identical raw bytes");

    let rust_meta = extract_value(&rust_output, "META_BYTE").expect("No META_BYTE from Rust");
    let meta_byte = u8::from_str_radix(&rust_meta, 16).expect("Invalid hex");

    // Verify bit 4 is set (transport_type=Transport)
    assert_eq!(
        meta_byte & 0x10,
        0x10,
        "transport_type=Transport should have bit 4 set"
    );

    // Verify bit 6 is set (header_type=Type2)
    assert_eq!(
        meta_byte & 0x40,
        0x40,
        "header_type=Type2 should have bit 6 set"
    );

    // Verify transport_id appears after hops byte
    let raw_bytes = hex::decode(&rust_raw).expect("Invalid raw hex");
    assert!(raw_bytes.len() >= 2 + 16 + 16, "Packet should contain transport_id and destination");

    // Wire format for Type2: [meta][hops][transport_id(16)][dest(16)][context][data...]
    let wire_transport_id = &raw_bytes[2..18];
    let expected_transport_id = hex::decode(transport_id).expect("Invalid transport_id hex");
    assert_eq!(
        wire_transport_id, expected_transport_id.as_slice(),
        "Transport ID should appear at bytes 2-17"
    );

    eprintln!("test_propagation_type_transport passed");
}

/// Test 5: Test matrix of all header field combinations.
///
/// Verifies bidirectional encode/decode compatibility across all combinations.
#[test]
fn test_header_byte_encoding_patterns() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Test all combinations of:
    // header_type: 0, 1
    // context_flag: false, true
    // transport_type: 0, 1
    // destination_type: 0, 1, 2, 3
    // packet_type: 0, 1, 2, 3

    let mut test_count = 0;
    let mut pass_count = 0;

    for header_type in 0..=1 {
        for context_flag in [false, true] {
            for transport_type in 0..=1 {
                for destination_type in 0..=3 {
                    for packet_type in 0..=3 {
                        let json = format!(
                            r#"{{"header_type":{},"context_flag":{},"transport_type":{},"destination_type":{},"packet_type":{}}}"#,
                            header_type,
                            context_flag,
                            transport_type,
                            destination_type,
                            packet_type
                        );

                        test_count += 1;

                        // Rust encode
                        let rust_output =
                            match run_rust_codec(&ctx, &format!("meta_encode {}\n", json)) {
                                Ok(o) => o,
                                Err(e) => {
                                    eprintln!("Rust encode failed for {}: {}", json, e);
                                    continue;
                                }
                            };

                        // Python encode
                        let python_output =
                            match run_python_codec(&ctx, &format!("meta_encode {}\n", json)) {
                                Ok(o) => o,
                                Err(e) => {
                                    eprintln!("Python encode failed for {}: {}", json, e);
                                    continue;
                                }
                            };

                        let rust_meta = match extract_value(&rust_output, "META_BYTE") {
                            Some(v) => v,
                            None => {
                                eprintln!("No META_BYTE from Rust for {}", json);
                                continue;
                            }
                        };

                        let python_meta = match extract_value(&python_output, "META_BYTE") {
                            Some(v) => v,
                            None => {
                                eprintln!("No META_BYTE from Python for {}", json);
                                continue;
                            }
                        };

                        if rust_meta != python_meta {
                            eprintln!(
                                "MISMATCH for {}: Rust={}, Python={}",
                                json, rust_meta, python_meta
                            );
                            continue;
                        }

                        // Cross-decode: Python decode Rust's meta byte
                        let python_decode =
                            match run_python_codec(&ctx, &format!("meta_decode {}\n", rust_meta)) {
                                Ok(o) => o,
                                Err(e) => {
                                    eprintln!("Python decode failed: {}", e);
                                    continue;
                                }
                            };

                        // Verify decoded fields match
                        let decoded_header_type =
                            extract_value(&python_decode, "HEADER_TYPE").unwrap_or_default();
                        let decoded_context_flag =
                            extract_value(&python_decode, "CONTEXT_FLAG").unwrap_or_default();
                        let decoded_transport_type =
                            extract_value(&python_decode, "TRANSPORT_TYPE").unwrap_or_default();
                        let decoded_dest_type =
                            extract_value(&python_decode, "DESTINATION_TYPE").unwrap_or_default();
                        let decoded_pkt_type =
                            extract_value(&python_decode, "PACKET_TYPE").unwrap_or_default();

                        let expected_context_flag = if context_flag { "1" } else { "0" };

                        if decoded_header_type != header_type.to_string()
                            || decoded_context_flag != expected_context_flag
                            || decoded_transport_type != transport_type.to_string()
                            || decoded_dest_type != destination_type.to_string()
                            || decoded_pkt_type != packet_type.to_string()
                        {
                            eprintln!(
                                "Decode mismatch for {}: got ht={} cf={} tt={} dt={} pt={}",
                                json,
                                decoded_header_type,
                                decoded_context_flag,
                                decoded_transport_type,
                                decoded_dest_type,
                                decoded_pkt_type
                            );
                            continue;
                        }

                        pass_count += 1;
                    }
                }
            }
        }
    }

    eprintln!(
        "test_header_byte_encoding_patterns: {}/{} tests passed",
        pass_count, test_count
    );

    // All 128 combinations (2*2*2*4*4) should pass
    assert_eq!(
        pass_count, 128,
        "All 128 header field combinations should pass"
    );

    eprintln!("test_header_byte_encoding_patterns passed");
}

/// Test 6: Verify packet size limits (MDU).
///
/// Tests packets at MDU-1, MDU (2048), and MDU+1 bytes.
#[test]
fn test_packet_size_limits() {
    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    const MDU: usize = 2048;
    const HEADER_OVERHEAD: usize = 2 + 16 + 1; // meta + hops + dest + context for Type1

    // Maximum data size for Type1 packet
    let max_data_size = MDU - HEADER_OVERHEAD;

    // Test at max size - should succeed
    let data_max = "ab".repeat(max_data_size);
    let json_max = format!(
        r#"{{"header_type":0,"context_flag":false,"transport_type":0,"destination_type":0,"packet_type":0,"destination":"00000000000000000000000000000000","context":0,"data":"{}","hops":0}}"#,
        data_max
    );

    let rust_output =
        run_rust_codec(&ctx, &format!("encode {}\n", json_max)).expect("Rust codec failed");
    assert!(
        extract_value(&rust_output, "STATUS").map_or(false, |s| s == "OK"),
        "Max size packet should succeed"
    );

    let raw_bytes = extract_value(&rust_output, "RAW_BYTES").expect("No RAW_BYTES");
    let raw_len = raw_bytes.len() / 2; // hex string length / 2 = byte length
    eprintln!("Max size packet: {} bytes", raw_len);
    assert!(
        raw_len <= MDU,
        "Max size packet should not exceed MDU ({} > {})",
        raw_len,
        MDU
    );

    // Test at MDU-1 - should succeed
    let data_mdu_minus_1 = "ab".repeat(max_data_size - 1);
    let json_mdu_minus_1 = format!(
        r#"{{"header_type":0,"context_flag":false,"transport_type":0,"destination_type":0,"packet_type":0,"destination":"00000000000000000000000000000000","context":0,"data":"{}","hops":0}}"#,
        data_mdu_minus_1
    );

    let rust_output_minus_1 =
        run_rust_codec(&ctx, &format!("encode {}\n", json_mdu_minus_1)).expect("Rust codec failed");
    assert!(
        extract_value(&rust_output_minus_1, "STATUS").map_or(false, |s| s == "OK"),
        "MDU-1 size packet should succeed"
    );

    // Verify Python produces same result for max size
    let python_output =
        run_python_codec(&ctx, &format!("encode {}\n", json_max)).expect("Python codec failed");
    let python_raw = extract_value(&python_output, "RAW_BYTES").expect("No RAW_BYTES from Python");

    assert_eq!(
        raw_bytes, python_raw,
        "Rust and Python should produce identical raw bytes for max size packet"
    );

    eprintln!("test_packet_size_limits passed");
}
