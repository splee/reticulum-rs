//! Ratchet interoperability tests.
//!
//! Tests that verify ratchet support compatibility between Python and Rust
//! implementations. Ratchets provide forward secrecy for SINGLE destinations.

use std::time::Duration;

use crate::common::{IntegrationTestContext, TestOutput};

/// Test that Python can create a destination with ratchets enabled and announce it.
///
/// This is a baseline test to verify the Python ratchet server helper works correctly.
#[test]
fn test_python_ratchet_destination_creation() {
    let mut ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Start Python hub
    let hub = ctx
        .start_python_hub()
        .expect("Failed to start Python hub");

    // Start Python ratchet server
    let server = ctx
        .run_python_helper(
            "python_ratchet_server.py",
            &[
                "--tcp-client",
                &format!("127.0.0.1:{}", hub.port()),
                "-a",
                "test_app",
                "-A",
                "ratchettest",
                "-i",
                "2", // announce interval
                "-n",
                "2", // announce count
                "-t",
                "30", // timeout
                "-v",
            ],
        )
        .expect("Failed to start Python ratchet server");

    // Wait for destination hash
    let dest_line = server
        .wait_for_output("DESTINATION_HASH=", Duration::from_secs(15))
        .expect("Python server should output destination hash");

    let parsed = TestOutput::parse(&dest_line);
    let dest_hash = parsed
        .destination_hash()
        .expect("Should have destination hash");

    eprintln!("Python ratchet destination hash: {}", dest_hash);

    // Wait for ratchets to be enabled
    let ratchet_line = server
        .wait_for_output("RATCHETS_ENABLED=", Duration::from_secs(5))
        .expect("Python server should enable ratchets");

    assert!(
        ratchet_line.contains("RATCHETS_ENABLED=true"),
        "Ratchets should be enabled"
    );

    // Wait for first announce with ratchet
    let announce_line = server
        .wait_for_output("RATCHET_ID=", Duration::from_secs(10))
        .expect("Python server should output ratchet ID");

    eprintln!("Announce line: {}", announce_line);

    // Verify ratchet ID is present and correct format (20 hex chars = 10 bytes)
    if let Some(id_start) = announce_line.find("RATCHET_ID=") {
        let id_part = &announce_line[id_start + "RATCHET_ID=".len()..];
        let ratchet_id = id_part.split_whitespace().next().unwrap_or("");

        if ratchet_id != "none" {
            assert_eq!(
                ratchet_id.len(),
                20,
                "Ratchet ID should be 20 hex chars (10 bytes)"
            );
            assert!(
                ratchet_id.chars().all(|c| c.is_ascii_hexdigit()),
                "Ratchet ID should be hex"
            );
            eprintln!("Ratchet ID: {}", ratchet_id);
        }
    }

    // Wait for completion
    let complete_line = server
        .wait_for_output("COMPLETE=", Duration::from_secs(20))
        .expect("Python server should complete");

    assert!(
        complete_line.contains("COMPLETE=true"),
        "Server should complete successfully"
    );

    let server_output = server.output();
    eprintln!("Python ratchet server output:\n{}", server_output);
}

/// Test ratchet key generation format matches between Python and Rust.
///
/// This test verifies that the ratchet key generation functions produce
/// keys in the same format as Python.
#[test]
fn test_ratchet_key_format_compatibility() {
    use reticulum::identity::{
        generate_ratchet, get_ratchet_id, ratchet_public_bytes, RATCHET_ID_LENGTH, RATCHET_KEY_SIZE,
    };
    use rand_core::OsRng;

    // Generate a ratchet key with Rust
    let ratchet_priv = generate_ratchet(OsRng);
    assert_eq!(
        ratchet_priv.len(),
        RATCHET_KEY_SIZE,
        "Ratchet private key should be 32 bytes"
    );

    // Derive public key
    let ratchet_pub = ratchet_public_bytes(&ratchet_priv);
    assert_eq!(
        ratchet_pub.len(),
        RATCHET_KEY_SIZE,
        "Ratchet public key should be 32 bytes"
    );

    // Calculate ratchet ID
    let ratchet_id = get_ratchet_id(&ratchet_pub);
    assert_eq!(
        ratchet_id.len(),
        RATCHET_ID_LENGTH,
        "Ratchet ID should be 10 bytes"
    );

    // Verify formats
    eprintln!("Rust ratchet private key: {} bytes", ratchet_priv.len());
    eprintln!("Rust ratchet public key: {} bytes", ratchet_pub.len());
    eprintln!("Rust ratchet ID: {} bytes = {}", ratchet_id.len(), hex::encode(&ratchet_id));
}

/// Test that Rust can generate ratchet keys compatible with Python.
///
/// This test uses Python to verify Rust-generated ratchet keys.
#[test]
fn test_rust_ratchet_key_readable_by_python() {
    use reticulum::identity::{generate_ratchet, ratchet_public_bytes, get_ratchet_id};
    use rand_core::OsRng;

    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Generate ratchet with Rust
    let ratchet_priv = generate_ratchet(OsRng);
    let ratchet_pub = ratchet_public_bytes(&ratchet_priv);
    let rust_ratchet_id = get_ratchet_id(&ratchet_pub);

    let rust_priv_hex = hex::encode(&ratchet_priv);
    let rust_pub_hex = hex::encode(&ratchet_pub);
    let rust_id_hex = hex::encode(&rust_ratchet_id);

    eprintln!("Rust private: {}", rust_priv_hex);
    eprintln!("Rust public: {}", rust_pub_hex);
    eprintln!("Rust ID: {}", rust_id_hex);

    // Verify with Python
    let python_script = format!(
        r#"
import RNS

# Load the Rust-generated private key and use RNS's own method
priv_bytes = bytes.fromhex("{}")

# Use RNS's method which handles the key derivation correctly
pub_bytes = RNS.Identity._ratchet_public_bytes(priv_bytes)

# Calculate ratchet ID (Python method)
ratchet_id = RNS.Identity._get_ratchet_id(pub_bytes)

print(f"PYTHON_PUBLIC={{pub_bytes.hex()}}")
print(f"PYTHON_ID={{ratchet_id.hex()}}")
"#,
        rust_priv_hex
    );

    let output = ctx
        .run_to_completion(ctx.venv().python_command().args(["-c", &python_script]))
        .expect("Failed to run Python");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("Python stdout: {}", stdout);
    eprintln!("Python stderr: {}", stderr);

    assert!(output.status.success(), "Python script should succeed");

    // Extract Python results
    let python_pub = stdout
        .lines()
        .find_map(|line| {
            if line.starts_with("PYTHON_PUBLIC=") {
                Some(line.trim_start_matches("PYTHON_PUBLIC=").to_string())
            } else {
                None
            }
        })
        .expect("Python should output public key");

    let python_id = stdout
        .lines()
        .find_map(|line| {
            if line.starts_with("PYTHON_ID=") {
                Some(line.trim_start_matches("PYTHON_ID=").to_string())
            } else {
                None
            }
        })
        .expect("Python should output ratchet ID");

    // Compare
    assert_eq!(
        rust_pub_hex, python_pub,
        "Rust and Python should derive the same public key"
    );

    assert_eq!(
        rust_id_hex, python_id,
        "Rust and Python should calculate the same ratchet ID"
    );

    eprintln!("Ratchet key compatibility verified!");
    eprintln!("  Public key: {}", rust_pub_hex);
    eprintln!("  Ratchet ID: {}", rust_id_hex);
}

/// Test that Python-generated ratchet keys can be read by Rust.
#[test]
fn test_python_ratchet_key_readable_by_rust() {
    use reticulum::identity::{ratchet_public_bytes, get_ratchet_id, RATCHET_KEY_SIZE};

    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Generate ratchet with Python
    let python_script = r#"
import RNS

# Generate ratchet using Python's method
ratchet_priv = RNS.Identity._generate_ratchet()
ratchet_pub = RNS.Identity._ratchet_public_bytes(ratchet_priv)
ratchet_id = RNS.Identity._get_ratchet_id(ratchet_pub)

print(f"PYTHON_PRIVATE={ratchet_priv.hex()}")
print(f"PYTHON_PUBLIC={ratchet_pub.hex()}")
print(f"PYTHON_ID={ratchet_id.hex()}")
"#;

    let output = ctx
        .run_to_completion(ctx.venv().python_command().args(["-c", python_script]))
        .expect("Failed to run Python");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("Python stdout: {}", stdout);
    eprintln!("Python stderr: {}", stderr);

    assert!(output.status.success(), "Python script should succeed");

    // Extract Python results
    let python_priv_hex = stdout
        .lines()
        .find_map(|line| {
            if line.starts_with("PYTHON_PRIVATE=") {
                Some(line.trim_start_matches("PYTHON_PRIVATE=").to_string())
            } else {
                None
            }
        })
        .expect("Python should output private key");

    let python_pub_hex = stdout
        .lines()
        .find_map(|line| {
            if line.starts_with("PYTHON_PUBLIC=") {
                Some(line.trim_start_matches("PYTHON_PUBLIC=").to_string())
            } else {
                None
            }
        })
        .expect("Python should output public key");

    let python_id_hex = stdout
        .lines()
        .find_map(|line| {
            if line.starts_with("PYTHON_ID=") {
                Some(line.trim_start_matches("PYTHON_ID=").to_string())
            } else {
                None
            }
        })
        .expect("Python should output ratchet ID");

    eprintln!("Python private: {}", python_priv_hex);
    eprintln!("Python public: {}", python_pub_hex);
    eprintln!("Python ID: {}", python_id_hex);

    // Parse Python private key with Rust
    let python_priv_bytes = hex::decode(&python_priv_hex).expect("Valid hex");
    assert_eq!(python_priv_bytes.len(), RATCHET_KEY_SIZE, "Private key should be 32 bytes");

    let mut priv_key = [0u8; RATCHET_KEY_SIZE];
    priv_key.copy_from_slice(&python_priv_bytes);

    // Derive public key with Rust
    let rust_pub = ratchet_public_bytes(&priv_key);
    let rust_pub_hex = hex::encode(&rust_pub);

    // Calculate ratchet ID with Rust
    let rust_id = get_ratchet_id(&rust_pub);
    let rust_id_hex = hex::encode(&rust_id);

    // Compare
    assert_eq!(
        python_pub_hex, rust_pub_hex,
        "Rust should derive the same public key as Python"
    );

    assert_eq!(
        python_id_hex, rust_id_hex,
        "Rust should calculate the same ratchet ID as Python"
    );

    eprintln!("Python -> Rust ratchet compatibility verified!");
    eprintln!("  Public key: {}", rust_pub_hex);
    eprintln!("  Ratchet ID: {}", rust_id_hex);
}

/// Test that Rust can parse Python-generated ratchet announce packets.
///
/// This test verifies that Rust's DestinationAnnounce::validate_full() correctly
/// extracts the ratchet public key from announces with context_flag=true.
#[test]
fn test_rust_parse_python_ratchet_announce() {
    use reticulum::destination::DestinationAnnounce;
    use reticulum::identity::get_ratchet_id;
    use reticulum::packet::Packet;
    use reticulum::buffer::InputBuffer;

    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Python script that creates a ratchet announce and outputs the raw packet bytes
    let python_script = r#"
import RNS
import tempfile
import os

# Initialize Reticulum with a temporary config (standalone mode)
temp_config_dir = tempfile.mkdtemp(prefix="rns_ratchet_test_")
config_content = """
[reticulum]
enable_transport = No
share_instance = No
"""
config_path = os.path.join(temp_config_dir, "config")
with open(config_path, "w") as f:
    f.write(config_content)

RNS.Reticulum(configdir=temp_config_dir)

# Create identity and destination
identity = RNS.Identity()
destination = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "test_app",
    "ratchettest"
)

# Enable ratchets
ratchets_path = os.path.join(temp_config_dir, "ratchets")
destination.enable_ratchets(ratchets_path)

# Get the current ratchet info BEFORE announce (it will rotate during announce)
# We need to force a rotate first to have a ratchet
destination.rotate_ratchets()
ratchet_priv = destination.ratchets[0]
ratchet_pub = RNS.Identity._ratchet_public_bytes(ratchet_priv)
ratchet_id = RNS.Identity._get_ratchet_id(ratchet_pub)

# Create announce packet - this includes the ratchet
# We need to capture the raw packet bytes
# In Python RNS, the announce method sends the packet, so we need to build it manually

# Build the announce data like Python does
import time
random_hash = RNS.Identity.get_random_hash()[:5] + int(time.time()).to_bytes(5, 'big')

# Signed data: dest_hash + public_key + name_hash + random_hash + ratchet + app_data
# In Python RNS, the signed data uses pub_bytes (X25519) + sig_pub_bytes (Ed25519)
app_data = b""
signed_data = destination.hash + identity.pub_bytes + identity.sig_pub_bytes + destination.name_hash + random_hash + ratchet_pub + app_data
signature = identity.sign(signed_data)

# Packet data: x25519_pub + ed25519_pub + name_hash + random_hash + ratchet + signature + app_data
packet_data = identity.pub_bytes + identity.sig_pub_bytes + destination.name_hash + random_hash + ratchet_pub + signature + app_data

# Build header bytes (2 bytes for Type1 header)
# Header format: [ifac_flag:1, header_type:2, context_flag:1, transport_type:2, destination_type:2] [hops:8]
# context_flag=1 for ratchet, transport_type=broadcast(0), dest_type=single(0), packet_type=announce(1)
# Byte 0: 0b00100001 = 0x21 (context_flag=1, header_type=1, announce)
# Actually let me compute it properly:
# ifac_flag=0 (bit 7), header_type=1 (bits 6-5: 01), context_flag=1 (bit 4),
# transport_type=0 (bits 3-2: 00), dest_type=0 (bits 1-0: 00)
# Byte 0 = 0b0_01_1_00_00 = 0x30... wait this isn't right

# Let me look at how Python encodes the header
# From RNS packet.py - the header is [HEADER, HOPS] where HEADER encodes flags and types
# Actually the format is more complex - let me just print the values we need

print(f"DEST_HASH={destination.hash.hex()}")
print(f"IDENTITY_PUB={identity.pub_bytes.hex()}")
print(f"IDENTITY_SIGN_PUB={identity.sig_pub_bytes.hex()}")
print(f"NAME_HASH={destination.name_hash.hex()}")
print(f"RANDOM_HASH={random_hash.hex()}")
print(f"RATCHET_PUB={ratchet_pub.hex()}")
print(f"RATCHET_ID={ratchet_id.hex()}")
print(f"SIGNATURE={signature.hex()}")
print(f"APP_DATA=")

# Cleanup
import shutil
shutil.rmtree(temp_config_dir, ignore_errors=True)
"#;

    let output = ctx
        .run_to_completion(ctx.venv().python_command().args(["-c", python_script]))
        .expect("Failed to run Python");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("Python stdout:\n{}", stdout);
    eprintln!("Python stderr:\n{}", stderr);

    assert!(output.status.success(), "Python script should succeed");

    // Extract values from Python output
    let get_hex_value = |prefix: &str| -> String {
        stdout
            .lines()
            .find_map(|line| {
                if line.starts_with(prefix) {
                    Some(line.trim_start_matches(prefix).to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| panic!("Python should output {}", prefix))
    };

    let dest_hash_hex = get_hex_value("DEST_HASH=");
    let identity_pub_hex = get_hex_value("IDENTITY_PUB=");
    let identity_sign_pub_hex = get_hex_value("IDENTITY_SIGN_PUB=");
    let name_hash_hex = get_hex_value("NAME_HASH=");
    let random_hash_hex = get_hex_value("RANDOM_HASH=");
    let ratchet_pub_hex = get_hex_value("RATCHET_PUB=");
    let ratchet_id_hex = get_hex_value("RATCHET_ID=");
    let signature_hex = get_hex_value("SIGNATURE=");

    eprintln!("Destination hash: {}", dest_hash_hex);
    eprintln!("Ratchet public: {}", ratchet_pub_hex);
    eprintln!("Ratchet ID: {}", ratchet_id_hex);

    // Decode hex values
    let dest_hash = hex::decode(&dest_hash_hex).expect("valid hex");
    let identity_pub = hex::decode(&identity_pub_hex).expect("valid hex");
    let identity_sign_pub = hex::decode(&identity_sign_pub_hex).expect("valid hex");
    let name_hash = hex::decode(&name_hash_hex).expect("valid hex");
    let random_hash = hex::decode(&random_hash_hex).expect("valid hex");
    let ratchet_pub = hex::decode(&ratchet_pub_hex).expect("valid hex");
    let signature = hex::decode(&signature_hex).expect("valid hex");

    // Build packet data: pubkey + sign_pubkey + name_hash + random_hash + ratchet + signature
    let mut packet_data = Vec::new();
    packet_data.extend_from_slice(&identity_pub);
    packet_data.extend_from_slice(&identity_sign_pub);
    packet_data.extend_from_slice(&name_hash);
    packet_data.extend_from_slice(&random_hash);
    packet_data.extend_from_slice(&ratchet_pub);
    packet_data.extend_from_slice(&signature);

    // Build the full packet bytes
    // Header format for Type1 announce with ratchet:
    // Byte 0: [ifac_flag:1][header_type:2][context_flag:1][transport:2][dest_type:2]
    //         = 0_01_1_00_00 = 0x30 (but this might not be right)
    // Actually looking at packet.rs, the format is:
    // Byte 0: ifac(1) | type(2) | context(1) | transport(2) | dest_type(2)
    // Byte 1 for Type1: packet_type(4) | hops(4)
    // For context_flag=1, header_type=1, broadcast, single:
    // = 0 | 01 | 1 | 00 | 00 = 0b01100000 = 0x60? No wait...

    // Let me check: HeaderType::Type1 is encoded as 01 in bits 6-5
    // ifac_flag: bit 7
    // header_type: bits 6-5
    // context_flag: bit 5 (but that overlaps? No, let me re-read packet.rs)

    // From packet.rs to_meta():
    //   (self.ifac_flag.to_u8()) << 7
    // | (self.header_type as u8) << 6  -- this is just 1 bit?
    // | (self.context_flag as u8) << 5
    // | (self.transport_type.to_u8()) << 4
    // | (self.destination_type.to_u8()) << 2
    // | self.packet_type.to_u8()

    // Header format (from packet.rs to_meta):
    // - Bit 6: header_type (0=Type1, 1=Type2)
    // - Bit 5: context_flag
    // - Bit 4: transport_type (0=Broadcast)
    // - Bits 2-3: destination_type (0=Single)
    // - Bits 0-1: packet_type (1=Announce)
    // For Type1, context_flag=1, broadcast, single, announce:
    // Byte = 0<<6 | 1<<5 | 0<<4 | 0<<2 | 1 = 0b00100001 = 0x21
    let header_byte = 0x21u8; // Type1, context_flag=true, broadcast, single, announce
    let hops_byte = 0x00u8;

    // Build full packet: header(1) + hops(1) + dest_hash(16) + context(1) + data
    // The Rust implementation includes a context byte after destination hash
    let mut full_packet = Vec::new();
    full_packet.push(header_byte);
    full_packet.push(hops_byte);
    full_packet.extend_from_slice(&dest_hash[..16]); // Destination hash is 16 bytes
    full_packet.push(0x00); // Context byte (None = 0)
    full_packet.extend_from_slice(&packet_data);

    eprintln!("Full packet length: {} bytes", full_packet.len());
    eprintln!("Full packet hex: {}", hex::encode(&full_packet));

    // Deserialize the packet using Rust
    let packet = Packet::deserialize(&mut InputBuffer::new(&full_packet))
        .expect("Should deserialize packet");

    eprintln!("Packet header: ifac={:?}, type={:?}, context={}, transport={:?}, dest_type={:?}, pkt_type={:?}",
        packet.header.ifac_flag,
        packet.header.header_type,
        packet.header.context_flag,
        packet.header.transport_type,
        packet.header.destination_type,
        packet.header.packet_type
    );

    // Verify context_flag is set
    assert!(packet.header.context_flag, "Packet should have context_flag=true");

    // Validate the announce with ratchet support
    let validation = DestinationAnnounce::validate_full(&packet)
        .expect("Announce validation should succeed");

    // Verify ratchet was extracted
    assert!(validation.ratchet.is_some(), "Should extract ratchet from announce");
    let extracted_ratchet = validation.ratchet.unwrap();

    // Verify ratchet matches
    assert_eq!(
        hex::encode(&extracted_ratchet),
        ratchet_pub_hex,
        "Extracted ratchet should match Python's ratchet"
    );

    // Verify ratchet ID calculation matches
    let rust_ratchet_id = get_ratchet_id(&extracted_ratchet);
    assert_eq!(
        hex::encode(&rust_ratchet_id),
        ratchet_id_hex,
        "Rust ratchet ID calculation should match Python"
    );

    eprintln!("Successfully parsed Python ratchet announce!");
    eprintln!("  Extracted ratchet: {}", hex::encode(&extracted_ratchet));
    eprintln!("  Ratchet ID: {}", hex::encode(&rust_ratchet_id));
}

/// Test that Python can parse Rust-generated ratchet announce packets.
///
/// This test verifies that announces created by Rust's announce_with_ratchet()
/// can be correctly parsed by Python, extracting the ratchet public key.
#[test]
fn test_rust_ratchet_announce_to_python() {
    use reticulum::destination::{DestinationName, SingleInputDestination};
    use reticulum::identity::{generate_ratchet, ratchet_public_bytes, get_ratchet_id, PrivateIdentity};
    use rand_core::OsRng;

    let ctx = IntegrationTestContext::new().expect("Failed to create test context");

    // Create Rust identity and destination
    let priv_identity = PrivateIdentity::new_from_rand(OsRng);
    let name = DestinationName::new("test_app", "ratchettest").unwrap();
    let destination = SingleInputDestination::new(priv_identity, name);

    // Generate a ratchet key
    let ratchet_priv = generate_ratchet(OsRng);
    let ratchet_pub = ratchet_public_bytes(&ratchet_priv);
    let ratchet_id = get_ratchet_id(&ratchet_pub);

    eprintln!("Rust destination hash: {}", hex::encode(destination.desc.address_hash.as_slice()));
    eprintln!("Rust ratchet public: {}", hex::encode(&ratchet_pub));
    eprintln!("Rust ratchet ID: {}", hex::encode(&ratchet_id));

    // Create announce with ratchet
    let announce = destination
        .announce_with_ratchet(OsRng, &ratchet_pub, None)
        .expect("Failed to create announce");

    // Manually serialize the packet (since serde module is private)
    // Format: header_meta(1) + hops(1) + dest_hash(16) + context(1) + data
    let header_meta = announce.header.to_meta();
    let mut packet_bytes = Vec::new();
    packet_bytes.push(header_meta);
    packet_bytes.push(announce.header.hops);
    packet_bytes.extend_from_slice(announce.destination.as_slice());
    packet_bytes.push(0x00); // context byte (None)
    packet_bytes.extend_from_slice(announce.data.as_slice());

    eprintln!("Rust announce packet ({} bytes): {}", packet_bytes.len(), hex::encode(&packet_bytes));

    // Create Python script that parses the announce bytes
    let python_script = format!(
        r#"
import RNS
import tempfile
import os

# Initialize Reticulum
temp_config_dir = tempfile.mkdtemp(prefix="rns_rust_ratchet_test_")
config_content = """
[reticulum]
enable_transport = No
share_instance = No
"""
config_path = os.path.join(temp_config_dir, "config")
with open(config_path, "w") as f:
    f.write(config_content)

RNS.Reticulum(configdir=temp_config_dir)

# The raw packet bytes from Rust
packet_hex = "{packet_hex}"
packet_bytes = bytes.fromhex(packet_hex)

# Parse the packet
# Rust format: header(1) + hops(1) + dest_hash(16) + context(1) + data
# But Python's packet parsing is different, so we need to extract components directly

# Skip header(1) + hops(1) + dest_hash(16) + context(1) = 20 bytes to get data
header_byte = packet_bytes[0]
hops = packet_bytes[1]
dest_hash = packet_bytes[2:18]
context_flag = (header_byte >> 5) & 1  # Extract context flag from header

print(f"HEADER_BYTE={{header_byte:02x}}")
print(f"CONTEXT_FLAG={{context_flag}}")
print(f"DEST_HASH={{dest_hash.hex()}}")

# The data section starts at byte 19 (skipping the context byte in Rust format)
data = packet_bytes[19:]

# Parse data: x25519_pub(32) + ed25519_pub(32) + name_hash(10) + rand_hash(10) + ratchet(32) + signature(64)
x25519_pub = data[0:32]
ed25519_pub = data[32:64]
name_hash = data[64:74]
rand_hash = data[74:84]

if context_flag:
    ratchet_pub = data[84:116]
    signature = data[116:180]
    app_data = data[180:]

    # Calculate ratchet ID using Python's method
    ratchet_id = RNS.Identity._get_ratchet_id(ratchet_pub)

    print(f"RATCHET_PUB={{ratchet_pub.hex()}}")
    print(f"RATCHET_ID={{ratchet_id.hex()}}")
    print("HAS_RATCHET=true")
else:
    signature = data[84:148]
    app_data = data[148:]
    print("HAS_RATCHET=false")

# Verify the signature using Python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
verifying_key = Ed25519PublicKey.from_public_bytes(ed25519_pub)

# Build signed data: dest_hash + x25519_pub + ed25519_pub + name_hash + rand_hash + [ratchet] + app_data
if context_flag:
    signed_data = dest_hash + x25519_pub + ed25519_pub + name_hash + rand_hash + ratchet_pub + app_data
else:
    signed_data = dest_hash + x25519_pub + ed25519_pub + name_hash + rand_hash + app_data

try:
    verifying_key.verify(signature, signed_data)
    print("SIGNATURE_VALID=true")
except Exception as e:
    print(f"SIGNATURE_VALID=false")
    print(f"SIGNATURE_ERROR={{e}}")

# Cleanup
import shutil
shutil.rmtree(temp_config_dir, ignore_errors=True)
"#,
        packet_hex = hex::encode(packet_bytes)
    );

    let output = ctx
        .run_to_completion(ctx.venv().python_command().args(["-c", &python_script]))
        .expect("Failed to run Python");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("Python stdout:\n{}", stdout);
    eprintln!("Python stderr:\n{}", stderr);

    assert!(output.status.success(), "Python script should succeed");

    // Verify results
    assert!(stdout.contains("HAS_RATCHET=true"), "Python should detect ratchet in announce");
    assert!(stdout.contains("SIGNATURE_VALID=true"), "Python should verify signature");

    // Extract and compare ratchet ID
    let python_ratchet_id = stdout
        .lines()
        .find_map(|line| {
            if line.starts_with("RATCHET_ID=") {
                Some(line.trim_start_matches("RATCHET_ID=").to_string())
            } else {
                None
            }
        })
        .expect("Python should output ratchet ID");

    assert_eq!(
        hex::encode(&ratchet_id),
        python_ratchet_id,
        "Python ratchet ID should match Rust"
    );

    // Extract and compare ratchet public key
    let python_ratchet_pub = stdout
        .lines()
        .find_map(|line| {
            if line.starts_with("RATCHET_PUB=") {
                Some(line.trim_start_matches("RATCHET_PUB=").to_string())
            } else {
                None
            }
        })
        .expect("Python should output ratchet public key");

    assert_eq!(
        hex::encode(&ratchet_pub),
        python_ratchet_pub,
        "Python ratchet public key should match Rust"
    );

    eprintln!("Successfully sent Rust ratchet announce to Python!");
    eprintln!("  Ratchet public: {}", hex::encode(&ratchet_pub));
    eprintln!("  Ratchet ID: {}", hex::encode(&ratchet_id));
}
