//! Test binary for packet encoding/decoding interoperability.
//!
//! This binary provides a stdin-based interface for encoding and decoding
//! Reticulum packets, allowing Python-Rust cross-validation of the wire format.
//!
//! ## Commands
//!
//! ### Encode
//! ```
//! encode <json>
//! ```
//! Encodes packet fields into raw bytes. JSON fields:
//! - header_type: 0 (Type1) or 1 (Type2)
//! - context_flag: false or true
//! - transport_type: 0 (Broadcast) or 1 (Transport)
//! - destination_type: 0 (Single), 1 (Group), 2 (Plain), 3 (Link)
//! - packet_type: 0 (Data), 1 (Announce), 2 (LinkRequest), 3 (Proof)
//! - hops: 0-255
//! - destination: hex string (16 bytes)
//! - transport_id: hex string (16 bytes, optional, required for Type2)
//! - context: 0-255
//! - data: hex string
//!
//! Output: RAW_BYTES=<hex>, META_BYTE=<hex>
//!
//! ### Decode
//! ```
//! decode <hex>
//! ```
//! Decodes raw packet bytes and outputs the parsed fields.
//!
//! Output: HEADER_TYPE=<n>, CONTEXT_FLAG=<0|1>, ...

use std::io::{self, BufRead, Write as IoWrite};

use reticulum::packet::{
    DestinationType, Header, HeaderType, PacketType, TransportType,
    PACKET_MDU,
};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("ERROR: Failed to read line: {}", e);
                continue;
            }
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse command
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.is_empty() {
            eprintln!("ERROR: Empty command");
            continue;
        }

        let cmd = parts[0];
        let arg = parts.get(1).copied().unwrap_or("");

        match cmd {
            "encode" => {
                if let Err(e) = handle_encode(arg, &mut stdout) {
                    writeln!(stdout, "ERROR={}", e).ok();
                }
            }
            "decode" => {
                if let Err(e) = handle_decode(arg, &mut stdout) {
                    writeln!(stdout, "ERROR={}", e).ok();
                }
            }
            "meta_encode" => {
                // Encode just the meta byte from JSON
                if let Err(e) = handle_meta_encode(arg, &mut stdout) {
                    writeln!(stdout, "ERROR={}", e).ok();
                }
            }
            "meta_decode" => {
                // Decode just a meta byte
                if let Err(e) = handle_meta_decode(arg, &mut stdout) {
                    writeln!(stdout, "ERROR={}", e).ok();
                }
            }
            _ => {
                writeln!(stdout, "ERROR=Unknown command: {}", cmd).ok();
            }
        }
        stdout.flush().ok();
    }
}

/// Handle the encode command.
/// Input: JSON with packet fields
/// Output: RAW_BYTES=<hex>, META_BYTE=<hex>
fn handle_encode(json_str: &str, out: &mut impl IoWrite) -> Result<(), String> {
    let json: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON: {}", e))?;

    // Parse header fields
    let header_type = match json.get("header_type").and_then(|v| v.as_u64()) {
        Some(0) => HeaderType::Type1,
        Some(1) => HeaderType::Type2,
        _ => HeaderType::Type1,
    };

    let context_flag = json
        .get("context_flag")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let transport_type = match json.get("transport_type").and_then(|v| v.as_u64()) {
        Some(0) => TransportType::Broadcast,
        Some(1) => TransportType::Transport,
        _ => TransportType::Broadcast,
    };

    let destination_type = match json.get("destination_type").and_then(|v| v.as_u64()) {
        Some(0) => DestinationType::Single,
        Some(1) => DestinationType::Group,
        Some(2) => DestinationType::Plain,
        Some(3) => DestinationType::Link,
        _ => DestinationType::Single,
    };

    let packet_type = match json.get("packet_type").and_then(|v| v.as_u64()) {
        Some(0) => PacketType::Data,
        Some(1) => PacketType::Announce,
        Some(2) => PacketType::LinkRequest,
        Some(3) => PacketType::Proof,
        _ => PacketType::Data,
    };

    let hops = json.get("hops").and_then(|v| v.as_u64()).unwrap_or(0) as u8;

    let context_val = json.get("context").and_then(|v| v.as_u64()).unwrap_or(0) as u8;

    // Parse destination (16 bytes hex)
    let dest_hex = json
        .get("destination")
        .and_then(|v| v.as_str())
        .unwrap_or("00000000000000000000000000000000");
    let dest_bytes = hex::decode(dest_hex).map_err(|e| format!("Invalid destination hex: {}", e))?;
    if dest_bytes.len() != 16 {
        return Err(format!(
            "Destination must be 16 bytes, got {}",
            dest_bytes.len()
        ));
    }

    // Parse transport_id (optional, 16 bytes hex for Type2)
    let transport_bytes = if header_type == HeaderType::Type2 {
        let transport_hex = json
            .get("transport_id")
            .and_then(|v| v.as_str())
            .ok_or("Type2 header requires transport_id")?;
        let bytes =
            hex::decode(transport_hex).map_err(|e| format!("Invalid transport_id hex: {}", e))?;
        if bytes.len() != 16 {
            return Err(format!(
                "Transport ID must be 16 bytes, got {}",
                bytes.len()
            ));
        }
        Some(bytes)
    } else {
        None
    };

    // Parse data (hex)
    let data_hex = json.get("data").and_then(|v| v.as_str()).unwrap_or("");
    let data_bytes = hex::decode(data_hex).map_err(|e| format!("Invalid data hex: {}", e))?;

    // Build header
    let header = Header {
        ifac_flag: reticulum::packet::IfacFlag::Open,
        header_type,
        context_flag,
        transport_type,
        destination_type,
        packet_type,
        hops,
    };

    // Manually serialize packet (same as serde module)
    let mut raw_bytes = Vec::with_capacity(PACKET_MDU);

    // Header: [meta_byte][hops]
    raw_bytes.push(header.to_meta());
    raw_bytes.push(hops);

    // For Type2, add transport_id before destination
    if header_type == HeaderType::Type2 {
        if let Some(ref transport) = transport_bytes {
            raw_bytes.extend_from_slice(transport);
        }
    }

    // Destination (16 bytes)
    raw_bytes.extend_from_slice(&dest_bytes);

    // Context (1 byte)
    raw_bytes.push(context_val);

    // Data
    raw_bytes.extend_from_slice(&data_bytes);

    let meta_byte = header.to_meta();

    writeln!(out, "RAW_BYTES={}", hex::encode(&raw_bytes)).ok();
    writeln!(out, "META_BYTE={:02x}", meta_byte).ok();
    writeln!(out, "STATUS=OK").ok();

    Ok(())
}

/// Handle the decode command.
/// Input: hex-encoded raw packet bytes
/// Output: parsed fields
fn handle_decode(hex_str: &str, out: &mut impl IoWrite) -> Result<(), String> {
    let raw_bytes = hex::decode(hex_str.trim()).map_err(|e| format!("Invalid hex: {}", e))?;

    if raw_bytes.len() < 2 {
        return Err("Packet too short (minimum 2 bytes for header)".to_string());
    }

    // Manually deserialize packet (same as serde module)
    let meta_byte = raw_bytes[0];
    let hops = raw_bytes[1];

    // Parse header from meta byte
    let header = Header::from_meta(meta_byte);

    const DST_LEN: usize = 16;

    let (transport_id, destination, context, data) = if header.header_type == HeaderType::Type2 {
        // Type2: [meta][hops][transport_id(16)][dest(16)][context][data...]
        if raw_bytes.len() < 2 + DST_LEN + DST_LEN + 1 {
            return Err("Type2 packet too short".to_string());
        }
        let transport_id = &raw_bytes[2..2 + DST_LEN];
        let destination = &raw_bytes[2 + DST_LEN..2 + 2 * DST_LEN];
        let context = raw_bytes[2 + 2 * DST_LEN];
        let data = &raw_bytes[2 + 2 * DST_LEN + 1..];
        (Some(transport_id), destination, context, data)
    } else {
        // Type1: [meta][hops][dest(16)][context][data...]
        if raw_bytes.len() < 2 + DST_LEN + 1 {
            return Err("Type1 packet too short".to_string());
        }
        let destination = &raw_bytes[2..2 + DST_LEN];
        let context = raw_bytes[2 + DST_LEN];
        let data = &raw_bytes[2 + DST_LEN + 1..];
        (None, destination, context, data)
    };

    // Output all parsed fields
    writeln!(
        out,
        "HEADER_TYPE={}",
        match header.header_type {
            HeaderType::Type1 => 0,
            HeaderType::Type2 => 1,
        }
    )
    .ok();
    writeln!(out, "CONTEXT_FLAG={}", if header.context_flag { 1 } else { 0 }).ok();
    writeln!(
        out,
        "TRANSPORT_TYPE={}",
        match header.transport_type {
            TransportType::Broadcast => 0,
            TransportType::Transport => 1,
        }
    )
    .ok();
    writeln!(
        out,
        "DESTINATION_TYPE={}",
        match header.destination_type {
            DestinationType::Single => 0,
            DestinationType::Group => 1,
            DestinationType::Plain => 2,
            DestinationType::Link => 3,
        }
    )
    .ok();
    writeln!(
        out,
        "PACKET_TYPE={}",
        match header.packet_type {
            PacketType::Data => 0,
            PacketType::Announce => 1,
            PacketType::LinkRequest => 2,
            PacketType::Proof => 3,
        }
    )
    .ok();
    writeln!(out, "HOPS={}", hops).ok();
    writeln!(out, "CONTEXT={}", context).ok();
    writeln!(out, "DESTINATION={}", hex::encode(destination)).ok();

    if let Some(transport) = transport_id {
        writeln!(out, "TRANSPORT_ID={}", hex::encode(transport)).ok();
    }

    writeln!(out, "DATA={}", hex::encode(data)).ok();
    writeln!(out, "META_BYTE={:02x}", meta_byte).ok();
    writeln!(out, "STATUS=OK").ok();

    Ok(())
}

/// Handle the meta_encode command.
/// Input: JSON with header fields
/// Output: META_BYTE=<hex>
fn handle_meta_encode(json_str: &str, out: &mut impl IoWrite) -> Result<(), String> {
    let json: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON: {}", e))?;

    let header_type = match json.get("header_type").and_then(|v| v.as_u64()) {
        Some(0) => HeaderType::Type1,
        Some(1) => HeaderType::Type2,
        _ => HeaderType::Type1,
    };

    let context_flag = json
        .get("context_flag")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let transport_type = match json.get("transport_type").and_then(|v| v.as_u64()) {
        Some(0) => TransportType::Broadcast,
        Some(1) => TransportType::Transport,
        _ => TransportType::Broadcast,
    };

    let destination_type = match json.get("destination_type").and_then(|v| v.as_u64()) {
        Some(0) => DestinationType::Single,
        Some(1) => DestinationType::Group,
        Some(2) => DestinationType::Plain,
        Some(3) => DestinationType::Link,
        _ => DestinationType::Single,
    };

    let packet_type = match json.get("packet_type").and_then(|v| v.as_u64()) {
        Some(0) => PacketType::Data,
        Some(1) => PacketType::Announce,
        Some(2) => PacketType::LinkRequest,
        Some(3) => PacketType::Proof,
        _ => PacketType::Data,
    };

    let header = Header {
        ifac_flag: reticulum::packet::IfacFlag::Open,
        header_type,
        context_flag,
        transport_type,
        destination_type,
        packet_type,
        hops: 0,
    };

    let meta_byte = header.to_meta();
    writeln!(out, "META_BYTE={:02x}", meta_byte).ok();
    writeln!(out, "STATUS=OK").ok();

    Ok(())
}

/// Handle the meta_decode command.
/// Input: hex-encoded meta byte (1-2 chars)
/// Output: parsed header fields
fn handle_meta_decode(hex_str: &str, out: &mut impl IoWrite) -> Result<(), String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("Invalid hex: {}", e))?;

    if bytes.is_empty() {
        return Err("Empty meta byte".to_string());
    }

    let meta_byte = bytes[0];
    let header = Header::from_meta(meta_byte);

    writeln!(
        out,
        "HEADER_TYPE={}",
        match header.header_type {
            HeaderType::Type1 => 0,
            HeaderType::Type2 => 1,
        }
    )
    .ok();
    writeln!(out, "CONTEXT_FLAG={}", if header.context_flag { 1 } else { 0 }).ok();
    writeln!(
        out,
        "TRANSPORT_TYPE={}",
        match header.transport_type {
            TransportType::Broadcast => 0,
            TransportType::Transport => 1,
        }
    )
    .ok();
    writeln!(
        out,
        "DESTINATION_TYPE={}",
        match header.destination_type {
            DestinationType::Single => 0,
            DestinationType::Group => 1,
            DestinationType::Plain => 2,
            DestinationType::Link => 3,
        }
    )
    .ok();
    writeln!(
        out,
        "PACKET_TYPE={}",
        match header.packet_type {
            PacketType::Data => 0,
            PacketType::Announce => 1,
            PacketType::LinkRequest => 2,
            PacketType::Proof => 3,
        }
    )
    .ok();
    writeln!(out, "META_BYTE={:02x}", meta_byte).ok();
    writeln!(out, "STATUS=OK").ok();

    Ok(())
}
