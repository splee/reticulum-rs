//! Pickle protocol handler for Python RPC compatibility.
//!
//! This module handles conversion between Python's dict-based RPC format and
//! the Rust type system. Python RNS uses simple dict messages like:
//!
//! ```python
//! # Requests
//! {"get": "interface_stats"}
//! {"get": "path_table", "max_hops": 5}
//! {"drop": "path", "destination_hash": b'\x...'}
//! {"blackhole_identity": b'\x...', "until": 1234567890.0, "reason": "spam"}
//!
//! # Responses are arbitrary Python objects (dicts, lists, etc.)
//! {"interfaces": [...], "rxb": 12345, "txb": 67890}
//! ```
//!
//! The `serde_pickle::Value` type is used for dynamic handling of the loosely-typed
//! Python dict format, with conversion to/from the strongly-typed Rust `RpcRequest`
//! and `RpcResponse` types.

use serde_pickle::Value as PickleValue;
use std::collections::BTreeMap;

use super::protocol::{
    BlackholeEntry, DiscoveredInterfaceEntry, InterfaceStats, NextHopInfo, PathEntry, RpcRequest,
    RpcResponse, RpcResult,
};

/// Error type for pickle protocol conversion.
#[derive(Debug)]
pub enum PickleProtocolError {
    /// Missing required field in request.
    MissingField(String),
    /// Invalid field type.
    InvalidType { field: String, expected: String },
    /// Unknown request type.
    UnknownRequest(String),
    /// Serialization error.
    Serialization(String),
    /// Deserialization error.
    Deserialization(String),
}

impl std::fmt::Display for PickleProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PickleProtocolError::MissingField(field) => {
                write!(f, "Missing required field: {}", field)
            }
            PickleProtocolError::InvalidType { field, expected } => {
                write!(f, "Invalid type for field '{}': expected {}", field, expected)
            }
            PickleProtocolError::UnknownRequest(req) => {
                write!(f, "Unknown request type: {}", req)
            }
            PickleProtocolError::Serialization(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            PickleProtocolError::Deserialization(msg) => {
                write!(f, "Deserialization error: {}", msg)
            }
        }
    }
}

impl std::error::Error for PickleProtocolError {}

/// Parse an RPC request from a pickle-encoded dict.
///
/// # Arguments
/// * `data` - The raw pickle bytes
///
/// # Returns
/// * `Ok(RpcRequest)` on success
/// * `Err(PickleProtocolError)` if the request is malformed
pub fn parse_request(data: &[u8]) -> Result<RpcRequest, PickleProtocolError> {
    let value: PickleValue = serde_pickle::from_slice(data, serde_pickle::DeOptions::new())
        .map_err(|e| PickleProtocolError::Deserialization(e.to_string()))?;

    let dict = match value {
        PickleValue::Dict(d) => d,
        _ => {
            return Err(PickleProtocolError::InvalidType {
                field: "request".to_string(),
                expected: "dict".to_string(),
            })
        }
    };

    // Convert BTreeMap<HashableValue, Value> to a more usable form
    let map = btree_to_string_map(&dict);

    // Check for "get" requests
    if let Some(path) = map.get("get").and_then(|v| value_to_string(v)) {
        return parse_get_request(&path, &map);
    }

    // Check for "drop" requests
    if let Some(path) = map.get("drop").and_then(|v| value_to_string(v)) {
        return parse_drop_request(&path, &map);
    }

    // Check for "blackhole_identity" request
    if let Some(identity_bytes) = map.get("blackhole_identity").and_then(|v| value_to_bytes(v)) {
        let until = map
            .get("until")
            .and_then(|v| value_to_f64(v))
            .unwrap_or(0.0);
        let reason = map
            .get("reason")
            .and_then(|v| value_to_string(v))
            .unwrap_or_default();
        return Ok(RpcRequest::BlackholeIdentity {
            identity_hash: identity_bytes,
            until,
            reason,
        });
    }

    // Check for "unblackhole_identity" request
    if let Some(identity_bytes) = map.get("unblackhole_identity").and_then(|v| value_to_bytes(v)) {
        return Ok(RpcRequest::UnblackholeIdentity {
            identity_hash: identity_bytes,
        });
    }

    Err(PickleProtocolError::UnknownRequest(
        "No recognized request type found".to_string(),
    ))
}

/// Parse a "get" request.
fn parse_get_request(
    path: &str,
    map: &std::collections::HashMap<String, &PickleValue>,
) -> Result<RpcRequest, PickleProtocolError> {
    match path {
        "interface_stats" => Ok(RpcRequest::GetInterfaceStats),

        "path_table" => {
            let max_hops = map.get("max_hops").and_then(|v| value_to_u32(v));
            Ok(RpcRequest::GetPathTable { max_hops })
        }

        "rate_table" => Ok(RpcRequest::GetRateTable),

        "next_hop_if_name" | "next_hop" => {
            let destination_hash = map
                .get("destination_hash")
                .and_then(|v| value_to_bytes(v))
                .ok_or_else(|| PickleProtocolError::MissingField("destination_hash".to_string()))?;
            Ok(RpcRequest::GetNextHop { destination_hash })
        }

        "first_hop_timeout" => {
            let destination_hash = map
                .get("destination_hash")
                .and_then(|v| value_to_bytes(v))
                .ok_or_else(|| PickleProtocolError::MissingField("destination_hash".to_string()))?;
            Ok(RpcRequest::GetFirstHopTimeout { destination_hash })
        }

        "link_count" => Ok(RpcRequest::GetLinkCount),

        "packet_rssi" | "packet_snr" | "packet_q" => {
            // These are packet-specific queries not fully implemented yet
            // Return a ping for now as a placeholder
            Ok(RpcRequest::Ping)
        }

        "blackholed_identities" => Ok(RpcRequest::GetBlackholeIdentities),

        _ => Err(PickleProtocolError::UnknownRequest(format!(
            "get: {}",
            path
        ))),
    }
}

/// Parse a "drop" request.
fn parse_drop_request(
    path: &str,
    map: &std::collections::HashMap<String, &PickleValue>,
) -> Result<RpcRequest, PickleProtocolError> {
    match path {
        "path" => {
            let destination_hash = map
                .get("destination_hash")
                .and_then(|v| value_to_bytes(v))
                .ok_or_else(|| PickleProtocolError::MissingField("destination_hash".to_string()))?;
            Ok(RpcRequest::DropPath { destination_hash })
        }

        "all_via" => {
            let destination_hash = map
                .get("destination_hash")
                .and_then(|v| value_to_bytes(v))
                .ok_or_else(|| PickleProtocolError::MissingField("destination_hash".to_string()))?;
            Ok(RpcRequest::DropAllVia { destination_hash })
        }

        "announce_queues" => Ok(RpcRequest::DropAnnounceQueues),

        _ => Err(PickleProtocolError::UnknownRequest(format!(
            "drop: {}",
            path
        ))),
    }
}

/// Serialize an RPC response to pickle format.
///
/// Python expects responses to be the raw return value (not wrapped in Success/Error).
/// For example, `get_interface_stats()` returns the stats dict directly.
///
/// # Arguments
/// * `response` - The RPC response to serialize
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the pickled response
/// * `Err(PickleProtocolError)` on serialization failure
pub fn serialize_response(response: &RpcResponse) -> Result<Vec<u8>, PickleProtocolError> {
    let value = response_to_pickle_value(response);
    serde_pickle::value_to_vec(&value, serde_pickle::SerOptions::new())
        .map_err(|e| PickleProtocolError::Serialization(e.to_string()))
}

/// Convert an RpcResponse to a PickleValue for serialization.
fn response_to_pickle_value(response: &RpcResponse) -> PickleValue {
    match response {
        RpcResponse::Success(result) => result_to_pickle_value(result),
        RpcResponse::Error(_msg) => {
            // Return None for errors (Python handles this differently)
            // In practice, errors cause exceptions in Python, not returned values
            PickleValue::None
        }
    }
}

/// Convert an RpcResult to a PickleValue.
fn result_to_pickle_value(result: &RpcResult) -> PickleValue {
    match result {
        RpcResult::Ok => PickleValue::Bool(true),
        RpcResult::Pong => PickleValue::Bool(true),
        RpcResult::Bool(b) => PickleValue::Bool(*b),
        RpcResult::Count(n) => PickleValue::I64(*n as i64),
        RpcResult::Float(f) => PickleValue::F64(*f),
        RpcResult::PathTable(paths) => path_table_to_pickle(paths),
        RpcResult::InterfaceStats(stats) => interface_stats_to_pickle(stats),
        RpcResult::RateTable(table) => rate_table_to_pickle(table),
        RpcResult::NextHop(info) => next_hop_to_pickle(info),
        RpcResult::BlackholeList(entries) => blackhole_list_to_pickle(entries),
        RpcResult::DiscoveredInterfaces(interfaces) => discovered_interfaces_to_pickle(interfaces),
    }
}

/// Convert path table to pickle-compatible format.
fn path_table_to_pickle(paths: &[PathEntry]) -> PickleValue {
    let list: Vec<PickleValue> = paths
        .iter()
        .map(|entry| {
            let mut dict = BTreeMap::new();
            // Use bytes for hash to match Python
            dict.insert(
                hashable_str("hash"),
                PickleValue::Bytes(hex::decode(&entry.destination_hash).unwrap_or_default()),
            );
            dict.insert(hashable_str("hops"), PickleValue::I64(entry.hops as i64));
            dict.insert(hashable_str("expires"), PickleValue::F64(entry.expires));
            dict.insert(
                hashable_str("interface"),
                PickleValue::String(entry.interface.clone()),
            );
            if let Some(ref via) = entry.via {
                dict.insert(
                    hashable_str("via"),
                    PickleValue::Bytes(hex::decode(via).unwrap_or_default()),
                );
            }
            PickleValue::Dict(dict)
        })
        .collect();
    PickleValue::List(list)
}

/// Convert interface stats to pickle-compatible format matching Python's format.
fn interface_stats_to_pickle(stats: &[InterfaceStats]) -> PickleValue {
    let interfaces: Vec<PickleValue> = stats
        .iter()
        .map(|s| {
            let mut dict = BTreeMap::new();
            dict.insert(
                hashable_str("name"),
                PickleValue::String(s.name.clone()),
            );
            dict.insert(
                hashable_str("type"),
                PickleValue::String(s.interface_type.clone()),
            );
            dict.insert(hashable_str("status"), PickleValue::Bool(s.online));
            dict.insert(hashable_str("rxb"), PickleValue::I64(s.rx_bytes as i64));
            dict.insert(hashable_str("txb"), PickleValue::I64(s.tx_bytes as i64));
            if let Some(bitrate) = s.bitrate {
                dict.insert(hashable_str("bitrate"), PickleValue::I64(bitrate as i64));
            }
            PickleValue::Dict(dict)
        })
        .collect();

    // Return as dict with "interfaces" key to match Python format
    let mut result = BTreeMap::new();
    result.insert(hashable_str("interfaces"), PickleValue::List(interfaces));
    // Add total stats (placeholder values for now)
    result.insert(hashable_str("rxb"), PickleValue::I64(0));
    result.insert(hashable_str("txb"), PickleValue::I64(0));
    PickleValue::Dict(result)
}

/// Convert rate table to pickle-compatible format.
fn rate_table_to_pickle(table: &std::collections::HashMap<String, u64>) -> PickleValue {
    let list: Vec<PickleValue> = table
        .iter()
        .map(|(hash, rate)| {
            let mut dict = BTreeMap::new();
            dict.insert(
                hashable_str("hash"),
                PickleValue::Bytes(hex::decode(hash).unwrap_or_default()),
            );
            dict.insert(hashable_str("rate"), PickleValue::I64(*rate as i64));
            PickleValue::Dict(dict)
        })
        .collect();
    PickleValue::List(list)
}

/// Convert next hop info to pickle-compatible format.
fn next_hop_to_pickle(info: &Option<NextHopInfo>) -> PickleValue {
    match info {
        Some(hop) => {
            if let Some(ref via) = hop.via {
                PickleValue::Bytes(hex::decode(via).unwrap_or_default())
            } else {
                PickleValue::None
            }
        }
        None => PickleValue::None,
    }
}

/// Convert blackhole list to pickle-compatible format.
fn blackhole_list_to_pickle(entries: &[BlackholeEntry]) -> PickleValue {
    let mut dict = BTreeMap::new();
    for entry in entries {
        let hash_bytes = hex::decode(&entry.identity_hash).unwrap_or_default();
        let mut entry_dict = BTreeMap::new();
        entry_dict.insert(hashable_str("until"), PickleValue::F64(entry.until));
        entry_dict.insert(
            hashable_str("reason"),
            PickleValue::String(entry.reason.clone()),
        );
        dict.insert(
            serde_pickle::HashableValue::Bytes(hash_bytes),
            PickleValue::Dict(entry_dict),
        );
    }
    PickleValue::Dict(dict)
}

/// Convert discovered interfaces to pickle-compatible format.
fn discovered_interfaces_to_pickle(interfaces: &[DiscoveredInterfaceEntry]) -> PickleValue {
    let list: Vec<PickleValue> = interfaces
        .iter()
        .map(|iface| {
            let mut dict = BTreeMap::new();
            dict.insert(
                hashable_str("name"),
                PickleValue::String(iface.name.clone()),
            );
            dict.insert(
                hashable_str("type"),
                PickleValue::String(iface.interface_type.clone()),
            );
            dict.insert(
                hashable_str("status"),
                PickleValue::String(iface.status.clone()),
            );
            dict.insert(
                hashable_str("transport"),
                PickleValue::Bool(iface.transport),
            );
            dict.insert(hashable_str("hops"), PickleValue::I64(iface.hops as i64));
            dict.insert(
                hashable_str("discovered"),
                PickleValue::F64(iface.discovered),
            );
            dict.insert(
                hashable_str("last_heard"),
                PickleValue::F64(iface.last_heard),
            );
            PickleValue::Dict(dict)
        })
        .collect();
    PickleValue::List(list)
}

// === Helper functions for type conversion ===

/// Create a hashable string value for dict keys.
fn hashable_str(s: &str) -> serde_pickle::HashableValue {
    serde_pickle::HashableValue::String(s.to_string())
}

/// Convert a BTreeMap<HashableValue, Value> to HashMap<String, &Value>.
fn btree_to_string_map<'a>(
    dict: &'a BTreeMap<serde_pickle::HashableValue, PickleValue>,
) -> std::collections::HashMap<String, &'a PickleValue> {
    let mut map = std::collections::HashMap::new();
    for (k, v) in dict {
        if let serde_pickle::HashableValue::String(s) = k {
            map.insert(s.clone(), v);
        }
    }
    map
}

/// Extract a string from a PickleValue.
fn value_to_string(v: &PickleValue) -> Option<String> {
    match v {
        PickleValue::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Extract bytes from a PickleValue.
fn value_to_bytes(v: &PickleValue) -> Option<Vec<u8>> {
    match v {
        PickleValue::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

/// Extract an f64 from a PickleValue.
fn value_to_f64(v: &PickleValue) -> Option<f64> {
    match v {
        PickleValue::F64(f) => Some(*f),
        PickleValue::I64(i) => Some(*i as f64),
        _ => None,
    }
}

/// Extract a u32 from a PickleValue.
fn value_to_u32(v: &PickleValue) -> Option<u32> {
    match v {
        PickleValue::I64(i) if *i >= 0 && *i <= u32::MAX as i64 => Some(*i as u32),
        PickleValue::None => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_interface_stats() {
        // Create pickle bytes for {"get": "interface_stats"}
        let mut dict = BTreeMap::new();
        dict.insert(
            serde_pickle::HashableValue::String("get".to_string()),
            PickleValue::String("interface_stats".to_string()),
        );
        let data =
            serde_pickle::value_to_vec(&PickleValue::Dict(dict), serde_pickle::SerOptions::new())
                .unwrap();

        let request = parse_request(&data).unwrap();
        assert!(matches!(request, RpcRequest::GetInterfaceStats));
    }

    #[test]
    fn test_parse_get_path_table() {
        let mut dict = BTreeMap::new();
        dict.insert(
            serde_pickle::HashableValue::String("get".to_string()),
            PickleValue::String("path_table".to_string()),
        );
        dict.insert(
            serde_pickle::HashableValue::String("max_hops".to_string()),
            PickleValue::I64(5),
        );
        let data =
            serde_pickle::value_to_vec(&PickleValue::Dict(dict), serde_pickle::SerOptions::new())
                .unwrap();

        let request = parse_request(&data).unwrap();
        match request {
            RpcRequest::GetPathTable { max_hops } => {
                assert_eq!(max_hops, Some(5));
            }
            _ => panic!("Expected GetPathTable"),
        }
    }

    #[test]
    fn test_parse_drop_path() {
        let mut dict = BTreeMap::new();
        dict.insert(
            serde_pickle::HashableValue::String("drop".to_string()),
            PickleValue::String("path".to_string()),
        );
        dict.insert(
            serde_pickle::HashableValue::String("destination_hash".to_string()),
            PickleValue::Bytes(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        );
        let data =
            serde_pickle::value_to_vec(&PickleValue::Dict(dict), serde_pickle::SerOptions::new())
                .unwrap();

        let request = parse_request(&data).unwrap();
        match request {
            RpcRequest::DropPath { destination_hash } => {
                assert_eq!(destination_hash.len(), 16);
            }
            _ => panic!("Expected DropPath"),
        }
    }

    #[test]
    fn test_serialize_interface_stats() {
        let stats = vec![InterfaceStats {
            name: "TestInterface".to_string(),
            interface_type: "TCPClientInterface".to_string(),
            online: true,
            rx_packets: 100,
            tx_packets: 50,
            rx_bytes: 10000,
            tx_bytes: 5000,
            bitrate: Some(115200),
            address: "127.0.0.1:4242".to_string(),
        }];

        let response = RpcResponse::Success(RpcResult::InterfaceStats(stats));
        let data = serialize_response(&response).unwrap();

        // Verify we can deserialize it back
        let value: PickleValue =
            serde_pickle::from_slice(&data, serde_pickle::DeOptions::new()).unwrap();
        assert!(matches!(value, PickleValue::Dict(_)));
    }

    #[test]
    fn test_serialize_count() {
        let response = RpcResponse::Success(RpcResult::Count(42));
        let data = serialize_response(&response).unwrap();

        let value: PickleValue =
            serde_pickle::from_slice(&data, serde_pickle::DeOptions::new()).unwrap();
        assert!(matches!(value, PickleValue::I64(42)));
    }
}
