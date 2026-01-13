//! RPC module for daemon mode management queries.
//!
//! This module provides a simple RPC mechanism for CLI utilities to query
//! daemon state (interface statistics, path table, link count, etc.).
//!
//! ## Protocol
//!
//! The RPC interface is compatible with Python's `multiprocessing.connection`:
//! - HMAC-based mutual authentication (SHA256 or MD5 for legacy)
//! - Python pickle serialization for messages
//! - Signed 4-byte big-endian length prefix (8-byte extended for large messages)
//!
//! Each RPC call follows a connect → authenticate → send → receive → close pattern.
//!
//! ## Modules
//!
//! - `auth` - HMAC authentication handshake
//! - `framing` - Python-compatible message framing
//! - `protocol` - RPC request/response type definitions
//! - `client` - RPC client for connecting to daemon
//! - `server` - RPC server for daemon mode

pub mod auth;
pub mod client;
pub mod framing;
pub mod pickle_protocol;
pub mod protocol;
pub mod server;

pub use auth::{client_authenticate, server_authenticate, AuthError};
pub use client::RpcClient;
pub use pickle_protocol::{parse_request, serialize_response, PickleProtocolError};
pub use protocol::{RpcRequest, RpcResponse};
pub use server::RpcServer;
