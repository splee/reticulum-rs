//! RPC module for daemon mode management queries.
//!
//! This module provides a simple RPC mechanism for CLI utilities to query
//! daemon state (interface statistics, path table, link count, etc.).
//!
//! The protocol uses MessagePack serialization with length-prefixed messages:
//! - 4-byte big-endian length prefix
//! - MessagePack-encoded request/response payload
//!
//! Each RPC call follows a connect → send → receive → close pattern,
//! matching the simplicity of Python's multiprocessing.connection.

pub mod client;
pub mod protocol;
pub mod server;

pub use client::RpcClient;
pub use protocol::{RpcRequest, RpcResponse};
pub use server::RpcServer;
