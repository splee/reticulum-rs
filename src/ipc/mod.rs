//! Inter-process communication (IPC) module for daemon mode.
//!
//! This module provides the infrastructure for running Reticulum as a shared daemon
//! that multiple local processes can connect to. It implements two communication channels:
//!
//! 1. **Transport IPC** (`local` module): High-bandwidth packet relay between daemon and
//!    local clients using HDLC framing. This allows local programs to send/receive
//!    Reticulum packets through the daemon's network interfaces.
//!
//! 2. **RPC IPC** (`rpc` module): Low-latency management queries for CLI utilities
//!    to query daemon state (interface stats, path table, etc.)
//!
//! The socket addressing strategy is platform-adaptive:
//! - Linux: Abstract Unix sockets (no filesystem cleanup needed)
//! - macOS/BSD: Filesystem Unix sockets
//! - Windows: TCP localhost fallback

pub mod addr;
pub mod local;

pub use addr::ListenerAddr;
pub use local::{LocalClientInterface, LocalServerInterface};
