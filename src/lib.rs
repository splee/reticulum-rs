#[cfg(feature = "alloc")]
extern crate alloc;

// Core modules
pub mod buffer;
pub mod crypt;
pub mod destination;
pub mod error;
pub mod hash;
pub mod identity;
pub mod iface;
pub mod packet;
pub mod transport;

// Phase 1: Core infrastructure modules
pub mod config;
pub mod logging;
pub mod persistence;
pub mod receipt;

// Phase 3: Resource transfer module
pub mod resource;

// Phase 4: Channel and Buffer modules
pub mod channel;
pub mod channel_buffer;

// Phase 7: Discovery System
pub mod discovery;

// Proof-of-work stamp generation (shared with LXMF)
pub mod stamper;

// Phase 9: Testing Infrastructure
pub mod testing;

// Phase 10: Daemon Mode IPC
pub mod ipc;
pub mod rpc;

// Top-level SDK entry point
pub mod reticulum;

// Remote management client utilities
pub mod remote_client;

// CLI shared utilities
pub mod cli;

// Internal modules
mod utils;
mod serde;
