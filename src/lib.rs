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

// Phase 9: Testing Infrastructure
pub mod testing;

// Phase 10: Daemon Mode IPC
pub mod ipc;
pub mod rpc;

// Internal modules
mod utils;
mod serde;
