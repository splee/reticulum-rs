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

// Internal modules
mod utils;
mod serde;
