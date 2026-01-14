//! Dynamic port allocation for integration tests.
//!
//! Provides thread-safe port allocation to ensure parallel tests don't conflict.

use std::sync::atomic::{AtomicU16, Ordering};

/// Starting port for test allocations.
/// Using a high port range to avoid conflicts with common services.
const BASE_PORT: u16 = 20000;

/// Global atomic counter for port allocation.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(BASE_PORT);

/// Allocate a unique port for this test run.
///
/// Each call returns a new port number, ensuring parallel tests don't conflict.
pub fn allocate_port() -> u16 {
    PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Allocate multiple consecutive ports.
///
/// Useful when a test needs several ports (e.g., TCP server, shared instance, control).
pub fn allocate_ports(count: u16) -> Vec<u16> {
    (0..count).map(|_| allocate_port()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_port_increments() {
        let port1 = allocate_port();
        let port2 = allocate_port();
        assert!(port2 > port1);
    }

    #[test]
    fn test_allocate_ports_returns_consecutive() {
        let ports = allocate_ports(3);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[1], ports[0] + 1);
        assert_eq!(ports[2], ports[1] + 1);
    }
}
