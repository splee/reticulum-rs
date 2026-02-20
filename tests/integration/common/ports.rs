//! Dynamic port allocation for integration tests.
//!
//! Uses OS ephemeral port allocation (bind to port 0) to ensure parallel test
//! processes don't collide on ports, even across separate nextest subprocesses.

use std::net::TcpListener;

/// Allocate a unique port by binding to port 0 and reading back the OS-assigned port.
///
/// The listener is dropped immediately, freeing the port for the test process to use.
/// There is a small TOCTOU window, but in practice this is reliable because the OS
/// won't reassign the same ephemeral port immediately.
pub fn allocate_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .expect("failed to bind to ephemeral port for test port allocation");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Allocate multiple unique ports.
///
/// Each port is independently allocated via the OS, so they are guaranteed
/// to be distinct (the OS won't reuse a recently-freed ephemeral port).
pub fn allocate_ports(count: u16) -> Vec<u16> {
    // Hold all listeners open until we've collected all ports, to prevent
    // the OS from reassigning a just-freed port to the next allocation.
    let listeners: Vec<TcpListener> = (0..count)
        .map(|_| {
            TcpListener::bind("127.0.0.1:0")
                .expect("failed to bind to ephemeral port for test port allocation")
        })
        .collect();

    let ports: Vec<u16> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();

    // All listeners drop here, freeing the ports for test use
    drop(listeners);
    ports
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_allocate_port_returns_valid_port() {
        let port = allocate_port();
        assert!(port > 0, "port should be non-zero");
    }

    #[test]
    fn test_allocate_port_returns_unique_ports() {
        let mut ports = HashSet::new();
        for _ in 0..10 {
            let port = allocate_port();
            assert!(ports.insert(port), "duplicate port allocated: {}", port);
        }
    }

    #[test]
    fn test_allocate_ports_returns_correct_count() {
        let ports = allocate_ports(5);
        assert_eq!(ports.len(), 5);
    }

    #[test]
    fn test_allocate_ports_returns_distinct_ports() {
        let ports = allocate_ports(5);
        let unique: HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(unique.len(), 5, "allocate_ports returned duplicate ports");
    }
}
