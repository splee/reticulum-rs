//! TCP socket options configuration for Reticulum.
//!
//! This module provides platform-specific TCP socket configuration
//! to match the Python implementation's keepalive and timeout behavior.

use socket2::Socket;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket};

/// TCP socket configuration constants matching Python's TCPClientInterface.
///
/// These values are from reticulum-python/RNS/Interfaces/TCPInterface.py:83-95
pub mod constants {
    use std::time::Duration;

    /// TCP_USER_TIMEOUT value in seconds (Linux only)
    pub const TCP_USER_TIMEOUT_SECS: u32 = 24;

    /// Time before first keepalive probe (TCP_KEEPIDLE on Linux, TCP_KEEPALIVE on macOS)
    pub const TCP_PROBE_AFTER_SECS: u32 = 5;

    /// Interval between keepalive probes (Linux only)
    pub const TCP_PROBE_INTERVAL_SECS: u32 = 2;

    /// Number of keepalive probes before connection is considered dead (Linux only)
    pub const TCP_PROBES: u32 = 12;

    /// Keepalive time as Duration
    pub fn keepalive_time() -> Duration {
        Duration::from_secs(TCP_PROBE_AFTER_SECS as u64)
    }

    /// Keepalive interval as Duration (Linux only)
    pub fn keepalive_interval() -> Duration {
        Duration::from_secs(TCP_PROBE_INTERVAL_SECS as u64)
    }
}

/// Configure TCP socket options on a tokio TcpStream.
///
/// This function sets keepalive options to match the Python implementation:
/// - SO_KEEPALIVE = 1
/// - TCP_NODELAY = 1
/// - TCP_KEEPIDLE / TCP_KEEPALIVE = 5 seconds
/// - TCP_KEEPINTVL = 2 seconds (Linux only)
/// - TCP_KEEPCNT = 12 (Linux only)
/// - TCP_USER_TIMEOUT = 24000ms (Linux only)
///
/// # Platform differences
///
/// On Linux, all options are set including TCP_USER_TIMEOUT.
/// On macOS, only SO_KEEPALIVE and TCP_KEEPALIVE (probe-after) are available.
/// On other platforms, basic keepalive is enabled where possible.
pub fn configure_tcp_socket(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    // Get the raw socket from the TcpStream
    #[cfg(unix)]
    let socket = unsafe {
        // We need to be careful here - we're borrowing the fd, not taking ownership
        let fd = stream.as_raw_fd();
        Socket::from_raw_fd(fd)
    };

    #[cfg(windows)]
    let socket = unsafe {
        let handle = stream.as_raw_socket();
        Socket::from_raw_socket(handle)
    };

    // Configure the socket
    let result = configure_socket_impl(&socket);

    // Prevent the Socket from closing the fd when dropped
    // by converting it back to the raw fd and forgetting it
    #[cfg(unix)]
    {
        use std::os::unix::io::IntoRawFd;
        let _ = socket.into_raw_fd();
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::IntoRawSocket;
        let _ = socket.into_raw_socket();
    }

    result
}

/// Internal implementation for socket configuration.
fn configure_socket_impl(socket: &Socket) -> std::io::Result<()> {
    // Set TCP_NODELAY (disable Nagle's algorithm)
    socket.set_nodelay(true)?;

    // Enable keepalive with platform-specific configuration
    #[cfg(target_os = "linux")]
    {
        configure_linux(socket)?;
    }

    #[cfg(target_os = "macos")]
    {
        configure_macos(socket)?;
    }

    // For other platforms, just enable basic keepalive
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(constants::keepalive_time());
        socket.set_tcp_keepalive(&keepalive)?;
    }

    Ok(())
}

/// Configure TCP socket options for Linux.
#[cfg(target_os = "linux")]
fn configure_linux(socket: &Socket) -> std::io::Result<()> {
    use constants::*;

    // Configure keepalive with all Linux-specific options
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(keepalive_time())
        .with_interval(keepalive_interval())
        .with_retries(TCP_PROBES);

    socket.set_tcp_keepalive(&keepalive)?;

    // Set TCP_USER_TIMEOUT (requires manual setsockopt call)
    // TCP_USER_TIMEOUT is option 18 on Linux
    const TCP_USER_TIMEOUT: libc::c_int = 18;
    let timeout_ms: libc::c_uint = TCP_USER_TIMEOUT_SECS * 1000;

    unsafe {
        let result = libc::setsockopt(
            std::os::unix::io::AsRawFd::as_raw_fd(socket),
            libc::IPPROTO_TCP,
            TCP_USER_TIMEOUT,
            &timeout_ms as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        );

        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    log::trace!("tcp_options: configured Linux socket (keepidle={}, keepintvl={}, keepcnt={}, user_timeout={}ms)",
        TCP_PROBE_AFTER_SECS, TCP_PROBE_INTERVAL_SECS, TCP_PROBES, TCP_USER_TIMEOUT_SECS * 1000);

    Ok(())
}

/// Configure TCP socket options for macOS.
#[cfg(target_os = "macos")]
fn configure_macos(socket: &Socket) -> std::io::Result<()> {
    use constants::*;

    // macOS only supports TCP_KEEPALIVE (equivalent to TCP_KEEPIDLE on Linux)
    // TCP_KEEPINTVL and TCP_KEEPCNT are not available
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(keepalive_time());

    socket.set_tcp_keepalive(&keepalive)?;

    log::trace!("tcp_options: configured macOS socket (keepalive={}s)", TCP_PROBE_AFTER_SECS);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_constants() {
        assert_eq!(constants::TCP_USER_TIMEOUT_SECS, 24);
        assert_eq!(constants::TCP_PROBE_AFTER_SECS, 5);
        assert_eq!(constants::TCP_PROBE_INTERVAL_SECS, 2);
        assert_eq!(constants::TCP_PROBES, 12);
        assert_eq!(constants::keepalive_time(), Duration::from_secs(5));
        assert_eq!(constants::keepalive_interval(), Duration::from_secs(2));
    }
}
