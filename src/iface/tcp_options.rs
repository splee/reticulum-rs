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

    // Standard TCP keepalive constants (Python: TCPInterface.py:83-88)
    /// TCP_USER_TIMEOUT value in seconds (Linux only)
    pub const TCP_USER_TIMEOUT_SECS: u32 = 24;

    /// Time before first keepalive probe (TCP_KEEPIDLE on Linux, TCP_KEEPALIVE on macOS)
    pub const TCP_PROBE_AFTER_SECS: u32 = 5;

    /// Interval between keepalive probes (Linux only)
    pub const TCP_PROBE_INTERVAL_SECS: u32 = 2;

    /// Number of keepalive probes before connection is considered dead (Linux only)
    pub const TCP_PROBES: u32 = 12;

    // I2P tunnel keepalive constants (Python: TCPInterface.py:92-95)
    /// I2P TCP_USER_TIMEOUT value in seconds
    pub const I2P_USER_TIMEOUT_SECS: u32 = 45;

    /// I2P time before first keepalive probe
    pub const I2P_PROBE_AFTER_SECS: u32 = 10;

    /// I2P interval between keepalive probes
    pub const I2P_PROBE_INTERVAL_SECS: u32 = 9;

    /// I2P number of keepalive probes
    pub const I2P_PROBES: u32 = 5;

    /// Standard keepalive time as Duration
    pub fn keepalive_time() -> Duration {
        Duration::from_secs(TCP_PROBE_AFTER_SECS as u64)
    }

    /// Standard keepalive interval as Duration (Linux only)
    pub fn keepalive_interval() -> Duration {
        Duration::from_secs(TCP_PROBE_INTERVAL_SECS as u64)
    }

    /// I2P keepalive time as Duration
    pub fn i2p_keepalive_time() -> Duration {
        Duration::from_secs(I2P_PROBE_AFTER_SECS as u64)
    }

    /// I2P keepalive interval as Duration
    pub fn i2p_keepalive_interval() -> Duration {
        Duration::from_secs(I2P_PROBE_INTERVAL_SECS as u64)
    }
}

/// Configure TCP socket options on a tokio TcpStream.
///
/// Sets keepalive options matching the Python implementation. When `i2p_tunneled`
/// is true, uses longer I2P-specific timeout values.
///
/// Standard values: keepidle=5s, keepintvl=2s, keepcnt=12, user_timeout=24s
/// I2P values: keepidle=10s, keepintvl=9s, keepcnt=5, user_timeout=45s
///
/// # Platform differences
///
/// On Linux, all options are set including TCP_USER_TIMEOUT.
/// On macOS, only SO_KEEPALIVE and TCP_KEEPALIVE (probe-after) are available.
/// On other platforms, basic keepalive is enabled where possible.
pub fn configure_tcp_socket(stream: &tokio::net::TcpStream, i2p_tunneled: bool) -> std::io::Result<()> {
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
    let result = configure_socket_impl(&socket, i2p_tunneled);

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
fn configure_socket_impl(socket: &Socket, i2p_tunneled: bool) -> std::io::Result<()> {
    // Set TCP_NODELAY (disable Nagle's algorithm)
    socket.set_nodelay(true)?;

    // Enable keepalive with platform-specific configuration
    #[cfg(target_os = "linux")]
    {
        configure_linux(socket, i2p_tunneled)?;
    }

    #[cfg(target_os = "macos")]
    {
        configure_macos(socket, i2p_tunneled)?;
    }

    // For other platforms, just enable basic keepalive
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let time = if i2p_tunneled { constants::i2p_keepalive_time() } else { constants::keepalive_time() };
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(time);
        socket.set_tcp_keepalive(&keepalive)?;
    }

    Ok(())
}

/// Configure TCP socket options for Linux.
#[cfg(target_os = "linux")]
fn configure_linux(socket: &Socket, i2p_tunneled: bool) -> std::io::Result<()> {
    use constants::*;

    // Select standard or I2P keepalive constants
    let (user_timeout, probe_time, probe_interval, probes) = if i2p_tunneled {
        (I2P_USER_TIMEOUT_SECS, i2p_keepalive_time(), i2p_keepalive_interval(), I2P_PROBES)
    } else {
        (TCP_USER_TIMEOUT_SECS, keepalive_time(), keepalive_interval(), TCP_PROBES)
    };

    // Configure keepalive with all Linux-specific options
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(probe_time)
        .with_interval(probe_interval)
        .with_retries(probes);

    socket.set_tcp_keepalive(&keepalive)?;

    // Set TCP_USER_TIMEOUT (requires manual setsockopt call)
    // TCP_USER_TIMEOUT is option 18 on Linux
    const TCP_USER_TIMEOUT_OPT: libc::c_int = 18;
    let timeout_ms: libc::c_uint = user_timeout * 1000;

    unsafe {
        let result = libc::setsockopt(
            std::os::unix::io::AsRawFd::as_raw_fd(socket),
            libc::IPPROTO_TCP,
            TCP_USER_TIMEOUT_OPT,
            &timeout_ms as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        );

        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    let mode = if i2p_tunneled { "I2P" } else { "standard" };
    log::trace!("tcp_options: configured Linux socket ({} mode, keepidle={}s, keepintvl={}s, keepcnt={}, user_timeout={}ms)",
        mode, probe_time.as_secs(), probe_interval.as_secs(), probes, timeout_ms);

    Ok(())
}

/// Configure TCP socket options for macOS.
#[cfg(target_os = "macos")]
fn configure_macos(socket: &Socket, i2p_tunneled: bool) -> std::io::Result<()> {
    use constants::*;

    // macOS only supports TCP_KEEPALIVE (equivalent to TCP_KEEPIDLE on Linux)
    // TCP_KEEPINTVL and TCP_KEEPCNT are not available
    let probe_time = if i2p_tunneled { i2p_keepalive_time() } else { keepalive_time() };

    let keepalive = socket2::TcpKeepalive::new()
        .with_time(probe_time);

    socket.set_tcp_keepalive(&keepalive)?;

    let mode = if i2p_tunneled { "I2P" } else { "standard" };
    log::trace!("tcp_options: configured macOS socket ({} mode, keepalive={}s)", mode, probe_time.as_secs());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_standard_constants() {
        assert_eq!(constants::TCP_USER_TIMEOUT_SECS, 24);
        assert_eq!(constants::TCP_PROBE_AFTER_SECS, 5);
        assert_eq!(constants::TCP_PROBE_INTERVAL_SECS, 2);
        assert_eq!(constants::TCP_PROBES, 12);
        assert_eq!(constants::keepalive_time(), Duration::from_secs(5));
        assert_eq!(constants::keepalive_interval(), Duration::from_secs(2));
    }

    #[test]
    fn test_i2p_constants() {
        assert_eq!(constants::I2P_USER_TIMEOUT_SECS, 45);
        assert_eq!(constants::I2P_PROBE_AFTER_SECS, 10);
        assert_eq!(constants::I2P_PROBE_INTERVAL_SECS, 9);
        assert_eq!(constants::I2P_PROBES, 5);
        assert_eq!(constants::i2p_keepalive_time(), Duration::from_secs(10));
        assert_eq!(constants::i2p_keepalive_interval(), Duration::from_secs(9));
    }
}
