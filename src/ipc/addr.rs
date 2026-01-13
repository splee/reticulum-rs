//! Platform-adaptive socket addressing for IPC.
//!
//! This module provides the `ListenerAddr` enum which abstracts over different
//! socket types based on platform capabilities:
//! - Linux: Abstract Unix sockets (preferred, no filesystem cleanup)
//! - macOS/BSD: Filesystem Unix sockets
//! - Windows: TCP localhost fallback

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// Address for IPC listeners and connections.
///
/// Supports multiple socket types for cross-platform compatibility:
/// - Abstract Unix sockets (Linux only)
/// - Filesystem Unix sockets (Unix systems)
/// - TCP localhost (Windows fallback, or explicit configuration)
#[derive(Debug, Clone)]
pub enum ListenerAddr {
    /// Abstract Unix socket (Linux only).
    /// The name should NOT include the leading null byte - it will be added automatically.
    /// Example: "rns/default" becomes "\0rns/default"
    #[cfg(target_os = "linux")]
    AbstractUnix(String),

    /// Filesystem-based Unix socket.
    /// The socket file will be created at this path and must be cleaned up on shutdown.
    #[cfg(unix)]
    FilesystemUnix(PathBuf),

    /// TCP socket bound to localhost.
    /// Used as fallback on Windows or when explicitly configured.
    Tcp(SocketAddr),
}

impl ListenerAddr {
    /// Returns the default transport IPC address for the current platform.
    ///
    /// Uses the instance name to create a unique socket address:
    /// - Linux: Abstract socket `\0rns/{instance_name}`
    /// - macOS/BSD: Filesystem socket `{socket_dir}/{instance_name}.sock`
    /// - Windows: TCP `127.0.0.1:{port}`
    pub fn default_transport(instance_name: &str, socket_dir: &Path, port: u16) -> Self {
        #[cfg(target_os = "linux")]
        {
            let _ = socket_dir; // unused on Linux
            let _ = port;
            ListenerAddr::AbstractUnix(format!("rns/{}", instance_name))
        }

        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let _ = port;
            ListenerAddr::FilesystemUnix(socket_dir.join(format!("{}.sock", instance_name)))
        }

        #[cfg(windows)]
        {
            let _ = instance_name;
            let _ = socket_dir;
            ListenerAddr::Tcp(SocketAddr::from(([127, 0, 0, 1], port)))
        }
    }

    /// Returns the default RPC address for the current platform.
    ///
    /// Similar to `default_transport` but uses a distinct socket/port:
    /// - Linux: Abstract socket `\0rns/{instance_name}/rpc`
    /// - macOS/BSD: Filesystem socket `{socket_dir}/{instance_name}_rpc.sock`
    /// - Windows: TCP `127.0.0.1:{port}`
    pub fn default_rpc(instance_name: &str, socket_dir: &Path, port: u16) -> Self {
        #[cfg(target_os = "linux")]
        {
            let _ = socket_dir;
            let _ = port;
            ListenerAddr::AbstractUnix(format!("rns/{}/rpc", instance_name))
        }

        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let _ = port;
            ListenerAddr::FilesystemUnix(socket_dir.join(format!("{}_rpc.sock", instance_name)))
        }

        #[cfg(windows)]
        {
            let _ = instance_name;
            let _ = socket_dir;
            ListenerAddr::Tcp(SocketAddr::from(([127, 0, 0, 1], port)))
        }
    }

    /// Create a TCP address from host and port.
    pub fn tcp(host: [u8; 4], port: u16) -> Self {
        ListenerAddr::Tcp(SocketAddr::from((host, port)))
    }

    /// Create a TCP address bound to localhost.
    pub fn localhost(port: u16) -> Self {
        Self::tcp([127, 0, 0, 1], port)
    }

    /// Create a filesystem Unix socket address.
    #[cfg(unix)]
    pub fn unix_filesystem(path: impl Into<PathBuf>) -> Self {
        ListenerAddr::FilesystemUnix(path.into())
    }

    /// Create an abstract Unix socket address (Linux only).
    #[cfg(target_os = "linux")]
    pub fn unix_abstract(name: impl Into<String>) -> Self {
        ListenerAddr::AbstractUnix(name.into())
    }

    /// Returns a human-readable description of the address.
    pub fn display(&self) -> String {
        match self {
            #[cfg(target_os = "linux")]
            ListenerAddr::AbstractUnix(name) => format!("unix-abstract://{}", name),
            #[cfg(unix)]
            ListenerAddr::FilesystemUnix(path) => format!("unix://{}", path.display()),
            ListenerAddr::Tcp(addr) => format!("tcp://{}", addr),
        }
    }
}

/// A wrapper around different stream types that implements AsyncRead + AsyncWrite.
pub enum IpcStream {
    #[cfg(unix)]
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl AsyncRead for IpcStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            IpcStream::Unix(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            IpcStream::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for IpcStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            IpcStream::Unix(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            IpcStream::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            IpcStream::Unix(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            IpcStream::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            IpcStream::Unix(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            IpcStream::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A wrapper around different listener types.
pub enum IpcListener {
    #[cfg(unix)]
    Unix(UnixListener),
    Tcp(TcpListener),
}

impl IpcListener {
    /// Bind to the given address.
    pub async fn bind(addr: &ListenerAddr) -> io::Result<Self> {
        match addr {
            #[cfg(target_os = "linux")]
            ListenerAddr::AbstractUnix(name) => {
                use std::os::linux::net::SocketAddrExt;
                let socket_addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
                let std_listener = std::os::unix::net::UnixListener::bind_addr(&socket_addr)?;
                std_listener.set_nonblocking(true)?;
                let listener = UnixListener::from_std(std_listener)?;
                Ok(IpcListener::Unix(listener))
            }
            #[cfg(unix)]
            ListenerAddr::FilesystemUnix(path) => {
                // Remove existing socket file if present
                let _ = std::fs::remove_file(path);
                let listener = UnixListener::bind(path)?;
                Ok(IpcListener::Unix(listener))
            }
            ListenerAddr::Tcp(addr) => {
                let listener = TcpListener::bind(addr).await?;
                Ok(IpcListener::Tcp(listener))
            }
        }
    }

    /// Accept a new connection.
    pub async fn accept(&self) -> io::Result<(IpcStream, String)> {
        match self {
            #[cfg(unix)]
            IpcListener::Unix(listener) => {
                let (stream, addr) = listener.accept().await?;
                let addr_str = addr
                    .as_pathname()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unix-client".to_string());
                Ok((IpcStream::Unix(stream), addr_str))
            }
            IpcListener::Tcp(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok((IpcStream::Tcp(stream), addr.to_string()))
            }
        }
    }
}

/// Connect to an IPC address.
pub async fn connect(addr: &ListenerAddr) -> io::Result<IpcStream> {
    match addr {
        #[cfg(target_os = "linux")]
        ListenerAddr::AbstractUnix(name) => {
            use std::os::linux::net::SocketAddrExt;
            let socket_addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
            // For abstract sockets, we need to use the std library first
            let std_stream = std::os::unix::net::UnixStream::connect_addr(&socket_addr)?;
            std_stream.set_nonblocking(true)?;
            let stream = UnixStream::from_std(std_stream)?;
            Ok(IpcStream::Unix(stream))
        }
        #[cfg(unix)]
        ListenerAddr::FilesystemUnix(path) => {
            let stream = UnixStream::connect(path).await?;
            Ok(IpcStream::Unix(stream))
        }
        ListenerAddr::Tcp(addr) => {
            let stream = TcpStream::connect(addr).await?;
            Ok(IpcStream::Tcp(stream))
        }
    }
}

/// Check if a daemon is already listening at the given address.
///
/// Returns `true` if a connection can be established, `false` otherwise.
pub async fn is_daemon_running(addr: &ListenerAddr) -> bool {
    connect(addr).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        let tcp_addr = ListenerAddr::localhost(37428);
        assert!(tcp_addr.display().starts_with("tcp://"));

        #[cfg(target_os = "linux")]
        {
            let abstract_addr = ListenerAddr::unix_abstract("rns/default");
            assert!(abstract_addr.display().starts_with("unix-abstract://"));
        }

        #[cfg(unix)]
        {
            let fs_addr = ListenerAddr::unix_filesystem("/tmp/test.sock");
            assert!(fs_addr.display().starts_with("unix://"));
        }
    }
}
