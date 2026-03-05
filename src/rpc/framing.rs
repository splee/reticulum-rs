//! Python-compatible message framing for multiprocessing.connection protocol.
//!
//! This module implements the message framing used by Python's `multiprocessing.connection`
//! module. Messages are prefixed with their length as a signed 32-bit big-endian integer.
//!
//! ## Wire Format
//!
//! For messages up to 2GB (most common):
//! ```text
//! ┌─────────────────────────────┬─────────────────────────────────┐
//! │ 4 bytes (signed big-endian) │ message payload                 │
//! └─────────────────────────────┴─────────────────────────────────┘
//! ```
//!
//! For messages larger than 2GB:
//! ```text
//! ┌──────────────────┬────────────────────────────┬─────────────────────────────────┐
//! │ 4 bytes (-1)     │ 8 bytes (unsigned big-end) │ message payload                 │
//! └──────────────────┴────────────────────────────┴─────────────────────────────────┘
//! ```
//!
//! Note: Python uses `struct.pack("!i", n)` which is signed network byte order (big-endian).
//! The Nagle algorithm optimization (concatenating header + small payloads) is not implemented
//! here since Tokio handles buffering appropriately.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum size threshold for standard 4-byte header.
/// Messages larger than this use the extended 8-byte size format.
const MAX_STANDARD_SIZE: usize = 0x7FFFFFFF; // i32::MAX

/// Send bytes with Python-compatible length prefix.
///
/// Matches Python's `Connection._send_bytes()` behavior:
/// - For messages <= 2GB: 4-byte signed big-endian length prefix
/// - For messages > 2GB: 4-byte -1 marker, then 8-byte unsigned length
///
/// # Arguments
/// * `stream` - The stream to write to
/// * `data` - The data to send
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(io::Error)` on I/O failure
pub async fn send_bytes<S>(stream: &mut S, data: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let n = data.len();

    if n > MAX_STANDARD_SIZE {
        // Extended format for large messages
        let pre_header = (-1i32).to_be_bytes();
        let header = (n as u64).to_be_bytes();
        stream.write_all(&pre_header).await?;
        stream.write_all(&header).await?;
    } else {
        // Standard format
        let header = (n as i32).to_be_bytes();
        stream.write_all(&header).await?;
    }

    stream.write_all(data).await?;
    stream.flush().await?;

    Ok(())
}

/// Receive bytes with Python-compatible length prefix.
///
/// Matches Python's `Connection._recv_bytes()` behavior:
/// - Read 4-byte signed length
/// - If -1, read additional 8-byte unsigned length
/// - Read that many bytes
///
/// # Arguments
/// * `stream` - The stream to read from
/// * `maxsize` - Maximum message size to accept (prevents DoS)
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the received data
/// * `Err(io::Error)` on I/O failure or if message exceeds maxsize
pub async fn recv_bytes<S>(stream: &mut S, maxsize: usize) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    // Read 4-byte length header
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = i32::from_be_bytes(len_buf);

    // Determine actual size
    let size = if len == -1 {
        // Extended format: read 8-byte unsigned length
        let mut ext_len_buf = [0u8; 8];
        stream.read_exact(&mut ext_len_buf).await?;
        u64::from_be_bytes(ext_len_buf) as usize
    } else if len < 0 {
        // Invalid negative length (not -1)
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid negative message length: {}", len),
        ));
    } else {
        len as usize
    };

    // Check against maximum size
    if size > maxsize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Message size {} exceeds maximum allowed size {}",
                size, maxsize
            ),
        ));
    }

    // Read the message body
    let mut buf = vec![0u8; size];
    stream.read_exact(&mut buf).await?;

    Ok(buf)
}

/// Send a pickled Python object.
///
/// Convenience wrapper that serializes an object to pickle format and sends it
/// with the appropriate length prefix.
///
/// # Arguments
/// * `stream` - The stream to write to
/// * `value` - The value to serialize and send
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(io::Error)` on serialization or I/O failure
pub async fn send_pickle<S, T>(stream: &mut S, value: &T) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let data = serde_pickle::to_vec(value, serde_pickle::SerOptions::new()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Pickle serialization failed: {}", e),
        )
    })?;

    send_bytes(stream, &data).await
}

/// Receive and unpickle a Python object.
///
/// Convenience wrapper that receives a message and deserializes it from pickle format.
///
/// # Arguments
/// * `stream` - The stream to read from
/// * `maxsize` - Maximum message size to accept
///
/// # Returns
/// * `Ok(T)` containing the deserialized value
/// * `Err(io::Error)` on I/O or deserialization failure
pub async fn recv_pickle<S, T>(stream: &mut S, maxsize: usize) -> io::Result<T>
where
    S: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let data = recv_bytes(stream, maxsize).await?;

    serde_pickle::from_slice(&data, serde_pickle::DeOptions::new()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Pickle deserialization failed: {}", e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A simple in-memory async stream for testing.
    struct TestStream {
        read_buf: Cursor<Vec<u8>>,
        write_buf: Vec<u8>,
    }

    impl TestStream {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_buf: Cursor::new(read_data),
                write_buf: Vec::new(),
            }
        }

        fn written(&self) -> &[u8] {
            &self.write_buf
        }
    }

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let pos = self.read_buf.position() as usize;
            let data = self.read_buf.get_ref();
            let remaining = &data[pos..];
            let to_read = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_read]);
            self.read_buf.set_position((pos + to_read) as u64);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_buf.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_send_bytes_small() {
        let mut stream = TestStream::new(vec![]);
        let data = b"hello world";

        send_bytes(&mut stream, data).await.unwrap();

        let written = stream.written();
        // 4-byte length header + data
        assert_eq!(written.len(), 4 + data.len());

        // Check length header (11 as signed big-endian)
        let len = i32::from_be_bytes([written[0], written[1], written[2], written[3]]);
        assert_eq!(len, 11);

        // Check data
        assert_eq!(&written[4..], data);
    }

    #[tokio::test]
    async fn test_send_bytes_empty() {
        let mut stream = TestStream::new(vec![]);
        let data = b"";

        send_bytes(&mut stream, data).await.unwrap();

        let written = stream.written();
        assert_eq!(written.len(), 4);

        let len = i32::from_be_bytes([written[0], written[1], written[2], written[3]]);
        assert_eq!(len, 0);
    }

    #[tokio::test]
    async fn test_recv_bytes() {
        // Prepare data: length header (5) + "hello"
        let mut data = Vec::new();
        data.extend_from_slice(&5i32.to_be_bytes());
        data.extend_from_slice(b"hello");

        let mut stream = TestStream::new(data);
        let result = recv_bytes(&mut stream, 1024).await.unwrap();

        assert_eq!(result, b"hello");
    }

    #[tokio::test]
    async fn test_recv_bytes_empty() {
        // Prepare data: length header (0)
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_be_bytes());

        let mut stream = TestStream::new(data);
        let result = recv_bytes(&mut stream, 1024).await.unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_recv_bytes_exceeds_maxsize() {
        // Prepare data: length header (1000) + some data
        let mut data = Vec::new();
        data.extend_from_slice(&1000i32.to_be_bytes());
        data.extend_from_slice(&[0u8; 1000]);

        let mut stream = TestStream::new(data);
        let result = recv_bytes(&mut stream, 100).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[tokio::test]
    async fn test_roundtrip() {
        let original = b"test message for roundtrip";

        // Send
        let mut send_stream = TestStream::new(vec![]);
        send_bytes(&mut send_stream, original).await.unwrap();

        // Receive
        let mut recv_stream = TestStream::new(send_stream.written().to_vec());
        let received = recv_bytes(&mut recv_stream, 1024).await.unwrap();

        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_pickle_roundtrip() {
        use std::collections::HashMap;

        let mut original: HashMap<String, i64> = HashMap::new();
        original.insert("count".to_string(), 42);
        original.insert("value".to_string(), 100);

        // Send
        let mut send_stream = TestStream::new(vec![]);
        send_pickle(&mut send_stream, &original).await.unwrap();

        // Receive
        let mut recv_stream = TestStream::new(send_stream.written().to_vec());
        let received: HashMap<String, i64> = recv_pickle(&mut recv_stream, 1024).await.unwrap();

        assert_eq!(received, original);
    }
}
