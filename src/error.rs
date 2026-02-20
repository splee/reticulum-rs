use std::fmt;

/// Core error type for RNS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RnsError {
    OutOfMemory,
    InvalidArgument,
    IncorrectSignature,
    IncorrectHash,
    CryptoError,
    PacketError,
    ConnectionError,
    /// Operation was cancelled before completion
    Cancelled,
    /// Invalid or malformed data (e.g., slice-to-array conversion failures)
    InvalidData,
    /// Serialization or deserialization error (msgpack, pickle, etc.)
    SerializationError,
    /// File or I/O operation failed
    IoError,
    /// Configuration or value parsing error
    ParseError,
    /// Request data exceeds link MDU; must use a Resource transfer instead
    ResourceRequired,
}

impl fmt::Display for RnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RnsError::OutOfMemory => write!(f, "out of memory"),
            RnsError::InvalidArgument => write!(f, "invalid argument"),
            RnsError::IncorrectSignature => write!(f, "incorrect signature"),
            RnsError::IncorrectHash => write!(f, "incorrect hash"),
            RnsError::CryptoError => write!(f, "cryptographic error"),
            RnsError::PacketError => write!(f, "packet error"),
            RnsError::ConnectionError => write!(f, "connection error"),
            RnsError::Cancelled => write!(f, "operation cancelled"),
            RnsError::InvalidData => write!(f, "invalid data"),
            RnsError::SerializationError => write!(f, "serialization error"),
            RnsError::IoError => write!(f, "I/O error"),
            RnsError::ParseError => write!(f, "parse error"),
            RnsError::ResourceRequired => write!(f, "resource required for large data"),
        }
    }
}

impl std::error::Error for RnsError {}

/// Helper to convert a byte slice to a fixed-size array with error handling.
///
/// Returns `RnsError::InvalidData` if the slice length doesn't match the array size.
pub fn slice_to_array<const N: usize>(slice: &[u8]) -> Result<[u8; N], RnsError> {
    slice.try_into().map_err(|_| RnsError::InvalidData)
}
