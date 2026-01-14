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
        }
    }
}

impl std::error::Error for RnsError {}
