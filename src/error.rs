#[derive(Debug)]
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
