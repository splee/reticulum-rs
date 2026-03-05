//! HMAC authentication for Python multiprocessing.connection compatibility.
//!
//! This module implements the challenge-response authentication protocol used by
//! Python's `multiprocessing.connection` module. The protocol provides mutual
//! authentication where both sides prove knowledge of a shared secret (authkey).
//!
//! ## Protocol Flow
//!
//! Server (Listener.accept):
//! 1. Send challenge: `#CHALLENGE# + {sha256}random_bytes`
//! 2. Receive and verify client's HMAC response
//! 3. Send `#WELCOME#` or `#FAILURE#`
//! 4. Receive challenge from client
//! 5. Compute and send HMAC response
//! 6. Receive `#WELCOME#` or `#FAILURE#`
//!
//! Client (Client):
//! 1. Receive challenge from server
//! 2. Compute and send HMAC response
//! 3. Receive `#WELCOME#` or `#FAILURE#`
//! 4. Send challenge: `#CHALLENGE# + {sha256}random_bytes`
//! 5. Receive and verify server's HMAC response
//! 6. Send `#WELCOME#` or `#FAILURE#`
//!
//! ## Digest Algorithms
//!
//! Modern Python (3.12+) uses `{sha256}` prefixed challenges and responses.
//! Legacy Python (≤3.11) uses raw 20-byte challenges with MD5 responses.
//! This implementation supports both for maximum compatibility.

use hmac::{Hmac, Mac};
use md5::Md5;
use rand::RngCore;
use sha2::Sha256;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

use super::framing::{recv_bytes, send_bytes};

/// Protocol constants matching Python's multiprocessing.connection
const CHALLENGE: &[u8] = b"#CHALLENGE#";
const WELCOME: &[u8] = b"#WELCOME#";
const FAILURE: &[u8] = b"#FAILURE#";

/// Length of random bytes in challenge (must be > 20 for modern protocol)
const MESSAGE_LENGTH: usize = 40;

/// Legacy MD5-only message length (Python ≤3.11)
const MD5_ONLY_MESSAGE_LENGTH: usize = 20;

/// MD5 digest length
const MD5_DIGEST_LEN: usize = 16;

/// Maximum message size for auth handshake
const MAX_AUTH_MESSAGE: usize = 256;

/// Default digest algorithm for modern protocol
const DEFAULT_DIGEST: &str = "sha256";

/// Allowed digest algorithms (matching Python's _ALLOWED_DIGESTS)
const ALLOWED_DIGESTS: &[&str] = &["md5", "sha256", "sha384"];

/// Errors that can occur during authentication.
#[derive(Debug)]
pub enum AuthError {
    /// I/O error during communication.
    Io(io::Error),
    /// Protocol error (unexpected message format).
    ProtocolError(String),
    /// Authentication failed (wrong key or tampered message).
    AuthenticationFailed(String),
    /// Unsupported digest algorithm.
    UnsupportedDigest(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Io(e) => write!(f, "I/O error: {}", e),
            AuthError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            AuthError::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            AuthError::UnsupportedDigest(d) => write!(f, "Unsupported digest: {}", d),
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AuthError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for AuthError {
    fn from(e: io::Error) -> Self {
        AuthError::Io(e)
    }
}

/// Perform server-side authentication (called by Listener.accept equivalent).
///
/// This performs mutual authentication:
/// 1. Server sends challenge to client
/// 2. Client proves knowledge of authkey
/// 3. Client sends challenge to server
/// 4. Server proves knowledge of authkey
///
/// # Arguments
/// * `stream` - The connection stream (must implement AsyncRead + AsyncWrite)
/// * `authkey` - The shared secret key for authentication
///
/// # Returns
/// * `Ok(())` if authentication succeeds
/// * `Err(AuthError)` if authentication fails
pub async fn server_authenticate<S>(stream: &mut S, authkey: &[u8]) -> Result<(), AuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1: Send our challenge and verify client's response
    deliver_challenge(stream, authkey).await?;

    // Step 2: Answer the client's challenge
    answer_challenge(stream, authkey).await?;

    Ok(())
}

/// Perform client-side authentication (called by Client equivalent).
///
/// This performs mutual authentication:
/// 1. Client receives challenge from server
/// 2. Client proves knowledge of authkey
/// 3. Client sends challenge to server
/// 4. Server proves knowledge of authkey
///
/// # Arguments
/// * `stream` - The connection stream (must implement AsyncRead + AsyncWrite)
/// * `authkey` - The shared secret key for authentication
///
/// # Returns
/// * `Ok(())` if authentication succeeds
/// * `Err(AuthError)` if authentication fails
pub async fn client_authenticate<S>(stream: &mut S, authkey: &[u8]) -> Result<(), AuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1: Answer the server's challenge
    answer_challenge(stream, authkey).await?;

    // Step 2: Send our challenge and verify server's response
    deliver_challenge(stream, authkey).await?;

    Ok(())
}

/// Send a challenge and verify the response.
///
/// Generates a random challenge, sends it with a digest prefix, then verifies
/// the HMAC response from the other side.
async fn deliver_challenge<S>(stream: &mut S, authkey: &[u8]) -> Result<(), AuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Generate random challenge with digest prefix
    let mut random_bytes = [0u8; MESSAGE_LENGTH];
    rand::thread_rng().fill_bytes(&mut random_bytes);

    // Format: {sha256}random_bytes
    let digest_prefix = format!("{{{}}}", DEFAULT_DIGEST);
    let mut message = Vec::with_capacity(digest_prefix.len() + MESSAGE_LENGTH);
    message.extend_from_slice(digest_prefix.as_bytes());
    message.extend_from_slice(&random_bytes);

    // Send: #CHALLENGE# + message
    let mut challenge = Vec::with_capacity(CHALLENGE.len() + message.len());
    challenge.extend_from_slice(CHALLENGE);
    challenge.extend_from_slice(&message);
    send_bytes(stream, &challenge).await?;

    // Receive response (HMAC digest)
    let response = recv_bytes(stream, MAX_AUTH_MESSAGE).await?;

    // Verify the response
    match verify_challenge(authkey, &message, &response) {
        Ok(()) => {
            // Send welcome
            send_bytes(stream, WELCOME).await?;
            Ok(())
        }
        Err(e) => {
            // Send failure
            let _ = send_bytes(stream, FAILURE).await;
            Err(e)
        }
    }
}

/// Receive a challenge and send the response.
///
/// Receives a challenge from the other side, computes the HMAC, and sends
/// the response. Then waits for confirmation (WELCOME or FAILURE).
async fn answer_challenge<S>(stream: &mut S, authkey: &[u8]) -> Result<(), AuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Receive challenge
    let data = recv_bytes(stream, MAX_AUTH_MESSAGE).await?;

    // Verify it starts with #CHALLENGE#
    if !data.starts_with(CHALLENGE) {
        return Err(AuthError::ProtocolError(format!(
            "Expected challenge, got {} bytes not starting with #CHALLENGE#",
            data.len()
        )));
    }

    // Extract the message (after #CHALLENGE# prefix)
    let message = &data[CHALLENGE.len()..];

    if message.len() < MD5_ONLY_MESSAGE_LENGTH {
        return Err(AuthError::ProtocolError(format!(
            "Challenge too short: {} bytes",
            message.len()
        )));
    }

    // Create and send response
    let response = create_response(authkey, message)?;
    send_bytes(stream, &response).await?;

    // Wait for welcome/failure
    let result = recv_bytes(stream, MAX_AUTH_MESSAGE).await?;

    if result == WELCOME {
        Ok(())
    } else if result == FAILURE {
        Err(AuthError::AuthenticationFailed(
            "Server rejected our authentication".to_string(),
        ))
    } else {
        Err(AuthError::ProtocolError(format!(
            "Expected #WELCOME# or #FAILURE#, got {} bytes",
            result.len()
        )))
    }
}

/// Create an HMAC response to a challenge message.
///
/// The response format depends on the challenge:
/// - Modern (has `{digest}` prefix): Response is `{digest}hmac_bytes`
/// - Legacy (20-byte raw): Response is raw MD5 HMAC bytes
fn create_response(authkey: &[u8], message: &[u8]) -> Result<Vec<u8>, AuthError> {
    let (digest_name, _payload) = get_digest_name_and_payload(message)?;

    if digest_name.is_empty() {
        // Legacy protocol: raw MD5 HMAC
        let mut mac = Hmac::<Md5>::new_from_slice(authkey)
            .map_err(|_| AuthError::AuthenticationFailed("Invalid key length".to_string()))?;
        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    } else {
        // Modern protocol: prefixed HMAC
        let hmac_bytes = compute_hmac(authkey, message, &digest_name)?;
        let mut response = Vec::with_capacity(digest_name.len() + 2 + hmac_bytes.len());
        response.push(b'{');
        response.extend_from_slice(digest_name.as_bytes());
        response.push(b'}');
        response.extend_from_slice(&hmac_bytes);
        Ok(response)
    }
}

/// Verify an HMAC response to our challenge.
///
/// Parses the digest name from the response (or defaults to MD5 for legacy),
/// computes the expected HMAC, and compares using constant-time comparison.
fn verify_challenge(authkey: &[u8], message: &[u8], response: &[u8]) -> Result<(), AuthError> {
    let (response_digest, response_mac) = get_digest_name_and_payload(response)?;

    // Default to MD5 for legacy responses
    let digest_name = if response_digest.is_empty() {
        "md5"
    } else {
        &response_digest
    };

    // Compute expected HMAC
    let expected = compute_hmac(authkey, message, digest_name)?;

    // Constant-time comparison
    if expected.len() != response_mac.len() {
        return Err(AuthError::AuthenticationFailed(format!(
            "Expected {} digest of length {}, got {}",
            digest_name,
            expected.len(),
            response_mac.len()
        )));
    }

    // Use subtle crate-style constant-time comparison
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(response_mac.iter()) {
        diff |= a ^ b;
    }

    if diff == 0 {
        Ok(())
    } else {
        Err(AuthError::AuthenticationFailed(
            "Digest received was wrong".to_string(),
        ))
    }
}

/// Parse digest name and payload from a message or response.
///
/// Modern format: `{digest_name}payload`
/// Legacy format: raw bytes (16 or 20 bytes indicates legacy)
///
/// Returns (digest_name, payload). Empty digest_name indicates legacy mode.
fn get_digest_name_and_payload(message: &[u8]) -> Result<(String, &[u8]), AuthError> {
    // Check for legacy format (16 or 20 byte messages)
    if message.len() == MD5_DIGEST_LEN || message.len() == MD5_ONLY_MESSAGE_LENGTH {
        return Ok((String::new(), message));
    }

    // Check for modern format: {digest}payload
    if message.starts_with(b"{") {
        // Find closing brace (within reasonable length)
        let max_search = message.len().min(20);
        if let Some(pos) = message[1..max_search].iter().position(|&b| b == b'}') {
            let digest_name = std::str::from_utf8(&message[1..pos + 1])
                .map_err(|_| AuthError::ProtocolError("Invalid digest name encoding".to_string()))?
                .to_string();

            // Verify it's an allowed digest
            if !ALLOWED_DIGESTS.contains(&digest_name.as_str()) {
                return Err(AuthError::UnsupportedDigest(digest_name));
            }

            let payload = &message[pos + 2..];
            return Ok((digest_name, payload));
        }
    }

    Err(AuthError::ProtocolError(format!(
        "Unsupported message format: {} bytes, missing digest prefix",
        message.len()
    )))
}

/// Compute HMAC using the specified digest algorithm.
fn compute_hmac(authkey: &[u8], message: &[u8], digest_name: &str) -> Result<Vec<u8>, AuthError> {
    match digest_name {
        "md5" => {
            let mut mac = Hmac::<Md5>::new_from_slice(authkey)
                .map_err(|_| AuthError::AuthenticationFailed("Invalid key length".to_string()))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "sha256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(authkey)
                .map_err(|_| AuthError::AuthenticationFailed("Invalid key length".to_string()))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(AuthError::UnsupportedDigest(digest_name.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_digest_name_and_payload_modern() {
        let message = b"{sha256}hello world";
        let (digest, payload) = get_digest_name_and_payload(message).unwrap();
        assert_eq!(digest, "sha256");
        assert_eq!(payload, b"hello world");
    }

    #[test]
    fn test_get_digest_name_and_payload_legacy_20() {
        let message = [0u8; 20];
        let (digest, payload) = get_digest_name_and_payload(&message).unwrap();
        assert_eq!(digest, "");
        assert_eq!(payload.len(), 20);
    }

    #[test]
    fn test_get_digest_name_and_payload_legacy_16() {
        let message = [0u8; 16];
        let (digest, payload) = get_digest_name_and_payload(&message).unwrap();
        assert_eq!(digest, "");
        assert_eq!(payload.len(), 16);
    }

    #[test]
    fn test_create_response_modern() {
        let authkey = b"test_key";
        let message = b"{sha256}challenge_data_here_padding";
        let response = create_response(authkey, message).unwrap();

        // Response should start with {sha256}
        assert!(response.starts_with(b"{sha256}"));
        // SHA256 digest is 32 bytes
        assert_eq!(response.len(), 8 + 32); // {sha256} + 32 bytes
    }

    #[test]
    fn test_create_response_legacy() {
        let authkey = b"test_key";
        let message = [0u8; 20]; // Legacy 20-byte message
        let response = create_response(authkey, &message).unwrap();

        // Legacy response is raw MD5, 16 bytes
        assert_eq!(response.len(), 16);
    }

    #[test]
    fn test_verify_challenge_modern() {
        let authkey = b"test_key";
        let message = b"{sha256}random_challenge_bytes_here";

        // Create a valid response
        let response = create_response(authkey, message).unwrap();

        // Verification should succeed
        assert!(verify_challenge(authkey, message, &response).is_ok());
    }

    #[test]
    fn test_verify_challenge_wrong_key() {
        let authkey = b"test_key";
        let wrong_key = b"wrong_key";
        let message = b"{sha256}random_challenge_bytes_here";

        // Create response with wrong key
        let response = create_response(wrong_key, message).unwrap();

        // Verification should fail
        assert!(verify_challenge(authkey, message, &response).is_err());
    }

    #[test]
    fn test_compute_hmac_sha256() {
        let authkey = b"key";
        let message = b"message";
        let hmac = compute_hmac(authkey, message, "sha256").unwrap();
        assert_eq!(hmac.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_compute_hmac_md5() {
        let authkey = b"key";
        let message = b"message";
        let hmac = compute_hmac(authkey, message, "md5").unwrap();
        assert_eq!(hmac.len(), 16); // MD5 produces 16 bytes
    }
}
