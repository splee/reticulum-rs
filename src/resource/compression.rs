//! Compression utilities for resource transfers.
//!
//! This module provides bz2 compression and decompression compatible with
//! Python's bz2 module.

use crate::error::RnsError;

/// Compress data using bz2 compression (compatible with Python bz2 module)
pub fn compress_bz2(data: &[u8]) -> Result<Vec<u8>, RnsError> {
    use bzip2::write::BzEncoder;
    use bzip2::Compression;
    use std::io::Write;

    let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).map_err(|e| {
        log::error!("bz2 compression failed: {:?}", e);
        RnsError::InvalidArgument
    })?;
    encoder.finish().map_err(|e| {
        log::error!("bz2 compression finalize failed: {:?}", e);
        RnsError::InvalidArgument
    })
}

/// Decompress bz2-compressed data
pub fn decompress_bz2(data: &[u8]) -> Result<Vec<u8>, RnsError> {
    use bzip2::read::BzDecoder;
    use std::io::Read;

    let mut decoder = BzDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).map_err(|e| {
        log::error!("bz2 decompression failed: {:?}", e);
        RnsError::InvalidArgument
    })?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_roundtrip() {
        let data = b"This is some test data that should compress well. ".repeat(100);
        let compressed = compress_bz2(&data).expect("compress");
        let decompressed = decompress_bz2(&compressed).expect("decompress");
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_compression_small_data() {
        let data = b"tiny";
        let compressed = compress_bz2(data).expect("compress");
        let decompressed = decompress_bz2(&compressed).expect("decompress");
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_compression_empty_data() {
        let data = b"";
        let compressed = compress_bz2(data).expect("compress");
        let decompressed = decompress_bz2(&compressed).expect("decompress");
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_compression_reduces_size() {
        // Highly compressible data
        let data = vec![0x42u8; 10000];
        let compressed = compress_bz2(&data).expect("compress");
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_decompression_invalid_data() {
        let invalid_data = b"this is not valid bz2 data";
        let result = decompress_bz2(invalid_data);
        assert!(result.is_err());
    }
}
