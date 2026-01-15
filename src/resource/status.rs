//! Resource status and flag types.
//!
//! This module contains the status enum and flag types used by the Resource
//! transfer system.

/// Resource status
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[derive(Default)]
pub enum ResourceStatus {
    /// No status
    #[default]
    None = 0x00,
    /// Resource is queued for transfer
    Queued = 0x01,
    /// Resource advertisement has been sent
    Advertised = 0x02,
    /// Resource is currently transferring
    Transferring = 0x03,
    /// Waiting for proof after all parts sent
    AwaitingProof = 0x04,
    /// Assembling received parts
    Assembling = 0x05,
    /// Transfer completed successfully
    Complete = 0x06,
    /// Transfer failed
    Failed = 0x07,
    /// Resource data is corrupt
    Corrupt = 0x08,
}

impl From<u8> for ResourceStatus {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ResourceStatus::None,
            0x01 => ResourceStatus::Queued,
            0x02 => ResourceStatus::Advertised,
            0x03 => ResourceStatus::Transferring,
            0x04 => ResourceStatus::AwaitingProof,
            0x05 => ResourceStatus::Assembling,
            0x06 => ResourceStatus::Complete,
            0x07 => ResourceStatus::Failed,
            0x08 => ResourceStatus::Corrupt,
            _ => ResourceStatus::None,
        }
    }
}

/// Flags for resource advertisements
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceFlags {
    /// Whether the resource is encrypted
    pub encrypted: bool,
    /// Whether the resource is compressed
    pub compressed: bool,
    /// Whether the resource is split into segments
    pub split: bool,
    /// Whether this is a request
    pub is_request: bool,
    /// Whether this is a response
    pub is_response: bool,
    /// Whether the resource has metadata
    pub has_metadata: bool,
}

impl ResourceFlags {
    /// Pack flags into a single byte
    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.encrypted {
            flags |= 0x01;
        }
        if self.compressed {
            flags |= 0x02;
        }
        if self.split {
            flags |= 0x04;
        }
        if self.is_request {
            flags |= 0x08;
        }
        if self.is_response {
            flags |= 0x10;
        }
        if self.has_metadata {
            flags |= 0x20;
        }
        flags
    }

    /// Unpack flags from a single byte
    pub fn from_byte(byte: u8) -> Self {
        Self {
            encrypted: (byte & 0x01) != 0,
            compressed: (byte & 0x02) != 0,
            split: (byte & 0x04) != 0,
            is_request: (byte & 0x08) != 0,
            is_response: (byte & 0x10) != 0,
            has_metadata: (byte & 0x20) != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_flags() {
        let flags = ResourceFlags {
            encrypted: true,
            compressed: true,
            split: false,
            is_request: true,
            is_response: false,
            has_metadata: true,
        };

        let byte = flags.to_byte();
        let restored = ResourceFlags::from_byte(byte);

        assert_eq!(flags.encrypted, restored.encrypted);
        assert_eq!(flags.compressed, restored.compressed);
        assert_eq!(flags.split, restored.split);
        assert_eq!(flags.is_request, restored.is_request);
        assert_eq!(flags.is_response, restored.is_response);
        assert_eq!(flags.has_metadata, restored.has_metadata);
    }

    #[test]
    fn test_resource_status_conversion() {
        assert_eq!(ResourceStatus::from(0x00), ResourceStatus::None);
        assert_eq!(ResourceStatus::from(0x03), ResourceStatus::Transferring);
        assert_eq!(ResourceStatus::from(0x06), ResourceStatus::Complete);
        assert_eq!(ResourceStatus::from(0xFF), ResourceStatus::None);
    }
}
