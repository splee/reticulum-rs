use core::fmt;

use sha2::Digest;

use crate::buffer::StaticBuffer;
use crate::hash::AddressHash;
use crate::hash::Hash;
use crate::identity::RATCHET_ID_LENGTH;

// Reticulum core sizing constants (match Python defaults in RNS/Reticulum.py)
pub const RETICULUM_MTU: usize = 500;
pub const TRUNCATED_HASH_LEN: usize = 16; // 128-bit truncated hashes
pub const HEADER_MIN_SIZE: usize = 2 + 1 + TRUNCATED_HASH_LEN; // header + context + destination
pub const HEADER_MAX_SIZE: usize = 2 + 1 + (TRUNCATED_HASH_LEN * 2); // header + context + transport + destination
pub const IFAC_MIN_SIZE: usize = 1; // minimum IFAC size in bytes
pub const RETICULUM_MDU: usize = RETICULUM_MTU - HEADER_MAX_SIZE - IFAC_MIN_SIZE;
pub const AES_BLOCK_SIZE: usize = 16;
pub const TOKEN_OVERHEAD: usize = 48; // 16-byte IV + 32-byte HMAC

// Packet payload buffer size (plain MDU)
pub const PACKET_MDU: usize = RETICULUM_MDU;
pub const PACKET_IFAC_MAX_LENGTH: usize = 64usize;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum IfacFlag {
    Open = 0b0,
    Authenticated = 0b1,
}

impl From<u8> for IfacFlag {
    fn from(value: u8) -> Self {
        match value {
            0 => IfacFlag::Open,
            1 => IfacFlag::Authenticated,
            _ => IfacFlag::Open,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum HeaderType {
    Type1 = 0b0,
    Type2 = 0b1,
}

impl From<u8> for HeaderType {
    fn from(value: u8) -> Self {
        match value & 0b1 {
            0 => HeaderType::Type1,
            1 => HeaderType::Type2,
            _ => HeaderType::Type1,
        }
    }
}

/// Transport type for packet routing (1 bit).
///
/// In the wire protocol (matching Python):
/// - Bit 4: transport_type (0 = Broadcast, 1 = Transport)
/// - Bit 5: context_flag (separate field in Header)
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TransportType {
    /// Broadcast packet - not routed through specific transport
    Broadcast = 0b0,
    /// Transport packet - routed through a specific transport node
    Transport = 0b1,
}

impl From<u8> for TransportType {
    fn from(value: u8) -> Self {
        match value & 0b1 {
            0b0 => TransportType::Broadcast,
            0b1 => TransportType::Transport,
            _ => TransportType::Broadcast,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum DestinationType {
    Single = 0b00,
    Group = 0b01,
    Plain = 0b10,
    Link = 0b11,
}

impl From<u8> for DestinationType {
    fn from(value: u8) -> Self {
        match value & 0b11 {
            0b00 => DestinationType::Single,
            0b01 => DestinationType::Group,
            0b10 => DestinationType::Plain,
            0b11 => DestinationType::Link,
            _ => DestinationType::Single,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PacketType {
    Data = 0b00,
    Announce = 0b01,
    LinkRequest = 0b10,
    Proof = 0b11,
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value & 0b11 {
            0b00 => PacketType::Data,
            0b01 => PacketType::Announce,
            0b10 => PacketType::LinkRequest,
            0b11 => PacketType::Proof,
            _ => PacketType::Data,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PacketContext {
    None = 0x00,                    // Generic data packet
    Resource = 0x01,                // Packet is part of a resource
    ResourceAdvrtisement = 0x02,    // Packet is a resource advertisement
    ResourceRequest = 0x03,         // Packet is a resource part request
    ResourceHashUpdate = 0x04,      // Packet is a resource hashmap update
    ResourceProof = 0x05,           // Packet is a resource proof
    ResourceInitiatorCancel = 0x06, // Packet is a resource initiator cancel message
    ResourceReceiverCancel = 0x07,  // Packet is a resource receiver cancel message
    CacheRequest = 0x08,            // Packet is a cache request
    Request = 0x09,                 // Packet is a request
    Response = 0x0A,                // Packet is a response to a request
    PathResponse = 0x0B,            // Packet is a response to a path request
    Command = 0x0C,                 // Packet is a command
    CommandStatus = 0x0D,           // Packet is a status of an executed command
    Channel = 0x0E,                 // Packet contains link channel data
    KeepAlive = 0xFA,               // Packet is a keepalive packet
    LinkIdentify = 0xFB,            // Packet is a link peer identification proof
    LinkClose = 0xFC,               // Packet is a link close message
    LinkProof = 0xFD,               // Packet is a link packet proof
    LinkRTT = 0xFE,                 // Packet is a link request round-trip time measurement
    LinkRequestProof = 0xFF,        // Packet is a link request proof
}

impl From<u8> for PacketContext {
    fn from(value: u8) -> Self {
        match value {
            0x01 => PacketContext::Resource,
            0x02 => PacketContext::ResourceAdvrtisement,
            0x03 => PacketContext::ResourceRequest,
            0x04 => PacketContext::ResourceHashUpdate,
            0x05 => PacketContext::ResourceProof,
            0x06 => PacketContext::ResourceInitiatorCancel,
            0x07 => PacketContext::ResourceReceiverCancel,
            0x08 => PacketContext::CacheRequest,
            0x09 => PacketContext::Request,
            0x0A => PacketContext::Response,
            0x0B => PacketContext::PathResponse,
            0x0C => PacketContext::Command,
            0x0D => PacketContext::CommandStatus,
            0x0E => PacketContext::Channel,
            0xFA => PacketContext::KeepAlive,
            0xFB => PacketContext::LinkIdentify,
            0xFC => PacketContext::LinkClose,
            0xFD => PacketContext::LinkProof,
            0xFE => PacketContext::LinkRTT,
            0xFF => PacketContext::LinkRequestProof,
            _ => PacketContext::None,
        }
    }
}

/// Packet header containing routing and type information.
///
/// Wire format (matching Python):
/// - Bit 7: Reserved (ifac_flag handled at transport layer)
/// - Bit 6: header_type (0 = Type1, 1 = Type2)
/// - Bit 5: context_flag (0 = unset, 1 = set)
/// - Bit 4: transport_type (0 = Broadcast, 1 = Transport)
/// - Bits 2-3: destination_type
/// - Bits 0-1: packet_type
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Header {
    /// Interface authentication flag (handled separately at transport layer for IFAC).
    pub ifac_flag: IfacFlag,
    /// Header type: Type1 (normal) or Type2 (with transport ID).
    pub header_type: HeaderType,
    /// Context flag used for specific packet contexts.
    pub context_flag: bool,
    /// Transport type: Broadcast or Transport (routed).
    pub transport_type: TransportType,
    /// Destination type: Single, Group, Plain, or Link.
    pub destination_type: DestinationType,
    /// Packet type: Data, Announce, LinkRequest, or Proof.
    pub packet_type: PacketType,
    /// Number of hops this packet has traversed.
    pub hops: u8,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
            hops: 0,
        }
    }
}

impl Header {
    /// Encode header fields into the wire format meta byte.
    ///
    /// Wire format (matching Python Packet.get_packed_flags):
    /// - Bit 6: header_type
    /// - Bit 5: context_flag
    /// - Bit 4: transport_type
    /// - Bits 2-3: destination_type
    /// - Bits 0-1: packet_type
    ///
    /// Note: ifac_flag is NOT included in the meta byte - it's handled
    /// separately at the transport layer for IFAC authentication.
    pub fn to_meta(&self) -> u8 {
        (self.header_type as u8) << 6
            | (self.context_flag as u8) << 5
            | (self.transport_type as u8) << 4
            | (self.destination_type as u8) << 2
            | (self.packet_type as u8)
    }

    /// Decode header fields from the wire format meta byte.
    ///
    /// Wire format (matching Python Packet.unpack):
    /// - Bit 6: header_type
    /// - Bit 5: context_flag
    /// - Bit 4: transport_type
    /// - Bits 2-3: destination_type
    /// - Bits 0-1: packet_type
    pub fn from_meta(meta: u8) -> Self {
        Self {
            ifac_flag: IfacFlag::Open, // Handled separately at transport layer
            header_type: HeaderType::from(meta >> 6),
            context_flag: (meta >> 5) & 0b1 != 0,
            transport_type: TransportType::from(meta >> 4),
            destination_type: DestinationType::from(meta >> 2),
            packet_type: PacketType::from(meta),
            hops: 0,
        }
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display format: [ifac][header_type][context][transport][dest_type][pkt_type].hops
        write!(
            f,
            "{:b}{:b}{:b}{:b}{:0>2b}{:0>2b}.{}",
            self.ifac_flag as u8,
            self.header_type as u8,
            self.context_flag as u8,
            self.transport_type as u8,
            self.destination_type as u8,
            self.packet_type as u8,
            self.hops,
        )
    }
}

pub type PacketDataBuffer = StaticBuffer<PACKET_MDU>;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct PacketIfac {
    pub access_code: [u8; PACKET_IFAC_MAX_LENGTH],
    pub length: usize,
}

impl PacketIfac {
    pub fn new_from_slice(slice: &[u8]) -> Self {
        let mut access_code = [0u8; PACKET_IFAC_MAX_LENGTH];
        access_code[..slice.len()].copy_from_slice(slice);
        Self {
            access_code,
            length: slice.len(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.access_code[..self.length]
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Packet {
    pub header: Header,
    pub ifac: Option<PacketIfac>,
    pub destination: AddressHash,
    pub transport: Option<AddressHash>,
    pub context: PacketContext,
    pub data: PacketDataBuffer,
    /// Ratchet ID used for encryption/decryption (local metadata, not on wire).
    pub ratchet_id: Option<[u8; RATCHET_ID_LENGTH]>,
}

impl Packet {
    /// Compute packet hash matching Python's get_hashable_part().
    ///
    /// The hash includes: [meta & 0x0F] + destination + context + data
    /// This matches Python's get_hashable_part(), which excludes hops and
    /// (for HEADER_2) excludes the transport ID.
    pub fn hash(&self) -> Hash {
        Hash::new(
            Hash::generator()
                .chain_update([self.header.to_meta() & 0b00001111])
                .chain_update(self.destination.as_slice())
                .chain_update([self.context as u8])
                .chain_update(self.data.as_slice())
                .finalize()
                .into(),
        )
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            header: Default::default(),
            destination: AddressHash::new_empty(),
            data: Default::default(),
            ifac: None,
            transport: None,
            context: crate::packet::PacketContext::None,
            ratchet_id: None,
        }
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}", self.header)?;

        if let Some(transport) = self.transport {
            write!(f, " {}", transport)?;
        }

        write!(f, " {}", self.destination)?;

        write!(f, " 0x[{}]]", self.data.len())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for enum conversions from u8 values.
    mod enum_conversions {
        use super::*;

        #[test]
        fn test_ifac_flag_from_valid_values() {
            assert_eq!(IfacFlag::from(0), IfacFlag::Open);
            assert_eq!(IfacFlag::from(1), IfacFlag::Authenticated);
        }

        #[test]
        fn test_ifac_flag_from_invalid_defaults_to_open() {
            // Out-of-range values should default to Open
            assert_eq!(IfacFlag::from(2), IfacFlag::Open);
            assert_eq!(IfacFlag::from(255), IfacFlag::Open);
        }

        #[test]
        fn test_header_type_from_valid_values() {
            assert_eq!(HeaderType::from(0), HeaderType::Type1);
            assert_eq!(HeaderType::from(1), HeaderType::Type2);
        }

        #[test]
        fn test_header_type_masks_to_single_bit() {
            // Mask 0b1 means only lowest bit matters
            assert_eq!(HeaderType::from(0b10), HeaderType::Type1); // masked to 0
            assert_eq!(HeaderType::from(0b11), HeaderType::Type2); // masked to 1
            assert_eq!(HeaderType::from(0xFF), HeaderType::Type2); // masked to 1
        }

        #[test]
        fn test_transport_type_from_valid_values() {
            assert_eq!(TransportType::from(0b0), TransportType::Broadcast);
            assert_eq!(TransportType::from(0b1), TransportType::Transport);
        }

        #[test]
        fn test_transport_type_masks_to_one_bit() {
            // Only lowest bit matters
            assert_eq!(TransportType::from(0b10), TransportType::Broadcast);
            assert_eq!(TransportType::from(0b11), TransportType::Transport);
            assert_eq!(TransportType::from(0b100), TransportType::Broadcast);
            assert_eq!(TransportType::from(0b101), TransportType::Transport);
        }

        #[test]
        fn test_destination_type_from_valid_values() {
            assert_eq!(DestinationType::from(0b00), DestinationType::Single);
            assert_eq!(DestinationType::from(0b01), DestinationType::Group);
            assert_eq!(DestinationType::from(0b10), DestinationType::Plain);
            assert_eq!(DestinationType::from(0b11), DestinationType::Link);
        }

        #[test]
        fn test_destination_type_masks_to_two_bits() {
            assert_eq!(DestinationType::from(0b100), DestinationType::Single);
            assert_eq!(DestinationType::from(0xFF), DestinationType::Link); // 0b11
        }

        #[test]
        fn test_packet_type_from_valid_values() {
            assert_eq!(PacketType::from(0b00), PacketType::Data);
            assert_eq!(PacketType::from(0b01), PacketType::Announce);
            assert_eq!(PacketType::from(0b10), PacketType::LinkRequest);
            assert_eq!(PacketType::from(0b11), PacketType::Proof);
        }

        #[test]
        fn test_packet_type_masks_to_two_bits() {
            assert_eq!(PacketType::from(0b100), PacketType::Data);
            assert_eq!(PacketType::from(0b111), PacketType::Proof);
        }

        #[test]
        fn test_packet_context_from_valid_values() {
            assert_eq!(PacketContext::from(0x00), PacketContext::None);
            assert_eq!(PacketContext::from(0x01), PacketContext::Resource);
            assert_eq!(PacketContext::from(0x02), PacketContext::ResourceAdvrtisement);
            assert_eq!(PacketContext::from(0x03), PacketContext::ResourceRequest);
            assert_eq!(PacketContext::from(0x04), PacketContext::ResourceHashUpdate);
            assert_eq!(PacketContext::from(0x05), PacketContext::ResourceProof);
            assert_eq!(PacketContext::from(0x06), PacketContext::ResourceInitiatorCancel);
            assert_eq!(PacketContext::from(0x07), PacketContext::ResourceReceiverCancel);
            assert_eq!(PacketContext::from(0x08), PacketContext::CacheRequest);
            assert_eq!(PacketContext::from(0x09), PacketContext::Request);
            assert_eq!(PacketContext::from(0x0A), PacketContext::Response);
            assert_eq!(PacketContext::from(0x0B), PacketContext::PathResponse);
            assert_eq!(PacketContext::from(0x0C), PacketContext::Command);
            assert_eq!(PacketContext::from(0x0D), PacketContext::CommandStatus);
            assert_eq!(PacketContext::from(0x0E), PacketContext::Channel);
            assert_eq!(PacketContext::from(0xFA), PacketContext::KeepAlive);
            assert_eq!(PacketContext::from(0xFB), PacketContext::LinkIdentify);
            assert_eq!(PacketContext::from(0xFC), PacketContext::LinkClose);
            assert_eq!(PacketContext::from(0xFD), PacketContext::LinkProof);
            assert_eq!(PacketContext::from(0xFE), PacketContext::LinkRTT);
            assert_eq!(PacketContext::from(0xFF), PacketContext::LinkRequestProof);
        }

        #[test]
        fn test_packet_context_unknown_defaults_to_none() {
            // Values not explicitly mapped should return None
            assert_eq!(PacketContext::from(0x0F), PacketContext::None);
            assert_eq!(PacketContext::from(0x10), PacketContext::None);
            assert_eq!(PacketContext::from(0x50), PacketContext::None);
        }
    }

    /// Tests for Header serialization and deserialization.
    mod header_serialization {
        use super::*;

        #[test]
        fn test_header_default_values() {
            let header = Header::default();
            assert_eq!(header.ifac_flag, IfacFlag::Open);
            assert_eq!(header.header_type, HeaderType::Type1);
            assert_eq!(header.context_flag, false);
            assert_eq!(header.transport_type, TransportType::Broadcast);
            assert_eq!(header.destination_type, DestinationType::Single);
            assert_eq!(header.packet_type, PacketType::Data);
            assert_eq!(header.hops, 0);
        }

        #[test]
        fn test_header_default_to_meta_is_zero() {
            let header = Header::default();
            assert_eq!(header.to_meta(), 0b00000000);
        }

        #[test]
        fn test_header_to_meta_all_flags_set() {
            let header = Header {
                ifac_flag: IfacFlag::Authenticated, // Not included in meta byte
                header_type: HeaderType::Type2,
                context_flag: true,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                hops: 0, // hops not encoded in meta
            };
            // Wire format: 1 << 6 | 1 << 5 | 1 << 4 | 11 << 2 | 11
            // = 0b01000000 | 0b00100000 | 0b00010000 | 0b00001100 | 0b00000011
            // = 0b01111111 = 127 (0x7F)
            assert_eq!(header.to_meta(), 0x7F);
        }

        #[test]
        fn test_header_to_meta_bit_positions() {
            // Test each field individually to verify bit positions
            // Note: ifac_flag is NOT included in meta byte (handled at transport layer)
            let ifac_only = Header {
                ifac_flag: IfacFlag::Authenticated,
                ..Default::default()
            };
            assert_eq!(ifac_only.to_meta(), 0b00000000); // ifac not in meta

            let header_type_only = Header {
                header_type: HeaderType::Type2,
                ..Default::default()
            };
            assert_eq!(header_type_only.to_meta(), 0b01000000); // bit 6

            let context_flag_only = Header {
                context_flag: true,
                ..Default::default()
            };
            assert_eq!(context_flag_only.to_meta(), 0b00100000); // bit 5

            let transport_only = Header {
                transport_type: TransportType::Transport,
                ..Default::default()
            };
            assert_eq!(transport_only.to_meta(), 0b00010000); // bit 4

            let dest_group = Header {
                destination_type: DestinationType::Group,
                ..Default::default()
            };
            assert_eq!(dest_group.to_meta(), 0b00000100); // bits 2-3

            let pkt_announce = Header {
                packet_type: PacketType::Announce,
                ..Default::default()
            };
            assert_eq!(pkt_announce.to_meta(), 0b00000001); // bits 0-1
        }

        #[test]
        fn test_header_from_meta_zero() {
            let header = Header::from_meta(0b00000000);
            assert_eq!(header.ifac_flag, IfacFlag::Open); // Always Open (not stored in meta)
            assert_eq!(header.header_type, HeaderType::Type1);
            assert_eq!(header.context_flag, false);
            assert_eq!(header.transport_type, TransportType::Broadcast);
            assert_eq!(header.destination_type, DestinationType::Single);
            assert_eq!(header.packet_type, PacketType::Data);
            assert_eq!(header.hops, 0); // hops always 0 from from_meta
        }

        #[test]
        fn test_header_from_meta_all_set() {
            // 0x7F = 0b01111111 (all bits 0-6 set)
            let header = Header::from_meta(0x7F);
            assert_eq!(header.ifac_flag, IfacFlag::Open); // Not stored in meta
            assert_eq!(header.header_type, HeaderType::Type2);
            assert_eq!(header.context_flag, true);
            assert_eq!(header.transport_type, TransportType::Transport);
            assert_eq!(header.destination_type, DestinationType::Link);
            assert_eq!(header.packet_type, PacketType::Proof);
        }

        #[test]
        fn test_header_from_meta_with_bit_7_set() {
            // 0xFF has bit 7 set, but it should be ignored (not ifac_flag)
            let header = Header::from_meta(0xFF);
            assert_eq!(header.ifac_flag, IfacFlag::Open); // Bit 7 is NOT ifac_flag
            assert_eq!(header.header_type, HeaderType::Type2);
            assert_eq!(header.context_flag, true);
            assert_eq!(header.transport_type, TransportType::Transport);
            assert_eq!(header.destination_type, DestinationType::Link);
            assert_eq!(header.packet_type, PacketType::Proof);
        }

        #[test]
        fn test_header_round_trip() {
            let original = Header {
                ifac_flag: IfacFlag::Authenticated, // Not preserved in meta
                header_type: HeaderType::Type2,
                context_flag: true,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Group,
                packet_type: PacketType::Announce,
                hops: 5, // hops not preserved in round-trip via meta
            };
            let meta = original.to_meta();
            let reconstructed = Header::from_meta(meta);

            // ifac_flag is NOT preserved (not in meta byte)
            assert_eq!(reconstructed.ifac_flag, IfacFlag::Open);
            assert_eq!(original.header_type, reconstructed.header_type);
            assert_eq!(original.context_flag, reconstructed.context_flag);
            assert_eq!(original.transport_type, reconstructed.transport_type);
            assert_eq!(original.destination_type, reconstructed.destination_type);
            assert_eq!(original.packet_type, reconstructed.packet_type);
            // hops is NOT preserved - from_meta always sets hops to 0
            assert_eq!(reconstructed.hops, 0);
        }

        #[test]
        fn test_header_display_format() {
            let header = Header::default();
            let display = format!("{}", header);
            // Format: ifac(1) header_type(1) context(1) transport(1) dest(2) pkt(2) . hops
            // = "0 0 0 0 00 00 . 0"
            assert_eq!(display, "00000000.0");
        }

        #[test]
        fn test_header_display_format_with_values() {
            let header = Header {
                ifac_flag: IfacFlag::Authenticated,
                header_type: HeaderType::Type2,
                context_flag: true,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Group,
                packet_type: PacketType::Announce,
                hops: 7,
            };
            let display = format!("{}", header);
            // = "1 1 1 1 01 01 . 7" (ifac=1, header_type=1, context=1, transport=1, dest=01, pkt=01)
            assert_eq!(display, "11110101.7");
        }
    }

    /// Tests for PacketIfac.
    mod packet_ifac {
        use super::*;

        #[test]
        fn test_new_from_slice_copies_data() {
            let data = [1u8, 2, 3, 4, 5];
            let ifac = PacketIfac::new_from_slice(&data);
            assert_eq!(ifac.length, 5);
            assert_eq!(&ifac.access_code[..5], &data);
        }

        #[test]
        fn test_new_from_slice_empty() {
            let ifac = PacketIfac::new_from_slice(&[]);
            assert_eq!(ifac.length, 0);
        }

        #[test]
        fn test_as_slice_returns_valid_portion() {
            let data = [0xAA, 0xBB, 0xCC];
            let ifac = PacketIfac::new_from_slice(&data);
            assert_eq!(ifac.as_slice(), &[0xAA, 0xBB, 0xCC]);
        }

        #[test]
        fn test_as_slice_empty() {
            let ifac = PacketIfac::new_from_slice(&[]);
            assert!(ifac.as_slice().is_empty());
        }

        #[test]
        fn test_max_length_access_code() {
            let data = [0x42u8; PACKET_IFAC_MAX_LENGTH];
            let ifac = PacketIfac::new_from_slice(&data);
            assert_eq!(ifac.length, PACKET_IFAC_MAX_LENGTH);
            assert_eq!(ifac.as_slice().len(), PACKET_IFAC_MAX_LENGTH);
        }
    }

    /// Tests for Packet.
    mod packet {
        use super::*;

        #[test]
        fn test_packet_default() {
            let packet = Packet::default();
            assert_eq!(packet.header, Header::default());
            assert!(packet.destination.as_slice().iter().all(|&b| b == 0));
            assert_eq!(packet.data.len(), 0);
            assert!(packet.ifac.is_none());
            assert!(packet.transport.is_none());
            assert_eq!(packet.context, PacketContext::None);
        }

        #[test]
        fn test_packet_hash_deterministic() {
            let packet = Packet::default();
            let hash1 = packet.hash();
            let hash2 = packet.hash();
            assert_eq!(hash1, hash2);
        }

        #[test]
        fn test_packet_hash_changes_with_context() {
            let mut packet1 = Packet::default();
            packet1.context = PacketContext::None;
            let mut packet2 = Packet::default();
            packet2.context = PacketContext::Resource;

            assert_ne!(packet1.hash(), packet2.hash());
        }

        #[test]
        fn test_packet_hash_changes_with_destination() {
            let mut packet1 = Packet::default();
            packet1.destination = AddressHash::new_from_slice(&[0u8; 32]);
            let mut packet2 = Packet::default();
            packet2.destination = AddressHash::new_from_slice(&[1u8; 32]);

            assert_ne!(packet1.hash(), packet2.hash());
        }

        #[test]
        fn test_packet_hash_changes_with_data() {
            let mut packet1 = Packet::default();
            packet1.data.write(&[1, 2, 3]).unwrap();
            let mut packet2 = Packet::default();
            packet2.data.write(&[4, 5, 6]).unwrap();

            assert_ne!(packet1.hash(), packet2.hash());
        }

        #[test]
        fn test_packet_hash_masks_upper_meta_bits() {
            // Hash uses only lower 4 bits of meta: self.header.to_meta() & 0b00001111
            // So changes to header_type, context_flag, transport_type should NOT affect hash
            let mut packet1 = Packet::default();
            packet1.header.ifac_flag = IfacFlag::Open;
            packet1.header.header_type = HeaderType::Type1;
            packet1.header.context_flag = false;
            packet1.header.transport_type = TransportType::Broadcast;

            let mut packet2 = Packet::default();
            packet2.header.ifac_flag = IfacFlag::Authenticated;
            packet2.header.header_type = HeaderType::Type2;
            packet2.header.context_flag = true;
            packet2.header.transport_type = TransportType::Transport;

            // These should have same hash (upper bits masked out)
            assert_eq!(packet1.hash(), packet2.hash());
        }

        #[test]
        fn test_packet_hash_affected_by_destination_and_packet_type() {
            // Lower 4 bits include destination_type (bits 2-3) and packet_type (bits 0-1)
            let mut packet1 = Packet::default();
            packet1.header.destination_type = DestinationType::Single;
            packet1.header.packet_type = PacketType::Data;

            let mut packet2 = Packet::default();
            packet2.header.destination_type = DestinationType::Link;
            packet2.header.packet_type = PacketType::Proof;

            assert_ne!(packet1.hash(), packet2.hash());
        }

        #[test]
        fn test_packet_display_basic() {
            let packet = Packet::default();
            let display = format!("{}", packet);
            // Should contain header display and destination
            assert!(display.starts_with("[00000000.0"));
            assert!(display.ends_with("]"));
        }

        #[test]
        fn test_packet_display_with_transport() {
            let mut packet = Packet::default();
            // AddressHash::new_from_slice hashes input, so use new() for predictable output
            let transport_bytes = [0xABu8; 16]; // ADDRESS_HASH_SIZE is 16
            packet.transport = Some(AddressHash::new(transport_bytes));
            let display = format!("{}", packet);
            // AddressHash displays as /hex/ format
            // Should show /abababababababababababababababab/ for all 0xAB bytes
            assert!(display.contains("/abababababababababababababababab/"));
        }

        #[test]
        fn test_packet_display_shows_data_length() {
            let mut packet = Packet::default();
            packet.data.write(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).unwrap();
            let display = format!("{}", packet);
            assert!(display.contains("0x[10]")); // 10 bytes of data
        }

        #[test]
        fn test_packet_hash_includes_hops() {
            // Verify that changing hops does NOT change the hash (Python compatibility)
            let mut packet1 = Packet::default();
            packet1.header.hops = 0;

            let mut packet2 = Packet::default();
            packet2.header.hops = 5;

            // Hashes MUST match when only hops differ
            assert_eq!(
                packet1.hash(),
                packet2.hash(),
                "Packet hash must ignore hops byte for Python compatibility"
            );
        }

        #[test]
        fn test_packet_hash_hops_sensitivity() {
            // Test multiple hop values produce identical hashes
            let hashes: Vec<_> = (0..=5)
                .map(|h| {
                    let mut p = Packet::default();
                    p.header.hops = h;
                    p.hash()
                })
                .collect();

            // All hashes should be identical
            for i in 0..hashes.len() {
                for j in (i + 1)..hashes.len() {
                    assert_eq!(
                        hashes[i], hashes[j],
                        "Hops {} and {} should produce identical hashes",
                        i, j
                    );
                }
            }
        }
    }
}
