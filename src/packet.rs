use core::fmt;

use sha2::Digest;

use crate::buffer::StaticBuffer;
use crate::hash::AddressHash;
use crate::hash::Hash;

pub const PACKET_MDU: usize = 2048usize;
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

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PropagationType {
    Broadcast = 0b00,
    Transport = 0b01,
    Reserved1 = 0b10,
    Reserved2 = 0b11,
}

impl From<u8> for PropagationType {
    fn from(value: u8) -> Self {
        match value & 0b11 {
            0b00 => PropagationType::Broadcast,
            0b01 => PropagationType::Transport,
            0b10 => PropagationType::Reserved1,
            0b11 => PropagationType::Reserved2,
            _ => PropagationType::Broadcast,
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

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Header {
    pub ifac_flag: IfacFlag,
    pub header_type: HeaderType,
    pub propagation_type: PropagationType,
    pub destination_type: DestinationType,
    pub packet_type: PacketType,
    pub hops: u8,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
            hops: 0,
        }
    }
}

impl Header {
    pub fn to_meta(&self) -> u8 {
        
        (self.ifac_flag as u8) << 7
            | (self.header_type as u8) << 6
            | (self.propagation_type as u8) << 4
            | (self.destination_type as u8) << 2
            | (self.packet_type as u8)
    }

    pub fn from_meta(meta: u8) -> Self {
        Self {
            ifac_flag: IfacFlag::from(meta >> 7),
            header_type: HeaderType::from(meta >> 6),
            propagation_type: PropagationType::from(meta >> 4),
            destination_type: DestinationType::from(meta >> 2),
            packet_type: PacketType::from(meta),
            hops: 0,
        }
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:b}{:b}{:0>2b}{:0>2b}{:0>2b}.{}",
            self.ifac_flag as u8,
            self.header_type as u8,
            self.propagation_type as u8,
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
}

impl Packet {
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
        fn test_propagation_type_from_valid_values() {
            assert_eq!(PropagationType::from(0b00), PropagationType::Broadcast);
            assert_eq!(PropagationType::from(0b01), PropagationType::Transport);
            assert_eq!(PropagationType::from(0b10), PropagationType::Reserved1);
            assert_eq!(PropagationType::from(0b11), PropagationType::Reserved2);
        }

        #[test]
        fn test_propagation_type_masks_to_two_bits() {
            // Only lowest 2 bits matter
            assert_eq!(PropagationType::from(0b100), PropagationType::Broadcast);
            assert_eq!(PropagationType::from(0b101), PropagationType::Transport);
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
            assert_eq!(header.propagation_type, PropagationType::Broadcast);
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
                ifac_flag: IfacFlag::Authenticated,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Reserved2,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                hops: 0, // hops not encoded in meta
            };
            // 1 << 7 | 1 << 6 | 11 << 4 | 11 << 2 | 11
            // = 0b10000000 | 0b01000000 | 0b00110000 | 0b00001100 | 0b00000011
            // = 0b11111111 = 255
            assert_eq!(header.to_meta(), 0xFF);
        }

        #[test]
        fn test_header_to_meta_bit_positions() {
            // Test each field individually to verify bit positions
            let ifac_only = Header {
                ifac_flag: IfacFlag::Authenticated,
                ..Default::default()
            };
            assert_eq!(ifac_only.to_meta(), 0b10000000);

            let header_type_only = Header {
                header_type: HeaderType::Type2,
                ..Default::default()
            };
            assert_eq!(header_type_only.to_meta(), 0b01000000);

            let prop_transport = Header {
                propagation_type: PropagationType::Transport,
                ..Default::default()
            };
            assert_eq!(prop_transport.to_meta(), 0b00010000);

            let dest_group = Header {
                destination_type: DestinationType::Group,
                ..Default::default()
            };
            assert_eq!(dest_group.to_meta(), 0b00000100);

            let pkt_announce = Header {
                packet_type: PacketType::Announce,
                ..Default::default()
            };
            assert_eq!(pkt_announce.to_meta(), 0b00000001);
        }

        #[test]
        fn test_header_from_meta_zero() {
            let header = Header::from_meta(0b00000000);
            assert_eq!(header.ifac_flag, IfacFlag::Open);
            assert_eq!(header.header_type, HeaderType::Type1);
            assert_eq!(header.propagation_type, PropagationType::Broadcast);
            assert_eq!(header.destination_type, DestinationType::Single);
            assert_eq!(header.packet_type, PacketType::Data);
            assert_eq!(header.hops, 0); // hops always 0 from from_meta
        }

        #[test]
        fn test_header_from_meta_all_set() {
            let header = Header::from_meta(0xFF);
            assert_eq!(header.ifac_flag, IfacFlag::Authenticated);
            assert_eq!(header.header_type, HeaderType::Type2);
            assert_eq!(header.propagation_type, PropagationType::Reserved2);
            assert_eq!(header.destination_type, DestinationType::Link);
            assert_eq!(header.packet_type, PacketType::Proof);
        }

        #[test]
        fn test_header_round_trip() {
            let original = Header {
                ifac_flag: IfacFlag::Authenticated,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Group,
                packet_type: PacketType::Announce,
                hops: 5, // hops not preserved in round-trip via meta
            };
            let meta = original.to_meta();
            let reconstructed = Header::from_meta(meta);

            assert_eq!(original.ifac_flag, reconstructed.ifac_flag);
            assert_eq!(original.header_type, reconstructed.header_type);
            assert_eq!(original.propagation_type, reconstructed.propagation_type);
            assert_eq!(original.destination_type, reconstructed.destination_type);
            assert_eq!(original.packet_type, reconstructed.packet_type);
            // hops is NOT preserved - from_meta always sets hops to 0
            assert_eq!(reconstructed.hops, 0);
        }

        #[test]
        fn test_header_display_format() {
            let header = Header::default();
            let display = format!("{}", header);
            // Format: "{:b}{:b}{:0>2b}{:0>2b}{:0>2b}.{}"
            // = "0 0 00 00 00 . 0"
            assert_eq!(display, "00000000.0");
        }

        #[test]
        fn test_header_display_format_with_values() {
            let header = Header {
                ifac_flag: IfacFlag::Authenticated,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Group,
                packet_type: PacketType::Announce,
                hops: 7,
            };
            let display = format!("{}", header);
            // = "1 1 01 01 01 . 7"
            assert_eq!(display, "11010101.7");
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
            // So changes to ifac_flag, header_type, propagation_type should NOT affect hash
            let mut packet1 = Packet::default();
            packet1.header.ifac_flag = IfacFlag::Open;
            packet1.header.header_type = HeaderType::Type1;
            packet1.header.propagation_type = PropagationType::Broadcast;

            let mut packet2 = Packet::default();
            packet2.header.ifac_flag = IfacFlag::Authenticated;
            packet2.header.header_type = HeaderType::Type2;
            packet2.header.propagation_type = PropagationType::Reserved2;

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
    }
}
