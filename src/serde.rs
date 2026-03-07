use crate::{
    buffer::{InputBuffer, OutputBuffer, StaticBuffer},
    error::RnsError,
    hash::AddressHash,
    packet::{Header, HeaderType, Packet, PacketContext},
};

pub trait Serialize {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError>;
}

impl Serialize for AddressHash {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(self.as_slice())
    }
}

impl Serialize for Header {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(&[self.to_meta(), self.hops])
    }
}
impl Serialize for PacketContext {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(&[*self as u8])
    }
}

impl Serialize for Packet {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        self.header.serialize(buffer)?;

        if self.header.header_type == HeaderType::Type2 {
            if let Some(transport) = &self.transport {
                transport.serialize(buffer)?;
            }
        }

        self.destination.serialize(buffer)?;

        self.context.serialize(buffer)?;

        buffer.write(self.data.as_slice())
    }
}

impl Header {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<Header, RnsError> {
        let mut header = Header::from_meta(buffer.read_byte()?);
        header.hops = buffer.read_byte()?;

        Ok(header)
    }
}

impl AddressHash {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<AddressHash, RnsError> {
        let mut address = AddressHash::new_empty();

        buffer.read(address.as_mut_slice())?;

        Ok(address)
    }
}

impl PacketContext {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<PacketContext, RnsError> {
        Ok(PacketContext::from(buffer.read_byte()?))
    }
}
impl Packet {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<Packet, RnsError> {
        let header = Header::deserialize(buffer)?;

        let transport = if header.header_type == HeaderType::Type2 {
            Some(AddressHash::deserialize(buffer)?)
        } else {
            None
        };

        let destination = AddressHash::deserialize(buffer)?;

        let context = PacketContext::deserialize(buffer)?;

        let mut packet = Packet {
            header,
            ifac: None,
            destination,
            transport,
            context,
            data: StaticBuffer::new(),
            ratchet_id: None,
        };

        buffer.read(packet.data.accuire_buf(buffer.bytes_left())?)?;

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::{
        buffer::{InputBuffer, OutputBuffer, StaticBuffer},
        hash::AddressHash,
        packet::{
            DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketType,
            TransportType,
        },
    };

    use crate::packet::{PACKET_DATA_MAX, RETICULUM_MTU};

    use super::Serialize;

    #[test]
    fn serialize_packet() {
        let mut output_data = [0u8; 4096];

        let mut buffer = OutputBuffer::new(&mut output_data);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: AddressHash::new_from_rand(OsRng),
            transport: None,
            context: PacketContext::None,
            data: StaticBuffer::new(),
            ratchet_id: None,
        };

        packet.serialize(&mut buffer).expect("serialized packet");

        println!("{}", buffer);
    }

    #[test]
    fn deserialize_packet() {
        let mut output_data = [0u8; 4096];

        let mut buffer = OutputBuffer::new(&mut output_data);

        let mut packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: AddressHash::new_from_rand(OsRng),
            transport: None,
            context: PacketContext::None,
            data: StaticBuffer::new(),
            ratchet_id: None,
        };

        packet.data.safe_write(b"Hello, world!");

        packet.serialize(&mut buffer).expect("serialized packet");

        let mut input_buffer = InputBuffer::new(buffer.as_slice());

        let new_packet = Packet::deserialize(&mut input_buffer).expect("deserialized packet");

        assert_eq!(packet.header, new_packet.header);
        assert_eq!(packet.destination, new_packet.destination);
        assert_eq!(packet.transport, new_packet.transport);
        assert_eq!(packet.context, new_packet.context);
        assert_eq!(packet.data.as_slice(), new_packet.data.as_slice());
    }

    /// Verify that packets with data between RETICULUM_MTU and PACKET_DATA_MAX
    /// (the expanded buffer range) deserialize successfully. This covers the
    /// case where a Python peer using link MTU discovery sends packets larger
    /// than the standard 500-byte MTU through a Rust relay hub.
    #[test]
    fn deserialize_oversized_mtu_packet_succeeds() {
        // Simulate a resource transfer packet with 595 bytes of data — the
        // scenario from issue #25 where Python endpoints negotiate an MTU
        // above 500 bytes via link MTU discovery.
        let data_len = 595;
        assert!(data_len > RETICULUM_MTU, "data must exceed standard MTU");
        assert!(data_len <= PACKET_DATA_MAX, "data must fit in expanded buffer");

        let wire_len = 19 + data_len; // Type1 header (19 bytes) + data
        let mut raw = vec![0u8; wire_len];
        raw[0] = 0x00; // Type1, Broadcast, Single, Data
        raw[1] = 0;
        raw[18] = 0x00; // context
        for byte in raw[19..].iter_mut() {
            *byte = 0xCC;
        }

        let mut input_buffer = InputBuffer::new(&raw);
        let packet = Packet::deserialize(&mut input_buffer)
            .expect("packet with data between MTU and PACKET_DATA_MAX should deserialize");
        assert_eq!(packet.data.len(), data_len);
        assert!(packet.data.as_slice().iter().all(|&b| b == 0xCC));
    }

    /// Verify that a packet at the exact PACKET_DATA_MAX boundary succeeds.
    #[test]
    fn deserialize_max_buffer_packet_succeeds() {
        let data_len = PACKET_DATA_MAX;
        let wire_len = 19 + data_len;
        let mut raw = vec![0u8; wire_len];
        raw[0] = 0x00;
        raw[1] = 0;
        raw[18] = 0x00;
        for byte in raw[19..].iter_mut() {
            *byte = 0xDD;
        }

        let mut input_buffer = InputBuffer::new(&raw);
        let packet = Packet::deserialize(&mut input_buffer)
            .expect("packet at exact PACKET_DATA_MAX should deserialize");
        assert_eq!(packet.data.len(), data_len);
    }

    /// Verify that a packet whose data exceeds PACKET_DATA_MAX returns an
    /// error instead of panicking.
    #[test]
    fn deserialize_oversized_packet_returns_error() {
        // Build a raw wire packet with a data payload that exceeds PACKET_DATA_MAX.
        // Header (Type1): 2 bytes (meta + hops) + 16 bytes destination + 1 byte context = 19 bytes
        // Fill the remaining space with more data than the buffer can hold.
        let oversized_data_len = PACKET_DATA_MAX + 1;
        let wire_len = 2 + 16 + 1 + oversized_data_len; // header + dest + context + data
        let mut raw = vec![0u8; wire_len];
        // meta byte: all zeros = Type1, Broadcast, Single, Data
        raw[0] = 0x00;
        // hops
        raw[1] = 0;
        // destination: 16 zero bytes (already zero)
        // context byte at offset 18
        raw[18] = 0x00;
        // data: fill with 0xAA starting at offset 19
        for byte in raw[19..].iter_mut() {
            *byte = 0xAA;
        }

        let mut input_buffer = InputBuffer::new(&raw);
        let result = Packet::deserialize(&mut input_buffer);
        assert!(result.is_err(), "oversized packet should return an error, not panic");
    }

    /// Verify that a packet using the full MTU worth of data deserializes
    /// successfully (the largest valid data payload after a Type1 header).
    #[test]
    fn deserialize_max_data_packet_succeeds() {
        // Type1 header consumes 19 bytes, leaving MTU - 19 = 481 bytes for data.
        let data_len = RETICULUM_MTU - 19;
        assert!(data_len <= PACKET_DATA_MAX, "data_len must fit in buffer");
        let wire_len = 19 + data_len;
        let mut raw = vec![0u8; wire_len];
        raw[0] = 0x00; // Type1, Broadcast, Single, Data
        raw[1] = 0;
        raw[18] = 0x00; // context
        for byte in raw[19..].iter_mut() {
            *byte = 0xBB;
        }

        let mut input_buffer = InputBuffer::new(&raw);
        let packet = Packet::deserialize(&mut input_buffer).expect("max-data packet should deserialize");
        assert_eq!(packet.data.len(), data_len);
        assert!(packet.data.as_slice().iter().all(|&b| b == 0xBB));
    }
}
