#!/usr/bin/env python3
"""
Python packet codec for integration testing.

This script provides the same stdin interface as test_packet_codec.rs for
cross-validation of packet encoding/decoding between Python and Rust.

Commands:
    encode <json>     - Encode packet fields to raw bytes
    decode <hex>      - Decode raw packet bytes to fields
    meta_encode <json> - Encode header fields to meta byte only
    meta_decode <hex>  - Decode meta byte to header fields
"""

import sys
import os
import json
import struct

# Add the parent reticulum-python directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..', 'reticulum-python'))

import RNS


def encode_packet(json_str: str) -> dict:
    """Encode packet fields into raw bytes following Python's wire format."""
    data = json.loads(json_str)

    # Parse fields
    header_type = data.get('header_type', 0)
    context_flag = 1 if data.get('context_flag', False) else 0
    transport_type = data.get('transport_type', 0)
    destination_type = data.get('destination_type', 0)
    packet_type = data.get('packet_type', 0)
    hops = data.get('hops', 0)
    context = data.get('context', 0)

    # Parse destination (16 bytes hex)
    dest_hex = data.get('destination', '00000000000000000000000000000000')
    destination = bytes.fromhex(dest_hex)
    if len(destination) != 16:
        raise ValueError(f"Destination must be 16 bytes, got {len(destination)}")

    # Parse transport_id (optional, for Type2)
    transport_id = None
    if header_type == 1:  # Type2
        transport_hex = data.get('transport_id')
        if not transport_hex:
            raise ValueError("Type2 header requires transport_id")
        transport_id = bytes.fromhex(transport_hex)
        if len(transport_id) != 16:
            raise ValueError(f"Transport ID must be 16 bytes, got {len(transport_id)}")

    # Parse data
    data_hex = data.get('data', '')
    payload = bytes.fromhex(data_hex) if data_hex else b''

    # Build meta byte (flags)
    # Wire format (matching Python Packet.get_packed_flags):
    # - Bit 6: header_type (0 = Type1, 1 = Type2)
    # - Bit 5: context_flag
    # - Bit 4: transport_type (0 = Broadcast, 1 = Transport)
    # - Bits 2-3: destination_type
    # - Bits 0-1: packet_type
    meta_byte = (header_type << 6) | (context_flag << 5) | (transport_type << 4) | (destination_type << 2) | packet_type

    # Build packet
    raw = b""
    raw += struct.pack("!B", meta_byte)  # flags
    raw += struct.pack("!B", hops)       # hops

    if header_type == 1:  # Type2
        raw += transport_id

    raw += destination
    raw += struct.pack("!B", context)
    raw += payload

    return {
        'raw_bytes': raw.hex(),
        'meta_byte': f'{meta_byte:02x}'
    }


def decode_packet(hex_str: str) -> dict:
    """Decode raw packet bytes to fields."""
    raw = bytes.fromhex(hex_str.strip())

    if len(raw) < 2:
        raise ValueError("Packet too short (minimum 2 bytes for header)")

    # Parse flags
    flags = raw[0]
    hops = raw[1]

    header_type = (flags & 0b01000000) >> 6
    context_flag = (flags & 0b00100000) >> 5
    transport_type = (flags & 0b00010000) >> 4
    destination_type = (flags & 0b00001100) >> 2
    packet_type = (flags & 0b00000011)

    DST_LEN = 16  # RNS.Reticulum.TRUNCATED_HASHLENGTH // 8

    result = {
        'header_type': header_type,
        'context_flag': context_flag,
        'transport_type': transport_type,
        'destination_type': destination_type,
        'packet_type': packet_type,
        'hops': hops,
        'meta_byte': f'{flags:02x}'
    }

    if header_type == 1:  # Type2
        transport_id = raw[2:DST_LEN+2]
        destination = raw[DST_LEN+2:2*DST_LEN+2]
        context = raw[2*DST_LEN+2]
        data = raw[2*DST_LEN+3:]
        result['transport_id'] = transport_id.hex()
    else:  # Type1
        destination = raw[2:DST_LEN+2]
        context = raw[DST_LEN+2]
        data = raw[DST_LEN+3:]

    result['destination'] = destination.hex()
    result['context'] = context
    result['data'] = data.hex()

    return result


def meta_encode(json_str: str) -> dict:
    """Encode header fields to meta byte only."""
    data = json.loads(json_str)

    header_type = data.get('header_type', 0)
    context_flag = 1 if data.get('context_flag', False) else 0
    transport_type = data.get('transport_type', 0)
    destination_type = data.get('destination_type', 0)
    packet_type = data.get('packet_type', 0)

    meta_byte = (header_type << 6) | (context_flag << 5) | (transport_type << 4) | (destination_type << 2) | packet_type

    return {
        'meta_byte': f'{meta_byte:02x}'
    }


def meta_decode(hex_str: str) -> dict:
    """Decode meta byte to header fields."""
    raw = bytes.fromhex(hex_str.strip())
    if len(raw) == 0:
        raise ValueError("Empty meta byte")

    flags = raw[0]

    header_type = (flags & 0b01000000) >> 6
    context_flag = (flags & 0b00100000) >> 5
    transport_type = (flags & 0b00010000) >> 4
    destination_type = (flags & 0b00001100) >> 2
    packet_type = (flags & 0b00000011)

    return {
        'header_type': header_type,
        'context_flag': context_flag,
        'transport_type': transport_type,
        'destination_type': destination_type,
        'packet_type': packet_type,
        'meta_byte': f'{flags:02x}'
    }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        parts = line.split(' ', 1)
        cmd = parts[0]
        arg = parts[1] if len(parts) > 1 else ''

        try:
            if cmd == 'encode':
                result = encode_packet(arg)
                print(f"RAW_BYTES={result['raw_bytes']}")
                print(f"META_BYTE={result['meta_byte']}")
                print("STATUS=OK")
            elif cmd == 'decode':
                result = decode_packet(arg)
                print(f"HEADER_TYPE={result['header_type']}")
                print(f"CONTEXT_FLAG={result['context_flag']}")
                print(f"TRANSPORT_TYPE={result['transport_type']}")
                print(f"DESTINATION_TYPE={result['destination_type']}")
                print(f"PACKET_TYPE={result['packet_type']}")
                print(f"HOPS={result['hops']}")
                print(f"CONTEXT={result['context']}")
                print(f"DESTINATION={result['destination']}")
                if 'transport_id' in result:
                    print(f"TRANSPORT_ID={result['transport_id']}")
                print(f"DATA={result['data']}")
                print(f"META_BYTE={result['meta_byte']}")
                print("STATUS=OK")
            elif cmd == 'meta_encode':
                result = meta_encode(arg)
                print(f"META_BYTE={result['meta_byte']}")
                print("STATUS=OK")
            elif cmd == 'meta_decode':
                result = meta_decode(arg)
                print(f"HEADER_TYPE={result['header_type']}")
                print(f"CONTEXT_FLAG={result['context_flag']}")
                print(f"TRANSPORT_TYPE={result['transport_type']}")
                print(f"DESTINATION_TYPE={result['destination_type']}")
                print(f"PACKET_TYPE={result['packet_type']}")
                print(f"META_BYTE={result['meta_byte']}")
                print("STATUS=OK")
            else:
                print(f"ERROR=Unknown command: {cmd}")
        except Exception as e:
            print(f"ERROR={e}")

        sys.stdout.flush()


if __name__ == "__main__":
    main()
