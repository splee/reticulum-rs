#!/usr/bin/env python3
"""
Python GROUP destination server helper for integration testing.

Creates a GROUP destination, announces it, and listens for incoming packets.
Outputs events to stdout for test verification.
"""

import argparse
import sys
import time
import os
import RNS

# Global state
running = True
packet_count = 0

def handle_packet(message, packet):
    """Callback when a packet is received at the GROUP destination."""
    global packet_count
    packet_count += 1

    # Decrypt and display
    data_hex = message.hex() if isinstance(message, bytes) else message.encode().hex()
    print(f"PACKET_RECEIVED={packet_count}:{len(message)}:{data_hex}", flush=True)
    RNS.log(f"Received packet #{packet_count}: {len(message)} bytes", RNS.LOG_INFO)

def main():
    global running

    parser = argparse.ArgumentParser(description='Python GROUP destination server for testing')
    parser.add_argument('-a', '--app-name', default='test_app', help='Application name')
    parser.add_argument('-A', '--aspect', default='grouptest', help='Destination aspect')
    parser.add_argument('-i', '--announce-interval', type=int, default=30, help='Announce interval in seconds')
    parser.add_argument('-n', '--packet-count', type=int, default=0, help='Exit after N packets (0=infinite)')
    parser.add_argument('-t', '--timeout', type=int, default=60, help='Exit after N seconds')
    parser.add_argument('-k', '--key-file', help='Path to save/load group key')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    args = parser.parse_args()

    # Set log level
    if args.verbose:
        RNS.loglevel = RNS.LOG_DEBUG
    else:
        RNS.loglevel = RNS.LOG_INFO

    # Initialize Reticulum
    reticulum = RNS.Reticulum()

    # For GROUP destinations, we don't need an identity
    # Create GROUP destination
    destination = RNS.Destination(
        None,  # No identity needed for GROUP
        RNS.Destination.IN,
        RNS.Destination.GROUP,
        args.app_name,
        args.aspect
    )

    # Create a new symmetric key
    destination.create_keys()

    # Get the group key (64 bytes for AES-256-CBC)
    group_key = destination.get_private_key()
    group_key_hex = group_key.hex()

    # Verify key length
    assert len(group_key) == 64, f"Expected 64-byte key, got {len(group_key)} bytes"

    print(f"GROUP_KEY={group_key_hex}", flush=True)
    print(f"KEY_LENGTH={len(group_key)}", flush=True)
    RNS.log(f"Group key created: {group_key_hex[:32]}... ({len(group_key)} bytes)", RNS.LOG_INFO)

    # Save key to file if requested
    if args.key_file:
        with open(args.key_file, 'wb') as f:
            f.write(group_key)
        RNS.log(f"Group key saved to {args.key_file}", RNS.LOG_INFO)
        print(f"KEY_SAVED={args.key_file}", flush=True)

    # Set packet callback
    destination.set_packet_callback(handle_packet)

    dest_hash = destination.hash.hex()
    print(f"DESTINATION_HASH={dest_hash}", flush=True)
    RNS.log(f"Created GROUP destination: {args.app_name}.{args.aspect} with hash {dest_hash}", RNS.LOG_INFO)

    # Announce
    destination.announce()
    print("ANNOUNCE_SENT=1", flush=True)
    RNS.log("Sent initial announce", RNS.LOG_INFO)

    # Set up periodic announces
    announce_num = 1
    last_announce = time.time()
    start_time = time.time()

    try:
        while running:
            # Check timeout
            if args.timeout > 0 and (time.time() - start_time) >= args.timeout:
                RNS.log("Timeout reached, exiting", RNS.LOG_INFO)
                print("STATUS=TIMEOUT", flush=True)
                break

            # Check packet count
            if args.packet_count > 0 and packet_count >= args.packet_count:
                RNS.log(f"Reached packet limit ({args.packet_count}), exiting", RNS.LOG_INFO)
                print("STATUS=PACKET_LIMIT_REACHED", flush=True)
                break

            # Periodic announce
            if (time.time() - last_announce) >= args.announce_interval:
                announce_num += 1
                destination.announce()
                print(f"ANNOUNCE_SENT={announce_num}", flush=True)
                RNS.log(f"Sent announce #{announce_num}", RNS.LOG_INFO)
                last_announce = time.time()

            time.sleep(0.1)

    except KeyboardInterrupt:
        running = False

    print(f"TOTAL_PACKETS={packet_count}", flush=True)
    print("STATUS=SHUTDOWN", flush=True)
    RNS.log(f"GROUP server complete: {packet_count} packets", RNS.LOG_INFO)

    # Clean shutdown
    RNS.Transport.detach_interfaces()

if __name__ == "__main__":
    main()
