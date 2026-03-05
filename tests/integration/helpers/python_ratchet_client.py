#!/usr/bin/env python3
"""
Python ratchet client helper for integration testing.

Listens for announces and reports ratchet information when received.
Used to verify that Rust destinations properly send ratchet announces.
"""

import argparse
import sys
import time
import os
import tempfile
import RNS

# Global state
received_announces = []
running = True

class AnnounceHandler:
    """Handler class for receiving announces."""

    def __init__(self, aspect_filter=None):
        self.aspect_filter = aspect_filter

    def received_announce(self, destination_hash, announced_identity, app_data):
        """Callback when an announce is received."""
        global received_announces

        try:
            dest_hash_hex = destination_hash.hex()

            # Check if this announce has a ratchet
            # The ratchet is stored in Identity.known_ratchets after announce validation
            try:
                # Use correct API: current_ratchet_id instead of get_ratchet_id
                ratchet_id = RNS.Identity.current_ratchet_id(destination_hash)
                ratchet = RNS.Identity.get_ratchet(destination_hash)
            except Exception as e:
                RNS.log(f"Error getting ratchet info: {e}", RNS.LOG_DEBUG)
                ratchet_id = None
                ratchet = None

            announce_info = {
                'destination_hash': dest_hash_hex,
                'identity_hash': announced_identity.hexhash,
                'has_ratchet': ratchet is not None,
                'ratchet_id': ratchet_id.hex() if ratchet_id else None,
                'ratchet_public': ratchet.hex() if ratchet else None,
            }

            received_announces.append(announce_info)

            print(f"ANNOUNCE_RECEIVED={dest_hash_hex}", flush=True)
            print(f"ANNOUNCE_IDENTITY={announced_identity.hexhash}", flush=True)

            if ratchet is not None:
                print(f"ANNOUNCE_HAS_RATCHET=true", flush=True)
                print(f"ANNOUNCE_RATCHET_ID={ratchet_id.hex()}", flush=True)
                print(f"ANNOUNCE_RATCHET_PUBLIC={ratchet.hex()}", flush=True)
                RNS.log(f"Received announce with ratchet ID: {ratchet_id.hex()}", RNS.LOG_INFO)
            else:
                print(f"ANNOUNCE_HAS_RATCHET=false", flush=True)
                RNS.log(f"Received announce without ratchet for {dest_hash_hex}", RNS.LOG_INFO)

        except Exception as e:
            print(f"ANNOUNCE_ERROR={e}", flush=True)
            RNS.log(f"Error in announce handler: {e}", RNS.LOG_ERROR)
            import traceback
            traceback.print_exc()

def main():
    global running

    parser = argparse.ArgumentParser(description='Python ratchet client for testing')
    parser.add_argument('-a', '--app-name', default='test_app', help='Application name')
    parser.add_argument('-A', '--aspect', default='ratchetserver', help='Destination aspect to listen for')
    parser.add_argument('-d', '--destination', help='Specific destination hash to listen for')
    parser.add_argument('-n', '--announce-count', type=int, default=1, help='Exit after N announces')
    parser.add_argument('-t', '--timeout', type=int, default=60, help='Timeout in seconds')
    parser.add_argument('-c', '--configdir', help='Config directory')
    parser.add_argument('--tcp-client', help='TCP client target host:port')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    args = parser.parse_args()

    # Set log level
    if args.verbose:
        RNS.loglevel = RNS.LOG_DEBUG
    else:
        RNS.loglevel = RNS.LOG_INFO

    # Set up config directory
    temp_configdir = None
    if args.tcp_client and not args.configdir:
        temp_configdir = tempfile.mkdtemp(prefix="rns_ratchet_client_")
        RNS.log(f"Using temporary config directory: {temp_configdir}", RNS.LOG_INFO)

        host, port = args.tcp_client.rsplit(':', 1)
        config_content = f"""
[reticulum]
enable_transport = No
share_instance = No

[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    interface_enabled = True
    target_host = {host}
    target_port = {port}
"""
        config_path = os.path.join(temp_configdir, "config")
        with open(config_path, "w") as f:
            f.write(config_content)

        reticulum = RNS.Reticulum(configdir=temp_configdir)
    elif args.configdir:
        reticulum = RNS.Reticulum(configdir=args.configdir)
    else:
        reticulum = RNS.Reticulum()

    # Register announce handler (using handler class for proper callback)
    aspect_filter = f"{args.app_name}.{args.aspect}" if args.aspect else args.app_name
    handler = AnnounceHandler(aspect_filter)
    RNS.Transport.register_announce_handler(handler)

    print(f"LISTENING=true", flush=True)
    print(f"ASPECT_FILTER={aspect_filter}", flush=True)
    RNS.log(f"Listening for announces with ratchets (filter: {aspect_filter})...", RNS.LOG_INFO)

    # Wait for announces
    start_time = time.time()
    while running:
        if time.time() - start_time > args.timeout:
            print("TIMEOUT=true", flush=True)
            break

        if len(received_announces) >= args.announce_count:
            print(f"RECEIVED_COUNT={len(received_announces)}", flush=True)
            break

        time.sleep(0.5)

    # Summary
    ratchet_count = sum(1 for a in received_announces if a['has_ratchet'])
    print(f"TOTAL_RECEIVED={len(received_announces)}", flush=True)
    print(f"WITH_RATCHET={ratchet_count}", flush=True)
    print("COMPLETE=true", flush=True)

    # Cleanup
    if temp_configdir:
        import shutil
        try:
            shutil.rmtree(temp_configdir)
        except:
            pass

if __name__ == "__main__":
    main()
