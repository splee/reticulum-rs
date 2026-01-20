#!/usr/bin/env python3
"""
Python ratchet server helper for integration testing.

Creates a destination with ratchets enabled, announces it, and outputs
ratchet information for verification by Rust tests.
"""

import argparse
import sys
import time
import os
import tempfile
import RNS

def main():
    parser = argparse.ArgumentParser(description='Python ratchet server for testing')
    parser.add_argument('-a', '--app-name', default='test_app', help='Application name')
    parser.add_argument('-A', '--aspect', default='ratchetserver', help='Destination aspect')
    parser.add_argument('-i', '--announce-interval', type=int, default=5, help='Announce interval in seconds')
    parser.add_argument('-n', '--announce-count', type=int, default=3, help='Number of announces')
    parser.add_argument('-t', '--timeout', type=int, default=60, help='Total timeout in seconds')
    parser.add_argument('-c', '--configdir', help='Config directory')
    parser.add_argument('--tcp-client', help='TCP client target host:port')
    parser.add_argument('--ratchets-path', help='Path for ratchet file (default: temp file)')
    parser.add_argument('--enforce-ratchets', action='store_true', help='Enforce ratchet usage')
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
        temp_configdir = tempfile.mkdtemp(prefix="rns_ratchet_server_")
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

    # Create identity
    identity = RNS.Identity()
    print(f"IDENTITY_HASH={identity.hexhash}", flush=True)

    # Create destination
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        args.app_name,
        args.aspect
    )

    dest_hash = destination.hexhash
    print(f"DESTINATION_HASH={dest_hash}", flush=True)

    # Set up ratchets
    if args.ratchets_path:
        ratchets_path = args.ratchets_path
    else:
        # Use temp file for ratchets
        ratchets_dir = temp_configdir if temp_configdir else tempfile.gettempdir()
        ratchets_path = os.path.join(ratchets_dir, f"ratchets_{dest_hash[:16]}")

    try:
        destination.enable_ratchets(ratchets_path)
        print(f"RATCHETS_ENABLED=true", flush=True)
        print(f"RATCHETS_PATH={ratchets_path}", flush=True)

        if args.enforce_ratchets:
            destination.enforce_ratchets = True
            print(f"RATCHETS_ENFORCED=true", flush=True)

    except Exception as e:
        print(f"RATCHETS_ERROR={e}", flush=True)
        RNS.log(f"Failed to enable ratchets: {e}", RNS.LOG_ERROR)
        sys.exit(1)

    # Announce with ratchet
    start_time = time.time()
    announce_count = 0

    while announce_count < args.announce_count:
        if time.time() - start_time > args.timeout:
            print("TIMEOUT=true", flush=True)
            break

        # Announce the destination
        destination.announce()
        announce_count += 1

        # Get ratchet info after announce (ratchet is rotated during announce)
        if destination.ratchets and len(destination.ratchets) > 0:
            # Get the current ratchet public key
            current_ratchet = destination.ratchets[0]
            ratchet_pub = RNS.Identity._ratchet_public_bytes(current_ratchet)
            ratchet_id = RNS.Identity._get_ratchet_id(ratchet_pub)

            print(f"ANNOUNCE_SENT={announce_count}", flush=True)
            print(f"RATCHET_ID={ratchet_id.hex()}", flush=True)
            print(f"RATCHET_PUBLIC={ratchet_pub.hex()}", flush=True)
            print(f"RATCHET_COUNT={len(destination.ratchets)}", flush=True)

            RNS.log(f"Announced with ratchet ID: {ratchet_id.hex()}", RNS.LOG_INFO)
        else:
            print(f"ANNOUNCE_SENT={announce_count}", flush=True)
            print(f"RATCHET_ID=none", flush=True)
            RNS.log(f"Announced (no ratchet)", RNS.LOG_WARNING)

        if announce_count < args.announce_count:
            time.sleep(args.announce_interval)

    print(f"TOTAL_ANNOUNCES={announce_count}", flush=True)
    print("COMPLETE=true", flush=True)

    # Keep running briefly to allow announces to propagate
    time.sleep(2)

    # Cleanup
    if temp_configdir:
        import shutil
        try:
            shutil.rmtree(temp_configdir)
        except:
            pass

if __name__ == "__main__":
    main()
