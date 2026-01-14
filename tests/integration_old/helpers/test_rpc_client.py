#!/usr/bin/env python3
"""
Simple test client for Python-Rust RPC interoperability.
Connects to a Reticulum RPC server and tests basic operations.
"""

import sys
import os
import struct
import hashlib
import multiprocessing.connection as mpc

def full_hash(data: bytes) -> bytes:
    """Compute SHA-256 hash (matching Reticulum's full_hash)."""
    return hashlib.sha256(data).digest()

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <rpc_address> <identity_file>")
        print("  rpc_address: unix:/path/to/socket OR host:port")
        print("  identity_file: path to 64-byte daemon identity file")
        sys.exit(1)

    rpc_address = sys.argv[1]
    identity_file = sys.argv[2]

    # Parse address - either Unix socket or TCP
    if rpc_address.startswith('unix:'):
        addr = rpc_address[5:]  # Strip 'unix:' prefix
        family = 'AF_UNIX'
    else:
        host, port = rpc_address.split(':')
        port = int(port)
        addr = (host, port)
        family = 'AF_INET'

    # Load identity and derive RPC key
    if not os.path.exists(identity_file):
        print(f"Identity file not found: {identity_file}")
        sys.exit(1)

    with open(identity_file, 'rb') as f:
        identity_bytes = f.read()

    if len(identity_bytes) != 64:
        print(f"Invalid identity file size: {len(identity_bytes)} bytes (expected 64)")
        sys.exit(1)

    rpc_key = full_hash(identity_bytes)
    print(f"RPC key: {rpc_key.hex()[:16]}...")

    def connect():
        """Create a new connection (each request needs its own connection)."""
        return mpc.Client(addr, family=family, authkey=rpc_key)

    # Test 1: Get interface stats
    print("\nTest 1: get_interface_stats")
    try:
        client = connect()
        print("Connected and authenticated!")
        client.send({"get": "interface_stats"})
        response = client.recv()
        client.close()
        print(f"Response type: {type(response)}")
        if isinstance(response, dict):
            print(f"Response keys: {list(response.keys())[:5]}")
            for key in list(response.keys())[:3]:
                print(f"  {key}: {type(response[key])}")
        elif response is None:
            print("Response: None (no stats available)")
        else:
            print(f"Response: {response}")
        print("Test 1: PASSED")
    except Exception as e:
        print(f"Test 1 FAILED: {e}")

    # Test 2: Get path table
    print("\nTest 2: get_path_table")
    try:
        client = connect()
        print("Connected!")
        client.send({"get": "path_table", "max_hops": None})
        response = client.recv()
        client.close()
        print(f"Response type: {type(response)}")
        if isinstance(response, list):
            print(f"Path count: {len(response)}")
            for path in response[:2]:
                print(f"  {path}")
        else:
            print(f"Response: {response}")
        print("Test 2: PASSED")
    except Exception as e:
        print(f"Test 2 FAILED: {e}")

    print("\nAll tests completed!")

if __name__ == '__main__':
    main()
