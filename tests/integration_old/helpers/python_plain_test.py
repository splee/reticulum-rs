#!/usr/bin/env python3
"""
Test PLAIN destination address hash computation for Python-Rust interoperability.

PLAIN destinations compute their address hash solely from the app name and aspects.
This script computes and outputs the hash for verification against Rust.
"""

import sys
import os

# Add the parent reticulum-python directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..', 'reticulum-python'))

import RNS

def compute_plain_hash(app_name, aspects):
    """Compute the address hash for a PLAIN destination."""
    # Initialize Reticulum (required for Identity methods)
    # We use a minimal config
    RNS.Reticulum(configdir=None)

    # Create a PLAIN destination
    destination = RNS.Destination(
        None,  # No identity for PLAIN
        RNS.Destination.IN,
        RNS.Destination.PLAIN,
        app_name,
        aspects
    )

    return destination.hash.hex()

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <app_name> <aspects>", file=sys.stderr)
        sys.exit(1)

    app_name = sys.argv[1]
    aspects = sys.argv[2]

    hash_hex = compute_plain_hash(app_name, aspects)
    print(f"PLAIN_HASH={hash_hex}")
    print("STATUS=OK")

if __name__ == "__main__":
    main()
