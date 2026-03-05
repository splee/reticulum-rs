#!/usr/bin/env python3
"""
Create an identity for testing.

Saves identity in binary format (64 bytes) which is compatible with both
Python and Rust implementations.

Usage:
    python3 create_identity.py [output_path]

Example:
    python3 create_identity.py /tmp/test_identity
"""

import RNS
import sys
import os

def main():
    output_path = sys.argv[1] if len(sys.argv) > 1 else None

    # Create a new random identity
    identity = RNS.Identity()

    # Output the hash
    identity_hash = identity.hash.hex()
    print(f"IDENTITY_HASH={identity_hash}")

    # Save to file if path specified
    if output_path:
        # Create directory if needed
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Save in binary format (compatible with both Python and Rust)
        identity.to_file(output_path)
        print(f"IDENTITY_FILE={output_path}")

if __name__ == "__main__":
    main()
