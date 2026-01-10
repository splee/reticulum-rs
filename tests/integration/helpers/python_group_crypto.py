#!/usr/bin/env python3
"""
Test GROUP encryption/decryption interoperability with Rust.

This script generates GROUP keys and encrypts/decrypts data to verify
compatibility with the Rust implementation.
"""

import sys
import os

# Add the parent reticulum-python directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..', 'reticulum-python'))

from RNS.Cryptography.Token import Token

def main():
    mode = input().strip()  # encrypt or decrypt
    key_hex = input().strip()  # 64 bytes = 128 hex chars
    data_hex = input().strip()  # data to encrypt/decrypt

    # Parse key
    key_bytes = bytes.fromhex(key_hex)
    if len(key_bytes) != 64:
        print(f"ERROR: Key must be 64 bytes, got {len(key_bytes)}", file=sys.stderr)
        print("STATUS=ERROR")
        sys.exit(1)

    # Create Token with the key
    token = Token(key_bytes)

    # Parse data
    data_bytes = bytes.fromhex(data_hex)

    try:
        if mode == "encrypt":
            result = token.encrypt(data_bytes)
            print(f"RESULT={result.hex()}")
            print("STATUS=OK")
        elif mode == "decrypt":
            result = token.decrypt(data_bytes)
            print(f"RESULT={result.hex()}")
            print("STATUS=OK")
        else:
            print(f"ERROR: Unknown mode '{mode}'", file=sys.stderr)
            print("STATUS=ERROR")
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("STATUS=ERROR")
        sys.exit(1)

if __name__ == "__main__":
    main()
