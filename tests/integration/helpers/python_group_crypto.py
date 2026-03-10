#!/usr/bin/env python3
"""
Test GROUP encryption/decryption interoperability with Rust.

This script handles multiple commands via stdin to verify GROUP key
compatibility with the Rust implementation:
- encrypt/decrypt: Fernet token encryption/decryption
- key-split: Verify key half interpretation (signing vs encryption)
- address-hash: Compute GROUP destination address hash
"""

import sys
import os
import hashlib

# Add the parent reticulum-python directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..', 'reticulum-python'))

from RNS.Cryptography.Token import Token


def handle_encrypt_decrypt(mode, lines):
    """Handle encrypt or decrypt commands."""
    key_hex = next(lines).strip()
    data_hex = next(lines).strip()

    key_bytes = bytes.fromhex(key_hex)
    if len(key_bytes) != 64:
        print(f"ERROR: Key must be 64 bytes, got {len(key_bytes)}", file=sys.stderr)
        print("STATUS=ERROR")
        return False

    token = Token(key_bytes)
    data_bytes = bytes.fromhex(data_hex)

    try:
        if mode == "encrypt":
            result = token.encrypt(data_bytes)
        else:
            result = token.decrypt(data_bytes)
        print(f"RESULT={result.hex()}")
        print("STATUS=OK")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("STATUS=ERROR")
        return False

    return True


def handle_key_split(lines):
    """Split a 64-byte key into signing (first 32) and encryption (last 32) halves."""
    key_hex = next(lines).strip()
    key_bytes = bytes.fromhex(key_hex)

    if len(key_bytes) != 64:
        print(f"ERROR: Key must be 64 bytes, got {len(key_bytes)}", file=sys.stderr)
        print("STATUS=ERROR")
        return False

    signing_key = key_bytes[:32]
    encryption_key = key_bytes[32:]

    print(f"SIGNING_KEY={signing_key.hex()}")
    print(f"ENCRYPTION_KEY={encryption_key.hex()}")
    print("STATUS=OK")
    return True


def handle_address_hash(lines):
    """Compute a GROUP destination address hash matching Rust's algorithm.

    Algorithm:
    1. name_hash = SHA256(app_name + "." + aspects) — full 32 bytes
    2. key_hash = SHA256(full_key) — full 32 bytes
    3. address_hash = SHA256(name_hash[:10] + key_hash)[:16]
    """
    key_hex = next(lines).strip()
    app_name = next(lines).strip()
    aspects = next(lines).strip()

    key_bytes = bytes.fromhex(key_hex)
    if len(key_bytes) != 64:
        print(f"ERROR: Key must be 64 bytes, got {len(key_bytes)}", file=sys.stderr)
        print("STATUS=ERROR")
        return False

    # Step 1: name_hash = SHA256(app_name + "." + aspects)
    name_hash = hashlib.sha256(
        app_name.encode('utf-8') + b"." + aspects.encode('utf-8')
    ).digest()

    # Step 2: key_hash = SHA256(full_key)
    key_hash = hashlib.sha256(key_bytes).digest()

    # Step 3: address_hash = SHA256(name_hash[:10] + key_hash)[:16]
    address_hash = hashlib.sha256(name_hash[:10] + key_hash).digest()[:16]

    print(f"ADDRESS_HASH={address_hash.hex()}")
    print("STATUS=OK")
    return True


def main():
    lines = iter(sys.stdin)
    mode = next(lines).strip()

    try:
        if mode in ("encrypt", "decrypt"):
            success = handle_encrypt_decrypt(mode, lines)
        elif mode == "key-split":
            success = handle_key_split(lines)
        elif mode == "address-hash":
            success = handle_address_hash(lines)
        else:
            print(f"ERROR: Unknown mode '{mode}'", file=sys.stderr)
            print("STATUS=ERROR")
            success = False
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("STATUS=ERROR")
        success = False

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
