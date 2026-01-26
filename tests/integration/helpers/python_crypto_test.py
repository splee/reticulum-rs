#!/usr/bin/env python3
"""
Python crypto primitives for integration testing.

This script provides the same stdin interface as test_crypto_primitives.rs for
cross-validation of cryptographic operations between Python and Rust.

Commands:
    ed25519-sign <priv_hex> <msg_hex>         - Sign a message
    ed25519-verify <pub_hex> <msg_hex> <sig>  - Verify a signature
    x25519-keygen [seed_hex]                   - Generate X25519 key pair
    x25519-exchange <priv_hex> <peer_pub_hex> - Perform key exchange
    hkdf-derive <secret_hex> [salt_hex]       - Derive key using HKDF
"""

import sys
import os

# Add the parent reticulum-python directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..', 'reticulum-python'))

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

# Import RNS's custom HKDF instead of the cryptography library's HKDF
from RNS.Cryptography.HKDF import hkdf as rns_hkdf


def ed25519_sign(priv_hex: str, msg_hex: str) -> dict:
    """Sign a message using Ed25519."""
    priv_bytes = bytes.fromhex(priv_hex)
    msg_bytes = bytes.fromhex(msg_hex)

    if len(priv_bytes) != 32:
        raise ValueError(f"Private key must be 32 bytes, got {len(priv_bytes)}")

    # Create signing key from raw bytes
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    # Sign the message
    signature = private_key.sign(msg_bytes)

    return {
        'signature': signature.hex()
    }


def ed25519_verify(pub_hex: str, msg_hex: str, sig_hex: str) -> dict:
    """Verify an Ed25519 signature."""
    pub_bytes = bytes.fromhex(pub_hex)
    msg_bytes = bytes.fromhex(msg_hex)
    sig_bytes = bytes.fromhex(sig_hex)

    if len(pub_bytes) != 32:
        raise ValueError(f"Public key must be 32 bytes, got {len(pub_bytes)}")
    if len(sig_bytes) != 64:
        raise ValueError(f"Signature must be 64 bytes, got {len(sig_bytes)}")

    # Create verifying key from raw bytes
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

    # Verify the signature
    try:
        public_key.verify(sig_bytes, msg_bytes)
        valid = True
    except Exception:
        valid = False

    return {
        'valid': valid
    }


def x25519_keygen(seed_hex: str = None) -> dict:
    """Generate an X25519 key pair."""
    if seed_hex:
        seed_bytes = bytes.fromhex(seed_hex)
        if len(seed_bytes) != 32:
            raise ValueError(f"Seed must be 32 bytes, got {len(seed_bytes)}")
        # Use seed as private key directly
        private_key = x25519.X25519PrivateKey.from_private_bytes(seed_bytes)
    else:
        private_key = x25519.X25519PrivateKey.generate()

    public_key = private_key.public_key()

    # Get raw bytes
    priv_bytes = private_key.private_bytes_raw()
    pub_bytes = public_key.public_bytes_raw()

    return {
        'priv_key': priv_bytes.hex(),
        'pub_key': pub_bytes.hex()
    }


def x25519_exchange(priv_hex: str, peer_pub_hex: str) -> dict:
    """Perform X25519 key exchange."""
    priv_bytes = bytes.fromhex(priv_hex)
    peer_pub_bytes = bytes.fromhex(peer_pub_hex)

    if len(priv_bytes) != 32:
        raise ValueError(f"Private key must be 32 bytes, got {len(priv_bytes)}")
    if len(peer_pub_bytes) != 32:
        raise ValueError(f"Peer public key must be 32 bytes, got {len(peer_pub_bytes)}")

    private_key = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)

    shared_secret = private_key.exchange(peer_public_key)

    return {
        'shared_secret': shared_secret.hex()
    }


def hkdf_derive(secret_hex: str, salt_hex: str = None) -> dict:
    """Derive a key using RNS's custom HKDF-SHA256.

    Uses RNS/Cryptography/HKDF.py which has custom behavior:
    - Counter: (i + 1) % 256 as single byte
    - Salt defaults to 32 zero bytes when None or empty
    - Context/info defaults to empty bytes
    """
    secret_bytes = bytes.fromhex(secret_hex)
    salt_bytes = bytes.fromhex(salt_hex) if salt_hex else None

    # Match the Rust DERIVED_KEY_LENGTH (64 bytes for AES-256, 32 bytes for AES-128)
    # Default is 64 bytes (512 / 8) for non-fernet-aes128 feature
    derived_key_length = 64

    # Use RNS's custom HKDF implementation
    derived_key = rns_hkdf(
        length=derived_key_length,
        derive_from=secret_bytes,
        salt=salt_bytes,
        context=None  # Empty context, matching Rust
    )

    return {
        'derived_key': derived_key.hex()
    }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        parts = line.split(' ', 1)
        cmd = parts[0]
        args = parts[1] if len(parts) > 1 else ''
        arg_parts = args.split()

        try:
            if cmd == 'ed25519-sign':
                if len(arg_parts) < 2:
                    raise ValueError("Usage: ed25519-sign <priv_hex> <msg_hex>")
                result = ed25519_sign(arg_parts[0], arg_parts[1])
                print(f"SIGNATURE={result['signature']}")
                print("STATUS=OK")

            elif cmd == 'ed25519-verify':
                if len(arg_parts) < 3:
                    raise ValueError("Usage: ed25519-verify <pub_hex> <msg_hex> <sig_hex>")
                result = ed25519_verify(arg_parts[0], arg_parts[1], arg_parts[2])
                print(f"VALID={str(result['valid']).lower()}")
                print("STATUS=OK")

            elif cmd == 'x25519-keygen':
                seed = arg_parts[0] if arg_parts else None
                result = x25519_keygen(seed)
                print(f"PRIV_KEY={result['priv_key']}")
                print(f"PUB_KEY={result['pub_key']}")
                print("STATUS=OK")

            elif cmd == 'x25519-exchange':
                if len(arg_parts) < 2:
                    raise ValueError("Usage: x25519-exchange <priv_hex> <peer_pub_hex>")
                result = x25519_exchange(arg_parts[0], arg_parts[1])
                print(f"SHARED_SECRET={result['shared_secret']}")
                print("STATUS=OK")

            elif cmd == 'hkdf-derive':
                if len(arg_parts) < 1:
                    raise ValueError("Usage: hkdf-derive <secret_hex> [salt_hex]")
                salt = arg_parts[1] if len(arg_parts) > 1 else None
                result = hkdf_derive(arg_parts[0], salt)
                print(f"DERIVED_KEY={result['derived_key']}")
                print("STATUS=OK")

            else:
                print(f"ERROR=Unknown command: {cmd}")

        except Exception as e:
            print(f"ERROR={e}")

        sys.stdout.flush()


if __name__ == "__main__":
    main()
