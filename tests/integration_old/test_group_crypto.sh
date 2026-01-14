#!/bin/bash
# Test GROUP destination encryption/decryption interoperability
#
# This test verifies that:
# 1. Python and Rust use the same 64-byte key format for AES-256-CBC
# 2. Data encrypted by Python can be decrypted by Rust
# 3. Data encrypted by Rust can be decrypted by Python

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== GROUP Encryption Interoperability Test ===${NC}"
echo ""

# Build the Rust binary
echo "Building Rust test binary..."
cargo build --bin test_group_crypto --quiet

# Use a fixed 64-byte key for reproducibility (128 hex chars)
KEY="5ea11018b20f83455bf49ae8e2b7a1315ea11018b20f83455bf49ae8e2b7a1315ea11018b20f83455bf49ae8e2b7a1315ea11018b20f83455bf49ae8e2b7a131"
echo "Using 64-byte test key: ${KEY:0:32}..."

# Test data
PLAINTEXT="48656c6c6f2c2047524f555020776f726c6421"  # "Hello, GROUP world!" in hex
echo "Plaintext: ${PLAINTEXT} (Hello, GROUP world!)"
echo ""

# Test 1: Python encrypts, Rust decrypts
echo -e "${YELLOW}Test 1: Python encrypts, Rust decrypts${NC}"

# Python encrypt using heredoc to avoid shell interpolation issues
PYTHON_OUTPUT=$(cat << PYEOF | python3 "$SCRIPT_DIR/helpers/python_group_crypto.py" 2>&1
encrypt
$KEY
$PLAINTEXT
PYEOF
)
PYTHON_CIPHERTEXT=$(echo "$PYTHON_OUTPUT" | grep "^RESULT=" | cut -d= -f2)

if [ -z "$PYTHON_CIPHERTEXT" ]; then
    echo -e "${RED}FAILED: Python encryption failed${NC}"
    echo "Python output: $PYTHON_OUTPUT"
    exit 1
fi
echo "Python ciphertext: ${PYTHON_CIPHERTEXT:0:32}..."

# Rust decrypt using heredoc
RUST_OUTPUT=$(cat << RSEOF | ./target/debug/test_group_crypto 2>&1
decrypt
$KEY
$PYTHON_CIPHERTEXT
RSEOF
)
RUST_DECRYPTED=$(echo "$RUST_OUTPUT" | grep "^RESULT=" | cut -d= -f2)

if [ -z "$RUST_DECRYPTED" ]; then
    echo -e "${RED}FAILED: Rust decryption failed${NC}"
    echo "Rust output: $RUST_OUTPUT"
    exit 1
fi
echo "Rust decrypted: ${RUST_DECRYPTED}"

if [ "$RUST_DECRYPTED" = "$PLAINTEXT" ]; then
    echo -e "${GREEN}PASSED: Python->Rust interop works!${NC}"
else
    echo -e "${RED}FAILED: Decrypted data doesn't match${NC}"
    echo "Expected: $PLAINTEXT"
    echo "Got: $RUST_DECRYPTED"
    exit 1
fi

echo ""

# Test 2: Rust encrypts, Python decrypts
echo -e "${YELLOW}Test 2: Rust encrypts, Python decrypts${NC}"

# Rust encrypt using heredoc
RUST_ENC_OUTPUT=$(cat << RSEOF | ./target/debug/test_group_crypto 2>&1
encrypt
$KEY
$PLAINTEXT
RSEOF
)
RUST_CIPHERTEXT=$(echo "$RUST_ENC_OUTPUT" | grep "^RESULT=" | cut -d= -f2)

if [ -z "$RUST_CIPHERTEXT" ]; then
    echo -e "${RED}FAILED: Rust encryption failed${NC}"
    echo "Rust output: $RUST_ENC_OUTPUT"
    exit 1
fi
echo "Rust ciphertext: ${RUST_CIPHERTEXT:0:32}..."

# Python decrypt using heredoc
PYTHON_DEC_OUTPUT=$(cat << PYEOF | python3 "$SCRIPT_DIR/helpers/python_group_crypto.py" 2>&1
decrypt
$KEY
$RUST_CIPHERTEXT
PYEOF
)
PYTHON_DECRYPTED=$(echo "$PYTHON_DEC_OUTPUT" | grep "^RESULT=" | cut -d= -f2)

if [ -z "$PYTHON_DECRYPTED" ]; then
    echo -e "${RED}FAILED: Python decryption failed${NC}"
    echo "Python output: $PYTHON_DEC_OUTPUT"
    exit 1
fi
echo "Python decrypted: ${PYTHON_DECRYPTED}"

if [ "$PYTHON_DECRYPTED" = "$PLAINTEXT" ]; then
    echo -e "${GREEN}PASSED: Rust->Python interop works!${NC}"
else
    echo -e "${RED}FAILED: Decrypted data doesn't match${NC}"
    echo "Expected: $PLAINTEXT"
    echo "Got: $PYTHON_DECRYPTED"
    exit 1
fi

echo ""
echo -e "${GREEN}=== All GROUP encryption tests PASSED ===${NC}"
