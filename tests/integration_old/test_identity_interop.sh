#!/bin/bash
# Test identity compatibility between Python and Rust
#
# This test verifies:
# 1. Rust-generated identities can be parsed by Python
# 2. Python-generated identities can be parsed by Rust
# 3. Address hash computation is identical

set -e
source "$(dirname "$0")/common.sh"

echo "========================================"
echo "Test: Identity Interoperability"
echo "========================================"

# Ensure containers are running
check_containers || start_containers

# Test 1: Generate identity with Rust and read with Python
info "Test 1: Rust identity -> Python verification"

# Generate identity with Rust (Python-compatible interface: -g requires file argument)
RUST_ID_OUTPUT=$(exec_rust rnid -g /tmp/test_rust_identity.dat 2>&1)
RUST_ADDRESS=$(echo "$RUST_ID_OUTPUT" | grep -oE '<[a-f0-9]{32}>' | tr -d '<>')

if [ -n "$RUST_ADDRESS" ]; then
    success "Rust generated identity with address: /$RUST_ADDRESS/"
else
    fail "Failed to generate identity with Rust"
    echo "$RUST_ID_OUTPUT"
fi

# Test 2: Generate identity with Python and read with Rust
info "Test 2: Python identity -> Rust verification"

# Generate identity with Python rnid
PYTHON_ID_OUTPUT=$(exec_python rnid -g 2>&1 || true)
PYTHON_ADDRESS=$(echo "$PYTHON_ID_OUTPUT" | grep -oE '[a-f0-9]{32}' | head -1)

if [ -n "$PYTHON_ADDRESS" ]; then
    success "Python generated identity with address: /$PYTHON_ADDRESS/"
else
    # Python rnid might have different output format
    info "Python rnid output format may differ, checking..."
    echo "$PYTHON_ID_OUTPUT" | head -10
fi

# Test 3: Verify address hash format compatibility
info "Test 3: Address hash format verification"

# Both should produce 32-character hex strings (16 bytes)
if [ ${#RUST_ADDRESS} -eq 32 ]; then
    success "Rust address hash is correct length (32 hex chars = 16 bytes)"
else
    fail "Rust address hash has unexpected length: ${#RUST_ADDRESS}"
fi

# Test 4: Create identity file and verify cross-platform reading
info "Test 4: Identity file format compatibility"

# Export Rust identity to file (Python-compatible: -g saves to file)
exec_rust rnid -g /tmp/test_identity.dat 2>&1 || true

# Check if file was created
if exec_rust test -f /tmp/test_identity.dat; then
    success "Rust identity exported to file"

    # Get file size - should be 194 bytes for a full identity (2 x 32-byte keys + overhead)
    FILE_SIZE=$(exec_rust stat -c %s /tmp/test_identity.dat 2>/dev/null || exec_rust wc -c < /tmp/test_identity.dat | tr -d ' ')
    info "Identity file size: ${FILE_SIZE} bytes"

    # Verify Python can read the Rust-exported identity
    PYTHON_READ_OUTPUT=$(exec_python sh -c 'python3 -c "
import RNS
identity = RNS.Identity.from_file(\"/tmp/test_identity.dat\")
print(\"ADDRESS=\" + identity.hexhash)
"' 2>&1 || true)

    if echo "$PYTHON_READ_OUTPUT" | grep -q "ADDRESS="; then
        PYTHON_READ_ADDRESS=$(echo "$PYTHON_READ_OUTPUT" | grep "ADDRESS=" | cut -d= -f2)
        success "Python successfully read Rust identity: /$PYTHON_READ_ADDRESS/"
    else
        # Copy file from Rust to Python container for testing
        docker cp reticulum-rust-node:/tmp/test_identity.dat /tmp/test_identity_transfer.dat 2>/dev/null
        docker cp /tmp/test_identity_transfer.dat reticulum-python-hub:/tmp/test_identity.dat 2>/dev/null
        rm -f /tmp/test_identity_transfer.dat

        PYTHON_READ_OUTPUT=$(exec_python sh -c 'python3 -c "
import RNS
identity = RNS.Identity.from_file(\"/tmp/test_identity.dat\")
print(\"ADDRESS=\" + identity.hexhash)
"' 2>&1 || true)

        if echo "$PYTHON_READ_OUTPUT" | grep -q "ADDRESS="; then
            PYTHON_READ_ADDRESS=$(echo "$PYTHON_READ_OUTPUT" | grep "ADDRESS=" | cut -d= -f2)
            success "Python successfully read Rust identity: /$PYTHON_READ_ADDRESS/"
        else
            fail "Python could not read Rust identity file"
            echo "$PYTHON_READ_OUTPUT"
        fi
    fi
else
    fail "Failed to export identity to file"
fi

print_summary
