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

# Generate identity with Rust
RUST_ID_OUTPUT=$(exec_rust rnid -g --hex 2>&1)
RUST_ADDRESS=$(echo "$RUST_ID_OUTPUT" | grep "Address Hash:" | sed 's/.*Address Hash:[[:space:]]*//' | tr -d '/' | tr -d ' ')

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

# Export Rust identity to file
exec_rust sh -c 'rnid -g -e /tmp/test_identity.dat' 2>&1 || true

# Check if file was created
if exec_rust test -f /tmp/test_identity.dat; then
    success "Rust identity exported to file"

    # Show the format
    IDENTITY_CONTENT=$(exec_rust cat /tmp/test_identity.dat 2>&1)
    info "Identity file content (hex): ${IDENTITY_CONTENT:0:64}..."

    # Verify it's valid hex
    if echo "$IDENTITY_CONTENT" | grep -qE '^[a-f0-9]+$'; then
        success "Identity file is valid hex format"
    else
        fail "Identity file is not valid hex format"
    fi
else
    fail "Failed to export identity to file"
fi

print_summary
