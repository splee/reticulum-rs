#!/bin/bash
# Test resource transfer from Rust (sender) to Python (receiver)
# This tests the Rust → Python resource transfer direction

set -e
source "$(dirname "$0")/common.sh"

echo "========================================"
echo "Test: Rust sends Resource to Python"
echo "========================================"

# Ensure containers are running
check_containers || start_containers

# Give nodes time to stabilize
sleep 3

# Test 1: Small resource transfer
info "Test 1: Rust sends small resource to Python"

# Start Python resource server in background
PYTHON_SERVER_OUTPUT=$(mktemp)
timeout 60 docker exec reticulum-python-hub python3 /app/helpers/python_resource_server.py \
    -a test_app -A resourceserver \
    -n 1 -t 50 -i 5 -v \
    > "$PYTHON_SERVER_OUTPUT" 2>&1 &
PYTHON_PID=$!

# Wait for Python to start and announce
sleep 3

# Get Python destination hash
PYTHON_DEST=""
for i in {1..30}; do
    if grep -q "DESTINATION_HASH=" "$PYTHON_SERVER_OUTPUT"; then
        PYTHON_DEST=$(grep "DESTINATION_HASH=" "$PYTHON_SERVER_OUTPUT" | head -1 | cut -d= -f2)
        break
    fi
    sleep 0.3
done

# Wait for announce to propagate
sleep 3

if [ -z "$PYTHON_DEST" ]; then
    fail "Could not get Python destination hash"
    cat "$PYTHON_SERVER_OUTPUT"
    kill $PYTHON_PID 2>/dev/null
    print_summary
    exit 1
fi

info "Python destination hash: $PYTHON_DEST"

# Test data to send (hex encoded "Hello from Rust!")
TEST_DATA_HEX="48656c6c6f2066726f6d205275737421"
info "Sending resource from Rust..."

# Rust client connects and sends resource
RUST_CLIENT_OUTPUT=$(mktemp)
timeout 60 docker exec reticulum-rust-node test_resource_client \
    --tcp-client python-hub:14242 \
    -d "$PYTHON_DEST" \
    -a test_app -A resourceserver \
    -s "$TEST_DATA_HEX" \
    -t 45 -v \
    > "$RUST_CLIENT_OUTPUT" 2>&1 || true

RUST_EXIT=$?

# Wait for resource transfer to complete
sleep 5

# Wait for Python server to process (it should exit after receiving resource with -n 1)
for i in {1..10}; do
    if ! kill -0 $PYTHON_PID 2>/dev/null; then
        break
    fi
    sleep 1
done
kill $PYTHON_PID 2>/dev/null || true
wait $PYTHON_PID 2>/dev/null || true

# Check results
info "Rust client output:"
cat "$RUST_CLIENT_OUTPUT"

info "Python server output:"
cat "$PYTHON_SERVER_OUTPUT"

# Verify link was established on both sides
if grep -q "LINK_ACTIVATED=" "$RUST_CLIENT_OUTPUT"; then
    success "Rust client established link"
else
    fail "Rust client failed to establish link"
fi

if grep -q "LINK_ACTIVATED=" "$PYTHON_SERVER_OUTPUT"; then
    success "Python server received link activation"
else
    fail "Python server did not receive link activation"
fi

# Verify resource was advertised by Rust
if grep -q "RESOURCE_ADVERTISED=" "$RUST_CLIENT_OUTPUT"; then
    success "Rust advertised resource"
else
    fail "Rust did not advertise resource"
fi

# Verify resource was received by Python (check for STARTED since we may skip OFFERED)
if grep -q "RESOURCE_STARTED=" "$PYTHON_SERVER_OUTPUT"; then
    success "Python started resource transfer"
else
    fail "Python did not start resource transfer"
fi

# Check for resource completion
if grep -q "RESOURCE_COMPLETE=" "$PYTHON_SERVER_OUTPUT"; then
    success "Python completed resource transfer"

    # Verify the data content
    COMPLETE_LINE=$(grep "RESOURCE_COMPLETE=" "$PYTHON_SERVER_OUTPUT" | head -1)
    RECEIVED_DATA_HEX=$(echo "$COMPLETE_LINE" | cut -d: -f3)

    if [ "$RECEIVED_DATA_HEX" = "$TEST_DATA_HEX" ]; then
        success "Resource data matches expected content"
    else
        fail "Resource data mismatch: expected $TEST_DATA_HEX, got $RECEIVED_DATA_HEX"
    fi
else
    fail "Python did not complete resource transfer"
fi

# Check for proof received by Rust
if grep -q "RESOURCE_PROOF_RECEIVED=" "$RUST_CLIENT_OUTPUT"; then
    success "Rust received resource proof from Python"
else
    fail "Rust did not receive resource proof"
fi

# Check overall success
if grep -q "RESOURCE_TRANSFER_COMPLETE=" "$RUST_CLIENT_OUTPUT"; then
    success "Rust→Python resource transfer complete"
else
    fail "Rust→Python resource transfer did not complete"
fi

# Clean up temp files
rm -f "$PYTHON_SERVER_OUTPUT" "$RUST_CLIENT_OUTPUT"

# -------------------------------------------------
# Test 2: Larger resource transfer
# -------------------------------------------------
info "Test 2: Rust sends larger resource to Python"

# Start Python resource server again
PYTHON_SERVER_OUTPUT2=$(mktemp)
timeout 60 docker exec reticulum-python-hub python3 /app/helpers/python_resource_server.py \
    -a test_app -A resourceserver2 \
    -n 1 -t 50 -i 5 \
    > "$PYTHON_SERVER_OUTPUT2" 2>&1 &
PYTHON_PID2=$!

sleep 3

PYTHON_DEST2=""
for i in {1..30}; do
    if grep -q "DESTINATION_HASH=" "$PYTHON_SERVER_OUTPUT2"; then
        PYTHON_DEST2=$(grep "DESTINATION_HASH=" "$PYTHON_SERVER_OUTPUT2" | head -1 | cut -d= -f2)
        break
    fi
    sleep 0.3
done

# Wait for announce to propagate
sleep 3

if [ -z "$PYTHON_DEST2" ]; then
    fail "Could not get Python destination hash for test 2"
    kill $PYTHON_PID2 2>/dev/null
    print_summary
    exit 1
fi

info "Python destination hash: $PYTHON_DEST2"

# Send a larger resource (500 bytes of 'B')
LARGER_DATA_HEX=$(python3 -c "print('42' * 500)")
info "Sending larger resource from Rust..."

RUST_CLIENT_OUTPUT2=$(mktemp)
timeout 60 docker exec reticulum-rust-node test_resource_client \
    --tcp-client python-hub:14242 \
    -d "$PYTHON_DEST2" \
    -a test_app -A resourceserver2 \
    -s "$LARGER_DATA_HEX" \
    -t 45 \
    > "$RUST_CLIENT_OUTPUT2" 2>&1 || true

# Wait for transfer
sleep 5

for i in {1..10}; do
    if ! kill -0 $PYTHON_PID2 2>/dev/null; then
        break
    fi
    sleep 1
done
kill $PYTHON_PID2 2>/dev/null || true
wait $PYTHON_PID2 2>/dev/null || true

info "Rust client output (test 2):"
cat "$RUST_CLIENT_OUTPUT2"

info "Python server output (test 2):"
cat "$PYTHON_SERVER_OUTPUT2"

# Verify larger transfer
if grep -q "RESOURCE_COMPLETE=" "$PYTHON_SERVER_OUTPUT2"; then
    success "Python completed larger resource transfer"

    # Verify size
    COMPLETE_LINE2=$(grep "RESOURCE_COMPLETE=" "$PYTHON_SERVER_OUTPUT2" | head -1)
    RECEIVED_SIZE=$(echo "$COMPLETE_LINE2" | cut -d: -f2)

    if [ "$RECEIVED_SIZE" = "500" ]; then
        success "Resource size matches (500 bytes)"
    else
        fail "Resource size mismatch: expected 500, got $RECEIVED_SIZE"
    fi
else
    fail "Python did not complete larger resource transfer"
fi

if grep -q "RESOURCE_TRANSFER_COMPLETE=" "$RUST_CLIENT_OUTPUT2"; then
    success "Rust completed larger resource transfer"
else
    fail "Rust did not complete larger resource transfer"
fi

# Clean up
rm -f "$PYTHON_SERVER_OUTPUT2" "$RUST_CLIENT_OUTPUT2"

print_summary
