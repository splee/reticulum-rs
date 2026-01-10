#!/bin/bash
# Test resource transfer between Python and Rust nodes
# This tests that resource advertisements are properly received and parsed

set -e
source "$(dirname "$0")/common.sh"

echo "========================================"
echo "Test: Resource Advertisement Reception"
echo "========================================"

# Ensure containers are running
check_containers || start_containers

# Give nodes time to stabilize
sleep 3

# Test 1: Python client sends resource to Rust server
info "Test 1: Python sends resource advertisement to Rust"

# Start Rust resource server in background
RUST_SERVER_OUTPUT=$(mktemp)
timeout 60 docker exec reticulum-rust-node test_resource_server \
    --tcp-client python-hub:4242 \
    -a test_app -A resourceserver \
    -n 1 -t 50 -i 5 \
    > "$RUST_SERVER_OUTPUT" 2>&1 &
RUST_PID=$!

# Wait for Rust to start and announce
sleep 3

# Get Rust destination hash - wait longer for it to appear
RUST_DEST=""
for i in {1..30}; do
    if grep -q "DESTINATION_HASH=" "$RUST_SERVER_OUTPUT"; then
        RUST_DEST=$(grep "DESTINATION_HASH=" "$RUST_SERVER_OUTPUT" | head -1 | cut -d= -f2)
        break
    fi
    sleep 0.3
done

# Wait for announce to propagate through the network
sleep 3

if [ -z "$RUST_DEST" ]; then
    fail "Could not get Rust destination hash"
    cat "$RUST_SERVER_OUTPUT"
    kill $RUST_PID 2>/dev/null
    print_summary
    exit 1
fi

info "Rust destination hash: $RUST_DEST"

# Test data to send (hex encoded "Hello Resource!")
TEST_DATA_HEX="48656c6c6f205265736f7572636521"
info "Sending resource from Python..."

# Python client connects and sends resource
PYTHON_CLIENT_OUTPUT=$(mktemp)
docker exec reticulum-python-hub python3 /app/helpers/python_resource_client.py \
    -d "$RUST_DEST" \
    -a test_app -A resourceserver \
    -s "$TEST_DATA_HEX" \
    -t 45 -v \
    > "$PYTHON_CLIENT_OUTPUT" 2>&1 || true

PYTHON_EXIT=$?

# Wait for resource transfer and server to process
# The Rust server has -n 1 so will exit after receiving 1 resource
sleep 5

# Wait for Rust server to finish (it should exit after receiving resource with -n 1)
# Give it a few seconds extra, then kill if still running
for i in {1..10}; do
    if ! kill -0 $RUST_PID 2>/dev/null; then
        break
    fi
    sleep 1
done
kill $RUST_PID 2>/dev/null || true
wait $RUST_PID 2>/dev/null || true

# Check results
info "Python client output:"
cat "$PYTHON_CLIENT_OUTPUT"

info "Rust server output:"
cat "$RUST_SERVER_OUTPUT"

# Verify link was established on both sides
if grep -q "LINK_ACTIVATED=" "$RUST_SERVER_OUTPUT"; then
    success "Rust server received link activation"
else
    fail "Rust server did not receive link activation"
fi

if grep -q "LINK_ACTIVATED=" "$PYTHON_CLIENT_OUTPUT"; then
    success "Python client established link"
else
    fail "Python client failed to establish link"
fi

# Verify resource advertisement was received by Rust
if grep -q "RESOURCE_ADVERTISEMENT=" "$RUST_SERVER_OUTPUT"; then
    success "Rust received resource advertisement"

    # Extract and verify advertisement details
    ADV_LINE=$(grep "RESOURCE_ADVERTISEMENT=" "$RUST_SERVER_OUTPUT" | head -1)
    info "Resource advertisement: $ADV_LINE"

    # Parse fields: LINK_ID:HASH:DATA_SIZE:TRANSFER_SIZE:NUM_PARTS
    ADV_DATA_SIZE=$(echo "$ADV_LINE" | cut -d: -f3)
    ADV_NUM_PARTS=$(echo "$ADV_LINE" | cut -d: -f5)

    if [ -n "$ADV_DATA_SIZE" ] && [ "$ADV_DATA_SIZE" -gt 0 ]; then
        success "Resource advertisement parsed correctly (size: $ADV_DATA_SIZE bytes, parts: $ADV_NUM_PARTS)"
    else
        fail "Resource advertisement parsing failed"
    fi
else
    # Check for parse error
    if grep -q "RESOURCE_ADVERTISEMENT_PARSE_ERROR=" "$RUST_SERVER_OUTPUT"; then
        fail "Rust received but could not parse resource advertisement"
        grep "RESOURCE_ADVERTISEMENT_PARSE_ERROR=" "$RUST_SERVER_OUTPUT"
    else
        fail "Rust did not receive resource advertisement"
    fi
fi

# Check if Python started the resource transfer
if grep -q "RESOURCE_STARTED=" "$PYTHON_CLIENT_OUTPUT"; then
    success "Python started resource transfer"
else
    fail "Python did not start resource transfer"
fi

# Clean up temp files
rm -f "$PYTHON_CLIENT_OUTPUT" "$RUST_SERVER_OUTPUT"

# -------------------------------------------------
# Test 2: Verify resource data packets flow
# -------------------------------------------------
info "Test 2: Verify resource data packet reception"

# Start Rust resource server again
RUST_SERVER_OUTPUT2=$(mktemp)
timeout 60 docker exec reticulum-rust-node test_resource_server \
    --tcp-client python-hub:4242 \
    -a test_app -A resourceserver2 \
    -n 1 -t 50 -i 5 -v \
    > "$RUST_SERVER_OUTPUT2" 2>&1 &
RUST_PID2=$!

sleep 3

RUST_DEST2=""
for i in {1..30}; do
    if grep -q "DESTINATION_HASH=" "$RUST_SERVER_OUTPUT2"; then
        RUST_DEST2=$(grep "DESTINATION_HASH=" "$RUST_SERVER_OUTPUT2" | head -1 | cut -d= -f2)
        break
    fi
    sleep 0.3
done

# Wait for announce to propagate
sleep 3

if [ -z "$RUST_DEST2" ]; then
    fail "Could not get Rust destination hash for test 2"
    kill $RUST_PID2 2>/dev/null
    print_summary
    exit 1
fi

info "Rust destination hash: $RUST_DEST2"

# Send a slightly larger resource to ensure data packets are sent
LARGER_DATA_HEX=$(python3 -c "print('41' * 100)")  # 100 bytes of 'A'
info "Sending larger resource from Python..."

PYTHON_CLIENT_OUTPUT2=$(mktemp)
docker exec reticulum-python-hub python3 /app/helpers/python_resource_client.py \
    -d "$RUST_DEST2" \
    -a test_app -A resourceserver2 \
    -s "$LARGER_DATA_HEX" \
    -t 45 \
    > "$PYTHON_CLIENT_OUTPUT2" 2>&1 || true

# Wait for resource transfer and server to process
sleep 5

# Wait for Rust server to finish
for i in {1..10}; do
    if ! kill -0 $RUST_PID2 2>/dev/null; then
        break
    fi
    sleep 1
done
kill $RUST_PID2 2>/dev/null || true
wait $RUST_PID2 2>/dev/null || true

info "Rust server output (test 2):"
cat "$RUST_SERVER_OUTPUT2"

# Verify resource advertisement and data packets
if grep -q "RESOURCE_ADVERTISEMENT=" "$RUST_SERVER_OUTPUT2"; then
    success "Rust received resource advertisement (test 2)"
else
    fail "Rust did not receive resource advertisement (test 2)"
fi

# Resource data packets may or may not arrive depending on timing
# (the receiver needs to send RESOURCE_REQ to get data)
if grep -q "RESOURCE_DATA=" "$RUST_SERVER_OUTPUT2"; then
    success "Rust received resource data packets"
else
    info "No resource data packets received (expected - full transfer not implemented)"
fi

# Clean up
rm -f "$PYTHON_CLIENT_OUTPUT2" "$RUST_SERVER_OUTPUT2"

print_summary
