#!/bin/bash
# Test link data exchange between Python and Rust nodes

set -e
source "$(dirname "$0")/common.sh"

echo "========================================"
echo "Test: Link Data Exchange"
echo "========================================"

# Ensure containers are running
check_containers || start_containers

# Give nodes time to stabilize
sleep 3

# Test 1: Rust client sends data to Python server
info "Test 1: Rust client sends data to Python server"

# Start Python server that echoes received data
# Note: Use -n 0 (infinite links) but -t timeout to wait for data
PYTHON_SERVER_OUTPUT=$(mktemp)
docker exec reticulum-python-hub timeout 35 python3 /app/helpers/python_link_server.py \
    -a test_app -A dataserver \
    -n 0 -t 30 -i 5 \
    > "$PYTHON_SERVER_OUTPUT" 2>&1 &
PYTHON_PID=$!

# Wait for Python to announce
sleep 3

# Get destination hash
PYTHON_DEST=""
for i in {1..10}; do
    if grep -q "DESTINATION_HASH=" "$PYTHON_SERVER_OUTPUT"; then
        PYTHON_DEST=$(grep "DESTINATION_HASH=" "$PYTHON_SERVER_OUTPUT" | head -1 | cut -d= -f2)
        break
    fi
    sleep 0.5
done

if [ -z "$PYTHON_DEST" ]; then
    fail "Could not get Python destination hash"
    cat "$PYTHON_SERVER_OUTPUT"
    kill $PYTHON_PID 2>/dev/null
    exit 1
fi

info "Python destination hash: $PYTHON_DEST"

# Test data to send (hex encoded "Hello from Rust!")
TEST_DATA_HEX="48656c6c6f2066726f6d205275737421"
info "Sending test data from Rust..."

# Rust client connects and sends data
RUST_OUTPUT=$(mktemp)
docker exec reticulum-rust-node test_link_client \
    --tcp-client python-hub:4242 \
    --destination "$PYTHON_DEST" \
    --send-data "$TEST_DATA_HEX" \
    -t 20 \
    > "$RUST_OUTPUT" 2>&1

RUST_EXIT=$?

# Wait for data to propagate
sleep 2

# Kill Python server (it runs with -n 0, so it doesn't auto-exit)
kill $PYTHON_PID 2>/dev/null
wait $PYTHON_PID 2>/dev/null

# Check results
info "Rust client output:"
cat "$RUST_OUTPUT"

info "Python server output:"
cat "$PYTHON_SERVER_OUTPUT"

# Verify link was established
if grep -q "LINK_ACTIVATED=" "$RUST_OUTPUT"; then
    success "Rust established link to Python"
else
    fail "Rust failed to establish link"
fi

# Verify data was sent
if grep -q "DATA_SENT=" "$RUST_OUTPUT"; then
    success "Rust sent data on link"
else
    fail "Rust did not send data"
fi

# Verify Python received the data
if grep -q "DATA_RECEIVED=" "$PYTHON_SERVER_OUTPUT"; then
    success "Python received data from Rust"

    # Check if the received data matches what was sent
    RECEIVED_DATA=$(grep "DATA_RECEIVED=" "$PYTHON_SERVER_OUTPUT" | head -1 | cut -d: -f3)
    if [ "$RECEIVED_DATA" = "$TEST_DATA_HEX" ]; then
        success "Received data matches sent data"
    else
        fail "Data mismatch: expected $TEST_DATA_HEX, got $RECEIVED_DATA"
    fi
else
    fail "Python did not receive data from Rust"
fi

# Clean up temp files
rm -f "$PYTHON_SERVER_OUTPUT" "$RUST_OUTPUT"

# -------------------------------------------------
# Test 2: Python client sends data to Rust server
# -------------------------------------------------
info "Test 2: Python client sends data to Rust server"

# Start Rust link server in background
# Use -n 0 (infinite) and timeout for proper data handling
RUST_SERVER_OUTPUT=$(mktemp)
timeout 50 docker exec reticulum-rust-node test_link_server \
    --tcp-client python-hub:4242 \
    -a test_app -A rustdataserver \
    -n 0 -t 45 -i 5 \
    > "$RUST_SERVER_OUTPUT" 2>&1 &
RUST_PID=$!

# Wait for Rust to start and announce
sleep 5

# Get Rust destination hash
RUST_DEST=""
for i in {1..15}; do
    if grep -q "DESTINATION_HASH=" "$RUST_SERVER_OUTPUT"; then
        RUST_DEST=$(grep "DESTINATION_HASH=" "$RUST_SERVER_OUTPUT" | head -1 | cut -d= -f2)
        break
    fi
    sleep 0.5
done

if [ -z "$RUST_DEST" ]; then
    fail "Could not get Rust destination hash"
    cat "$RUST_SERVER_OUTPUT"
    kill $RUST_PID 2>/dev/null
    print_summary
    exit 1
fi

info "Rust destination hash: $RUST_DEST"

# Test data to send (hex encoded "Hello from Python!")
TEST_DATA_HEX2="48656c6c6f2066726f6d20507974686f6e21"
info "Sending test data from Python..."

# Python client connects and sends data
PYTHON_CLIENT_OUTPUT=$(mktemp)
docker exec reticulum-python-hub python3 /app/helpers/python_link_client.py \
    -d "$RUST_DEST" \
    -a test_app -A rustdataserver \
    -s "$TEST_DATA_HEX2" \
    -t 30 -v \
    > "$PYTHON_CLIENT_OUTPUT" 2>&1

PYTHON_EXIT=$?

# Wait for data to propagate
sleep 3

# Kill Rust server
kill $RUST_PID 2>/dev/null
wait $RUST_PID 2>/dev/null

# Check results
info "Python client output:"
cat "$PYTHON_CLIENT_OUTPUT"

info "Rust server output:"
cat "$RUST_SERVER_OUTPUT"

# Verify link was established
if grep -q "LINK_ACTIVATED=" "$PYTHON_CLIENT_OUTPUT"; then
    success "Python established link to Rust"
else
    fail "Python failed to establish link"
fi

# Verify data was sent
if grep -q "DATA_SENT=" "$PYTHON_CLIENT_OUTPUT"; then
    success "Python sent data on link"
else
    fail "Python did not send data"
fi

# Verify Rust received the data
if grep -q "DATA_RECEIVED=" "$RUST_SERVER_OUTPUT"; then
    success "Rust received data from Python"

    # Check if the received data matches what was sent
    RECEIVED_DATA2=$(grep "DATA_RECEIVED=" "$RUST_SERVER_OUTPUT" | head -1 | cut -d: -f3)
    if [ "$RECEIVED_DATA2" = "$TEST_DATA_HEX2" ]; then
        success "Received data matches sent data"
    else
        fail "Data mismatch: expected $TEST_DATA_HEX2, got $RECEIVED_DATA2"
    fi
else
    fail "Rust did not receive data from Python"
fi

# Clean up temp files
rm -f "$PYTHON_CLIENT_OUTPUT" "$RUST_SERVER_OUTPUT"

print_summary
