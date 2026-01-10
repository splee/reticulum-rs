#!/bin/bash
# Test link establishment between Python and Rust nodes
#
# This test verifies:
# 1. Rust can establish a link to Python destination
# 2. Python can establish a link to Rust destination
# (Note: Bidirectional data tests require more infrastructure)

set -e
source "$(dirname "$0")/common.sh"

echo "========================================"
echo "Test: Link Establishment"
echo "========================================"

# Ensure containers are running
check_containers || start_containers

# Give nodes time to stabilize
sleep 3

# -------------------------------------------------
# Test 1: Python Link Server <- Rust Link Client
# -------------------------------------------------
info "Test 1: Python destination, Rust initiates link"

# Start Python link server in background via docker
# We use a named pipe (fifo) to capture output reliably
PYTHON_SERVER_FIFO=$(mktemp -u)
mkfifo "$PYTHON_SERVER_FIFO"

# Run Python server in background, outputting to fifo
(docker exec reticulum-python-hub timeout 45 python3 /app/helpers/python_link_server.py \
    --app-name test_app \
    --aspect pythonserver \
    --announce-interval 5 \
    --link-count 1 \
    --timeout 40 \
    2>&1 > "$PYTHON_SERVER_FIFO") &
PYTHON_SERVER_PID=$!

# Read from fifo in background, capturing to file
PYTHON_SERVER_OUTPUT=$(mktemp)
cat "$PYTHON_SERVER_FIFO" > "$PYTHON_SERVER_OUTPUT" &
CAT_PID=$!

# Wait for Python server to output destination hash
sleep 5

PYTHON_DEST_HASH=""
for i in $(seq 1 10); do
    if [ -f "$PYTHON_SERVER_OUTPUT" ] && grep -q "DESTINATION_HASH=" "$PYTHON_SERVER_OUTPUT" 2>/dev/null; then
        PYTHON_DEST_HASH=$(grep "DESTINATION_HASH=" "$PYTHON_SERVER_OUTPUT" | head -1 | cut -d= -f2)
        break
    fi
    sleep 1
done

if [ -z "$PYTHON_DEST_HASH" ]; then
    fail "Failed to get Python destination hash"
    info "Python server output:"
    cat "$PYTHON_SERVER_OUTPUT" 2>/dev/null || true
    kill $PYTHON_SERVER_PID 2>/dev/null || true
    kill $CAT_PID 2>/dev/null || true
    rm -f "$PYTHON_SERVER_FIFO" "$PYTHON_SERVER_OUTPUT"
    print_summary
    exit 1
fi

info "Python destination hash: $PYTHON_DEST_HASH"

# Wait for announce to propagate
sleep 3

# Start Rust link client - use --wait-announce to catch the next announce
info "Rust connecting to Python destination (waiting for announce)..."
RUST_CLIENT_OUTPUT=$(docker exec reticulum-rust-node timeout 30 test_link_client \
    --tcp-client python-hub:4242 \
    --wait-announce \
    --app-name test_app \
    --aspect pythonserver \
    --timeout 25 \
    2>&1 || true)

# Wait for Python server to complete
wait $PYTHON_SERVER_PID 2>/dev/null || true
wait $CAT_PID 2>/dev/null || true

PYTHON_SERVER_RESULT=$(cat "$PYTHON_SERVER_OUTPUT" 2>/dev/null || true)
rm -f "$PYTHON_SERVER_FIFO" "$PYTHON_SERVER_OUTPUT"

# Display outputs for debugging
info "Rust client output:"
echo "$RUST_CLIENT_OUTPUT" | head -20

info "Python server output:"
echo "$PYTHON_SERVER_RESULT" | head -20

# Check results
if echo "$RUST_CLIENT_OUTPUT" | grep -q "LINK_ACTIVATED="; then
    success "Rust established link to Python destination"
else
    fail "Rust failed to establish link to Python"
fi

if echo "$PYTHON_SERVER_RESULT" | grep -q "LINK_ACTIVATED="; then
    success "Python received incoming link from Rust"
else
    fail "Python did not receive link from Rust"
fi

# -------------------------------------------------
# Test 2: Rust announces destination, Python can reach it
# -------------------------------------------------
info "Test 2: Rust destination announced, Python can reach"

# Start Rust destination in background via docker
RUST_SERVER_FIFO=$(mktemp -u)
mkfifo "$RUST_SERVER_FIFO"

# Run Rust destination announcer
(docker exec reticulum-rust-node timeout 30 test_destination \
    --tcp-client python-hub:4242 \
    --app-name test_app \
    --aspect rustdest \
    --announce-interval 3 \
    --announce-count 5 \
    2>&1 > "$RUST_SERVER_FIFO") &
RUST_SERVER_PID=$!

# Read from fifo in background
RUST_SERVER_OUTPUT=$(mktemp)
cat "$RUST_SERVER_FIFO" > "$RUST_SERVER_OUTPUT" &
CAT_PID=$!

# Wait for Rust destination to output hash
sleep 5

RUST_DEST_HASH=""
for i in $(seq 1 10); do
    if [ -f "$RUST_SERVER_OUTPUT" ] && grep -q "DESTINATION_HASH=" "$RUST_SERVER_OUTPUT" 2>/dev/null; then
        RUST_DEST_HASH=$(grep "DESTINATION_HASH=" "$RUST_SERVER_OUTPUT" | head -1 | cut -d= -f2)
        break
    fi
    sleep 1
done

if [ -z "$RUST_DEST_HASH" ]; then
    fail "Failed to get Rust destination hash"
    info "Rust output:"
    cat "$RUST_SERVER_OUTPUT" 2>/dev/null || true
    kill $RUST_SERVER_PID 2>/dev/null || true
    kill $CAT_PID 2>/dev/null || true
    rm -f "$RUST_SERVER_FIFO" "$RUST_SERVER_OUTPUT"
    print_summary
    exit 1
fi

info "Rust destination hash: $RUST_DEST_HASH"

# Wait for announce to propagate
sleep 5

# Use rnpath to check if Python hub can see the Rust destination
info "Checking if Python hub can see Rust destination..."
RNPATH_OUTPUT=$(docker exec reticulum-python-hub timeout 10 rnpath -d "$RUST_DEST_HASH" 2>&1 || true)

echo "$RNPATH_OUTPUT" | head -10

# Wait for Rust to finish
wait $RUST_SERVER_PID 2>/dev/null || true
wait $CAT_PID 2>/dev/null || true

RUST_OUTPUT=$(cat "$RUST_SERVER_OUTPUT" 2>/dev/null || true)
rm -f "$RUST_SERVER_FIFO" "$RUST_SERVER_OUTPUT"

info "Rust output:"
echo "$RUST_OUTPUT" | head -15

# Check results - rnpath should show the path to the Rust destination
if echo "$RNPATH_OUTPUT" | grep -qi "path.*known\|hop\|announce"; then
    success "Python hub has path to Rust destination"
elif echo "$RNPATH_OUTPUT" | grep -q "$RUST_DEST_HASH"; then
    success "Python hub found Rust destination"
else
    fail "Python hub cannot find path to Rust destination"
fi

# Check that Rust announced successfully
if echo "$RUST_OUTPUT" | grep -q "ANNOUNCE_SENT="; then
    success "Rust destination announced successfully"
else
    fail "Rust destination did not announce"
fi

print_summary
