#!/bin/bash
# Test local client announce forwarding
#
# This test verifies that announces from local clients (like NomadNet)
# connecting via Unix socket are properly forwarded to network interfaces

set -e
source "$(dirname "$0")/common.sh"

echo "========================================="
echo "Test: Local Client Announces (Native)"
echo "========================================="

# Ensure containers are running
check_containers || start_containers

# Give time for connection to stabilize
sleep 3

info "Test 1: Create test script in Python container..."

# Create a Python script that acts like a local client
exec_python bash -c 'cat > /tmp/test_announce.py << "EOFPY"
#!/usr/bin/env python3
import RNS
import sys
import time

# Connect to the shared instance via Unix socket
reticulum = RNS.Reticulum(configdir="/root/.reticulum")
print("Connected to shared RNS instance", file=sys.stderr)

# Create an identity
identity = RNS.Identity()
print(f"Created identity: {identity.hash.hex()}", file=sys.stderr)

# Create a destination
destination = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "test",
    "localannounce"
)
print(f"Created destination: {destination.hash.hex()}", file=sys.stderr)

# Announce the destination
destination.announce()
print(f"Announced destination: {destination.hash.hex()}", file=sys.stderr)

# Give it time to propagate
time.sleep(2)

print("ANNOUNCE_COMPLETE", file=sys.stderr)
EOFPY
'

info "Test 2: Get initial Python hub announce count..."
PYTHON_BEFORE=$(docker logs reticulum-python-hub 2>&1 | grep -c "announce" | tr -d '\n' || echo "0")
info "Python hub announce count before: $PYTHON_BEFORE"

info "Test 3: Get initial Rust node announce count..."
RUST_BEFORE=$(docker logs reticulum-rust-node 2>&1 | grep -c "announce" | tr -d '\n' || echo "0")
info "Rust node announce count before: $RUST_BEFORE"

info "Test 4: Run announce from Python local client..."
exec_python python3 /tmp/test_announce.py 2>&1 | tee /tmp/announce_output.txt

# Check if announce completed
if grep -q "ANNOUNCE_COMPLETE" /tmp/announce_output.txt; then
    success "Python client announced successfully"
else
    fail "Python client announce failed"
fi

# Give time for forwarding
sleep 3

info "Test 5: Check Python hub logs for announce..."
PYTHON_AFTER=$(docker logs reticulum-python-hub 2>&1 | grep -c "announce" | tr -d '\n' || echo "0")
info "Python hub announce count after: $PYTHON_AFTER"

if [ "$PYTHON_AFTER" -gt "$PYTHON_BEFORE" ]; then
    success "Python hub processed announce"
else
    info "No new announces in Python hub (may forward without logging)"
fi

info "Test 6: Check Rust node logs for forwarded announce..."
RUST_AFTER=$(docker logs reticulum-rust-node 2>&1 | grep -c "announce" | tr -d '\n' || echo "0")
info "Rust node announce count after: $RUST_AFTER"

docker logs reticulum-rust-node 2>&1 | tail -50

if [ "$RUST_AFTER" -gt "$RUST_BEFORE" ]; then
    success "Rust node received announce from Python hub!"
else
    fail "Rust node did NOT receive announce from Python hub"
fi

# Now test the reverse - announce from Rust local client
info "Test 7: Create test destination in Rust container..."

# Use test_destination binary with --shared flag to connect to rnsd via Unix socket (announces once and exits)
RUST_ANNOUNCE_OUTPUT=$(exec_rust test_destination --shared --app-name test --aspect rustannounce -n 1 2>&1 | tee /tmp/rust_announce.txt)

# Extract the destination hash from the output
RUST_DEST_HASH=$(echo "$RUST_ANNOUNCE_OUTPUT" | grep "DESTINATION_HASH=" | sed 's/DESTINATION_HASH=//')

if [ -z "$RUST_DEST_HASH" ]; then
    fail "Failed to extract destination hash from Rust announce"
fi

info "Rust announced destination: /$RUST_DEST_HASH/"

sleep 3

info "Test 8: Check if Rust announce was forwarded to Python..."
# Check if Python hub has the destination in its path table
if exec_python rnpath -t 2>&1 | grep -q "$RUST_DEST_HASH"; then
    success "Python hub received announce from Rust local client!"
    exec_python rnpath -t 2>&1 | grep "$RUST_DEST_HASH"
else
    fail "Python hub did NOT receive announce from Rust local client"
    info "Python hub path table:"
    exec_python rnpath -t 2>&1 | tail -10
fi

print_summary
