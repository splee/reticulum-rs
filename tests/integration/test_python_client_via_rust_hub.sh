#!/bin/bash
# Test that Python clients can announce via Rust rnsd's shared instance
# and have those announces forwarded to network interfaces

set -e
source "$(dirname "$0")/common.sh"

echo "========================================="
echo "Test: Python Client via Rust Hub"
echo "========================================="

# Ensure containers are running
check_containers || start_containers
sleep 3

info "Test 1: Create Python script to connect to Rust shared instance..."

# Create a Python script that connects to Rust rnsd
exec_rust bash -c 'cat > /tmp/test_announce_rust.py << "EOFPY"
#!/usr/bin/env python3
import RNS
import sys
import time

# Connect to Rust shared instance
reticulum = RNS.Reticulum(configdir="/root/.reticulum")
print(f"Connected to RNS instance at {reticulum.local_interface_port}", file=sys.stderr)

# Create identity and destination
identity = RNS.Identity()
destination = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "nomadtest",
    "chat"
)

dest_hash = destination.hash.hex()
print(f"Created destination: {dest_hash}", file=sys.stderr)

# Announce
destination.announce(b"Test announce from Python via Rust")
print(f"Announced: {dest_hash}", file=sys.stderr)

time.sleep(2)
print("DONE", file=sys.stderr)
EOFPY
'

info "Test 2: Get baseline packet count..."
RUST_BEFORE=$(docker logs reticulum-rust-node 2>&1 | grep -c "Received packet" || echo "0")
info "Rust packets before: $RUST_BEFORE"

PYTHON_BEFORE=$(docker logs reticulum-python-hub 2>&1 | grep -c "Valid announce\|Rebroadcasting" || echo "0")
info "Python announces before: $PYTHON_BEFORE"

info "Test 3: Run Python client announcing via Rust shared instance..."
exec_rust python3 /tmp/test_announce_rust.py 2>&1 | tee /tmp/rust_announce_test.txt

if grep -q "DONE" /tmp/rust_announce_test.txt; then
    DEST_HASH=$(grep "Announced:" /tmp/rust_announce_test.txt | awk '{print $2}')
    success "Python client announced via Rust: $DEST_HASH"
else
    fail "Python client announce failed"
fi

sleep 3

info "Test 4: Check if Rust rnsd processed the announce..."
docker logs reticulum-rust-node 2>&1 | tail -50 > /tmp/rust_logs.txt

if grep -q "$DEST_HASH" /tmp/rust_logs.txt; then
    success "Rust rnsd processed announce for $DEST_HASH"
else
    warn "Rust rnsd did not log announce (may be normal)"
fi

info "Test 5: Check if announce was forwarded to Python hub..."
sleep 2
PYTHON_AFTER=$(docker logs reticulum-python-hub 2>&1 | grep -c "Valid announce\|Rebroadcasting" || echo "0")
info "Python announces after: $PYTHON_AFTER"

docker logs reticulum-python-hub 2>&1 | tail -50

if [ "$PYTHON_AFTER" -gt "$PYTHON_BEFORE" ]; then
    success "Announce was forwarded from Rust to Python!"
    if docker logs reticulum-python-hub 2>&1 | grep -q "$DEST_HASH"; then
        success "Python hub received announce for $DEST_HASH"
    fi
else
    fail "Announce was NOT forwarded from Rust to Python"
fi

print_summary
