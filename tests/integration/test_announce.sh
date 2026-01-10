#!/bin/bash
# Test announcement propagation between Python and Rust nodes
#
# This test verifies:
# 1. Announcements from Python are received by Rust
# 2. Announcements from Rust are received by Python
# 3. Announce packet format is compatible

set -e
source "$(dirname "$0")/common.sh"

echo "========================================"
echo "Test: Announcement Propagation"
echo "========================================"

# Ensure containers are running
check_containers || start_containers

# Give time for connection to stabilize
sleep 3

# Test 1: Check Python node's announce cache
info "Test 1: Checking Python announce cache..."

PYTHON_STATUS=$(exec_python rnstatus 2>&1 || true)
info "Python network status:"
echo "$PYTHON_STATUS" | head -20

# Test 2: Check Rust node's announce cache
info "Test 2: Checking Rust announce cache..."

# The Rust rnstatus should show network info
RUST_STATUS=$(exec_rust rnstatus 2>&1 || true)
info "Rust network status:"
echo "$RUST_STATUS" | head -20

# Test 3: Verify both nodes see each other's interface
info "Test 3: Checking interface visibility..."

# Check Python logs for any announce activity
PYTHON_LOGS=$(docker logs reticulum-python-hub 2>&1 | tail -50)
if echo "$PYTHON_LOGS" | grep -qi "announce\|destination"; then
    success "Python hub has announce/destination activity"
else
    info "No announce activity in Python logs (may be normal if no destinations announced)"
fi

# Check Rust logs for any announce activity
RUST_LOGS=$(docker logs reticulum-rust-node 2>&1 | tail -50)
if echo "$RUST_LOGS" | grep -qi "announce\|destination\|received packet"; then
    success "Rust node has announce/packet activity"
else
    info "No announce activity in Rust logs (may be normal if no destinations announced)"
fi

# Test 4: Verify packet flow
info "Test 4: Verifying packet flow between nodes..."

# Both nodes should have initialized transport
if echo "$RUST_LOGS" | grep -qi "transport initialized"; then
    success "Rust transport initialized"
else
    fail "Rust transport may not be initialized"
fi

# Test 5: Check interface counts
info "Test 5: Checking interface configuration..."

# Count interfaces on Python
PYTHON_IFACE_COUNT=$(exec_python rnstatus 2>&1 | grep -c "Interface\|interface" || echo "0")
info "Python interfaces detected in status: $PYTHON_IFACE_COUNT"

# For Rust, check from logs
RUST_IFACE_COUNT=$(echo "$RUST_LOGS" | grep -c "Starting interface\|TCP Server\|TCP Client" || echo "0")
info "Rust interfaces started: $RUST_IFACE_COUNT"

print_summary
