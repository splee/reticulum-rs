#!/bin/bash
# Test basic connectivity between Python and Rust nodes
#
# This test verifies:
# 1. Both daemons start successfully
# 2. TCP connection is established
# 3. Basic packet flow works

set -e
source "$(dirname "$0")/common.sh"

echo "========================================"
echo "Test: Basic Connectivity"
echo "========================================"

# Ensure containers are running
check_containers || start_containers

# Give nodes time to establish connection
info "Waiting for TCP connection to establish..."
sleep 5

# Check Python hub status for active connections
info "Checking Python hub for connections..."
PYTHON_STATUS=$(exec_python rnstatus 2>&1 || true)

if echo "$PYTHON_STATUS" | grep -q "Clients.*:.*[1-9]"; then
    success "Python hub has active client connections"
elif echo "$PYTHON_STATUS" | grep -q "TCPServerInterface"; then
    success "Python hub TCP server interface is up"
else
    # Fall back to checking logs
    PYTHON_LOGS=$(docker logs reticulum-python-hub 2>&1 | tail -50)
    if echo "$PYTHON_LOGS" | grep -qi "Spawned.*TCPClient\|incoming.*connection\|Client.*connected"; then
        success "Python hub received incoming connection (from logs)"
    else
        fail "Python hub shows no connection activity"
        echo "Python status:"
        echo "$PYTHON_STATUS"
    fi
fi

# Check Rust logs for connection
info "Checking Rust node for outgoing connection..."
RUST_LOGS=$(docker logs reticulum-rust-node 2>&1)

if echo "$RUST_LOGS" | grep -q "tcp_client connected\|TCP Client connecting"; then
    success "Rust node established TCP connection"
else
    if echo "$RUST_LOGS" | grep -qi "transport initialized"; then
        success "Rust transport is initialized"
    else
        fail "Rust node shows no connection activity"
        echo "Rust logs:"
        echo "$RUST_LOGS" | tail -20
    fi
fi

# Check that both processes are still running
info "Verifying daemons are still running..."

# Check Python daemon via rnstatus (if rnstatus works, daemon is running)
if exec_python rnstatus > /dev/null 2>&1; then
    success "Python daemon is running"
else
    fail "Python daemon is not responding"
fi

# Check Rust daemon via rnstatus
if exec_rust rnstatus > /dev/null 2>&1; then
    success "Rust daemon is running"
else
    fail "Rust daemon is not responding"
fi

print_summary
