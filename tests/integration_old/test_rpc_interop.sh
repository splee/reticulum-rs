#!/bin/bash
# Test RPC protocol interoperability between Rust server and Python client
#
# This test verifies:
# 1. Python can connect to Rust daemon via multiprocessing.connection
# 2. HMAC authentication succeeds
# 3. Pickle-encoded requests/responses work correctly

set -e
source "$(dirname "$0")/common.sh"

echo "========================================"
echo "Test: RPC Protocol Interoperability"
echo "========================================"

# Create temp directory for test
TEST_DIR=$(mktemp -d)
CONFIG_DIR="$TEST_DIR/config"
STORAGE_DIR="$CONFIG_DIR/storage"
IDENTITY_DIR="$STORAGE_DIR/identities"
SOCKET_DIR="$CONFIG_DIR/sockets"
mkdir -p "$IDENTITY_DIR" "$SOCKET_DIR"

cleanup() {
    if [ -n "$RUST_DAEMON_PID" ]; then
        kill $RUST_DAEMON_PID 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# -------------------------------------------------
# Setup: Create test configuration
# -------------------------------------------------
info "Setting up test configuration..."

# Create config file with TCP control port (for easier testing)
cat > "$CONFIG_DIR/config" << 'EOF'
[reticulum]
enable_transport = true
share_instance = true
shared_instance_port = 37429
control_port = 37428

# No interfaces for this test
EOF

# Build the Rust daemon if needed
info "Building Rust daemon..."
cd "$(dirname "$0")/../.."
cargo build --release --bin rnsd 2>&1 | tail -3

RNSD="./target/release/rnsd"
if [ ! -f "$RNSD" ]; then
    fail "rnsd binary not found at $RNSD"
    exit 1
fi

# -------------------------------------------------
# Test 1: Start Rust daemon and verify it creates identity
# -------------------------------------------------
info "Test 1: Starting Rust daemon..."

# Start daemon in background
RUST_LOG=info "$RNSD" --config "$CONFIG_DIR" &
RUST_DAEMON_PID=$!

# Wait for daemon to start and create identity
sleep 3

# Check if daemon is still running
if ! kill -0 $RUST_DAEMON_PID 2>/dev/null; then
    fail "Rust daemon failed to start"
    exit 1
fi

# Check if identity was created
IDENTITY_FILE="$IDENTITY_DIR/daemon_identity"
if [ ! -f "$IDENTITY_FILE" ]; then
    fail "Daemon identity file not created at $IDENTITY_FILE"
    ls -la "$STORAGE_DIR" || true
    ls -la "$IDENTITY_DIR" || true
    exit 1
fi

IDENTITY_SIZE=$(wc -c < "$IDENTITY_FILE" | tr -d ' ')
if [ "$IDENTITY_SIZE" != "64" ]; then
    fail "Identity file has wrong size: $IDENTITY_SIZE bytes (expected 64)"
    exit 1
fi

success "Rust daemon started and created identity"

# -------------------------------------------------
# Test 2: Python client connects and authenticates
# -------------------------------------------------
info "Test 2: Python RPC client connection..."

# Run Python test client with Unix socket
RPC_SOCKET="$SOCKET_DIR/default_rpc.sock"
SCRIPT_DIR="$(dirname "$0")/helpers"
PYTHON_OUTPUT=$(python3 "$SCRIPT_DIR/test_rpc_client.py" "unix:$RPC_SOCKET" "$IDENTITY_FILE" 2>&1) || true

echo "Python client output:"
echo "$PYTHON_OUTPUT"

# Check results
if echo "$PYTHON_OUTPUT" | grep -q "Connected and authenticated"; then
    success "Python client connected and authenticated with Rust daemon"
else
    fail "Python client failed to connect or authenticate"
    exit 1
fi

if echo "$PYTHON_OUTPUT" | grep -q "Test 1: PASSED"; then
    success "get_interface_stats test passed"
else
    fail "get_interface_stats test failed"
fi

if echo "$PYTHON_OUTPUT" | grep -q "Test 2: PASSED"; then
    success "get_path_table test passed"
else
    fail "get_path_table test failed"
fi

if echo "$PYTHON_OUTPUT" | grep -q "All tests completed"; then
    success "All RPC interoperability tests passed"
else
    fail "Some RPC tests failed"
fi

print_summary
