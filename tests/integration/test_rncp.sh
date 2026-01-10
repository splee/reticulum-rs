#!/bin/bash
# Test rncp functionality between Python and Rust implementations
# Tests identity persistence, CLI compatibility, and basic file transfer

set -e
source "$(dirname "$0")/common.sh"

echo "========================================"
echo "Test: rncp File Transfer Utility"
echo "========================================"

# Ensure containers are running
check_containers || start_containers

# Give nodes time to stabilize
sleep 2

# Test 1: Identity Persistence
info "Test 1: Identity persistence in Rust rncp"

# Remove any existing identity
exec_rust rm -f /root/.reticulum/identities/rncp 2>/dev/null || true

# First run - should create new identity
FIRST_RUN=$(exec_rust rncp -p 2>&1 | grep "Listening on")
FIRST_HASH=$(echo "$FIRST_RUN" | sed 's/.*<\(.*\)>/\1/')

if [ -z "$FIRST_HASH" ]; then
    fail "First run did not produce destination hash"
else
    info "First run destination: $FIRST_HASH"
fi

# Second run - should load same identity
SECOND_RUN=$(exec_rust rncp -p 2>&1 | grep "Listening on")
SECOND_HASH=$(echo "$SECOND_RUN" | sed 's/.*<\(.*\)>/\1/')

if [ "$FIRST_HASH" = "$SECOND_HASH" ]; then
    success "Identity persistence working - same hash on second run"
else
    fail "Identity not persisted - hashes differ: $FIRST_HASH vs $SECOND_HASH"
fi

# Test 2: CLI Help Comparison
info "Test 2: CLI argument compatibility"

# Get Rust help
RUST_HELP=$(exec_rust rncp --help 2>&1)

# Check for key flags (using grep -F for literal matching)
MISSING_FLAGS=""
for flag in "--listen" "--fetch" "--save" "--overwrite" "--no-auth" "--print-identity" "--no-compress" "--allow-fetch" "--jail"; do
    if echo "$RUST_HELP" | grep -qF -- "$flag"; then
        : # Flag present
    else
        MISSING_FLAGS="$MISSING_FLAGS $flag"
    fi
done

if [ -z "$MISSING_FLAGS" ]; then
    success "All expected CLI flags present"
else
    fail "Missing CLI flags:$MISSING_FLAGS"
fi

# Test 3: Version output
info "Test 3: Version output"

if exec_rust rncp --version 2>&1 | grep -q "rncp"; then
    success "Version output works"
else
    fail "Version output missing or malformed"
fi

# Test 4: Listen mode startup (brief test)
info "Test 4: Listen mode startup"

# Start rncp in listen mode with no-auth and timeout
LISTEN_OUTPUT=$(mktemp)
exec_rust sh -c "timeout 5 rncp -l -n --tcp-server 0.0.0.0:17777 -b 0 2>&1 || true" > "$LISTEN_OUTPUT" &
LISTEN_PID=$!
sleep 3

# Check if it started listening
if grep -qiF "listening on" "$LISTEN_OUTPUT"; then
    success "Listen mode starts correctly"
else
    fail "Listen mode did not start properly"
    cat "$LISTEN_OUTPUT"
fi

# Clean up listener
kill $LISTEN_PID 2>/dev/null || true
wait $LISTEN_PID 2>/dev/null || true
rm -f "$LISTEN_OUTPUT"

# Test 5: Allowed identities warning
info "Test 5: Allowed identities warning"

# Should warn when no identities configured and -n not set
WARN_OUTPUT=$(exec_rust sh -c 'rm -f /root/.rncp/allowed_identities ~/.config/rncp/allowed_identities 2>/dev/null; timeout 3 rncp -l --tcp-server 0.0.0.0:17778 2>&1 || true')

if echo "$WARN_OUTPUT" | grep -qiF "no allowed identities"; then
    success "Warning shown when no allowed identities"
else
    info "Output: $WARN_OUTPUT"
    fail "No warning when allowed identities missing"
fi

# Test 6: Python sends file to Rust listener
# Rust connects to Python's TCP server (4242), both share the same network
info "Test 6: File transfer from Python to Rust"

# Create test file on Python node
TEST_CONTENT="Hello from Python rncp $(date +%s)"
TEST_FILE_NAME="python_test_$(date +%s).txt"
exec_python sh -c "echo '$TEST_CONTENT' > /tmp/$TEST_FILE_NAME"

PYTHON_CHECKSUM=$(exec_python md5sum /tmp/$TEST_FILE_NAME | cut -d' ' -f1)
info "Python test file checksum: $PYTHON_CHECKSUM"

# Start Rust rncp listener (connects to Python's TCP server so both share the network)
RUST_OUTPUT=$(mktemp)
exec_rust sh -c "rm -f /tmp/received_* /tmp/*.txt; timeout 60 rncp -l -n -s /tmp --tcp-client python-hub:4242 -b 0 -i 5" > "$RUST_OUTPUT" 2>&1 &
RUST_PID=$!
sleep 5

# Get Rust destination hash from output
RUST_HASH=""
for i in {1..20}; do
    if grep -qF "listening on" "$RUST_OUTPUT"; then
        RUST_HASH=$(grep -F "listening on" "$RUST_OUTPUT" | head -1 | sed 's/.*<\(.*\)>/\1/')
        break
    fi
    sleep 0.5
done

if [ -z "$RUST_HASH" ]; then
    fail "Could not get Rust destination hash"
    cat "$RUST_OUTPUT"
    kill $RUST_PID 2>/dev/null || true
else
    info "Rust destination: $RUST_HASH"

    # Wait for announce to propagate
    sleep 3

    # Send file from Python to Rust (Python uses its default config)
    info "Python sending file to Rust..."
    exec_python timeout 45 rncp /tmp/$TEST_FILE_NAME $RUST_HASH -S 2>&1 || true

    sleep 5

    # Check Rust listener output
    info "Rust listener output:"
    cat "$RUST_OUTPUT"

    # Kill Rust listener
    kill $RUST_PID 2>/dev/null || true
    wait $RUST_PID 2>/dev/null || true

    # Check if file was received
    if exec_rust ls /tmp/$TEST_FILE_NAME 2>/dev/null; then
        RECEIVED_CHECKSUM=$(exec_rust md5sum /tmp/$TEST_FILE_NAME | cut -d' ' -f1)
        if [ "$PYTHON_CHECKSUM" = "$RECEIVED_CHECKSUM" ]; then
            success "File transfer Python->Rust successful with matching checksum"
        else
            fail "File received but checksum mismatch"
        fi
    else
        info "Looking for any received files..."
        exec_rust ls -la /tmp/received_* /tmp/*.txt 2>/dev/null || true
        fail "File not received by Rust"
    fi
fi
rm -f "$RUST_OUTPUT"

# Test 7: Rust sends file to Python listener
info "Test 7: File transfer from Rust to Python"

# Create test file on Rust node
TEST_CONTENT2="Hello from Rust rncp $(date +%s)"
TEST_FILE_NAME2="rust_test_$(date +%s).txt"
exec_rust sh -c "echo '$TEST_CONTENT2' > /tmp/$TEST_FILE_NAME2"

RUST_CHECKSUM2=$(exec_rust md5sum /tmp/$TEST_FILE_NAME2 | cut -d' ' -f1)
info "Rust test file checksum: $RUST_CHECKSUM2"

# Start Python rncp listener in background and capture output
# Use python3 -u for unbuffered output
# -b 5 announces every 5 seconds (like Rust in Test 6), -v for verbose
PYTHON_OUTPUT=$(mktemp)
exec_python sh -c "rm -f /tmp/received_* /tmp/*.txt; timeout 60 python3 -u -m RNS.Utilities.rncp -l -n -s /tmp -b 5 -v" > "$PYTHON_OUTPUT" 2>&1 &
PYTHON_PID=$!
sleep 5

# Get Python destination hash
PYTHON_HASH=""
for i in {1..20}; do
    if grep -qF "listening on" "$PYTHON_OUTPUT"; then
        PYTHON_HASH=$(grep -F "listening on" "$PYTHON_OUTPUT" | head -1 | sed 's/.*<\(.*\)>/\1/')
        break
    fi
    sleep 0.5
done

if [ -z "$PYTHON_HASH" ]; then
    fail "Could not get Python destination hash"
    cat "$PYTHON_OUTPUT"
    kill $PYTHON_PID 2>/dev/null || true
else
    info "Python destination: $PYTHON_HASH"

    # Wait for announce to propagate - Python needs time to announce
    sleep 5

    # Send file from Rust to Python (Rust connects to Python's TCP server on port 4242)
    info "Rust sending file to Python..."
    exec_rust timeout 45 rncp /tmp/$TEST_FILE_NAME2 $PYTHON_HASH --tcp-client python-hub:4242 -S -v 2>&1 || true

    sleep 8

    # Check Python listener output
    info "Python listener output:"
    cat "$PYTHON_OUTPUT"

    # Kill Python listener
    kill $PYTHON_PID 2>/dev/null || true
    wait $PYTHON_PID 2>/dev/null || true

    # Check if file was received
    if exec_python ls /tmp/$TEST_FILE_NAME2 2>/dev/null; then
        RECEIVED_CHECKSUM2=$(exec_python md5sum /tmp/$TEST_FILE_NAME2 | cut -d' ' -f1)
        if [ "$RUST_CHECKSUM2" = "$RECEIVED_CHECKSUM2" ]; then
            success "File transfer Rust->Python successful with matching checksum"
        else
            fail "File received but checksum mismatch"
        fi
    else
        info "Looking for any received files..."
        exec_python ls -la /tmp/received_* /tmp/*.txt 2>/dev/null || true
        fail "File not received by Python"
    fi
fi
rm -f "$PYTHON_OUTPUT"

# Note: Fetch mode tests skipped for now (file transfers already verify interop)
info "Note: Fetch mode tests skipped"

# Print summary
echo ""
echo "========================================"
print_summary
echo "========================================"

if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
fi
