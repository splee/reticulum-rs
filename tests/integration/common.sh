#!/bin/bash
# Common utilities for integration tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0

# Print functions
info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((++TESTS_PASSED)) || true
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((++TESTS_FAILED)) || true
}

# Wait for a container to be healthy
wait_for_healthy() {
    local container=$1
    local timeout=${2:-60}
    local elapsed=0

    info "Waiting for $container to be healthy..."

    while [ $elapsed -lt $timeout ]; do
        if docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null | grep -q "healthy"; then
            success "$container is healthy"
            return 0
        fi
        sleep 1
        ((elapsed++))
    done

    fail "$container did not become healthy within ${timeout}s"
    return 1
}

# Execute a command in a container
exec_in() {
    local container=$1
    shift
    docker exec "$container" "$@"
}

# Execute in Python container
exec_python() {
    exec_in reticulum-python-hub "$@"
}

# Execute in Rust container
exec_rust() {
    exec_in reticulum-rust-node "$@"
}

# Check if containers are running
check_containers() {
    info "Checking if containers are running..."

    if ! docker ps --format '{{.Names}}' | grep -q "reticulum-python-hub"; then
        fail "Python container is not running"
        return 1
    fi

    if ! docker ps --format '{{.Names}}' | grep -q "reticulum-rust-node"; then
        fail "Rust container is not running"
        return 1
    fi

    success "Both containers are running"
    return 0
}

# Start containers if not running
start_containers() {
    info "Starting containers..."
    cd "$(dirname "$0")/../../docker"
    docker compose up -d --build
    cd - > /dev/null

    wait_for_healthy reticulum-python-hub 60
    wait_for_healthy reticulum-rust-node 60
}

# Stop containers
stop_containers() {
    info "Stopping containers..."
    cd "$(dirname "$0")/../../docker"
    docker compose down
    cd - > /dev/null
}

# Print test summary
print_summary() {
    echo ""
    echo "========================================="
    echo "Test Summary"
    echo "========================================="
    echo -e "Passed: ${GREEN}${TESTS_PASSED}${NC}"
    echo -e "Failed: ${RED}${TESTS_FAILED}${NC}"
    echo "========================================="

    if [ $TESTS_FAILED -gt 0 ]; then
        return 1
    fi
    return 0
}

# Assert that two values are equal
assert_eq() {
    local expected=$1
    local actual=$2
    local message=${3:-"Values should be equal"}

    if [ "$expected" = "$actual" ]; then
        success "$message"
        return 0
    else
        fail "$message (expected: $expected, actual: $actual)"
        return 1
    fi
}

# Assert that a command succeeds
assert_success() {
    local message=$1
    shift

    if "$@" > /dev/null 2>&1; then
        success "$message"
        return 0
    else
        fail "$message"
        return 1
    fi
}

# Assert that output contains a string
assert_contains() {
    local output=$1
    local expected=$2
    local message=${3:-"Output should contain expected string"}

    if echo "$output" | grep -q "$expected"; then
        success "$message"
        return 0
    else
        fail "$message (expected to contain: $expected)"
        return 1
    fi
}
