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

# Sentinel file to track if images are already built
BUILD_SENTINEL="${BUILD_SENTINEL:-/tmp/reticulum-test-images-built}"

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

# Build containers (respects sentinel for optimization)
build_containers() {
    local force_build=${1:-false}

    cd "$(dirname "$0")/../../docker"

    # Check if we should skip build
    if [ -f "$BUILD_SENTINEL" ] && [ "$force_build" != "true" ]; then
        info "Using existing images (build sentinel detected)"
        docker compose up -d --no-build
    else
        info "Building Docker images (--no-cache to ensure fresh build)..."
        docker compose build --no-cache
        docker compose up -d

        # Create sentinel if it doesn't exist
        if [ ! -f "$BUILD_SENTINEL" ]; then
            touch "$BUILD_SENTINEL"
            # Mark that we created it (for cleanup)
            export CREATED_BUILD_SENTINEL=true
        fi
    fi

    cd - > /dev/null
}

# Start containers if not running (uses build_containers)
start_containers() {
    info "Starting containers..."
    build_containers
    wait_for_healthy reticulum-python-hub 60
    wait_for_healthy reticulum-rust-node 60
}

# Clean up build sentinel if we created it
cleanup_build_sentinel() {
    if [ "${CREATED_BUILD_SENTINEL:-false}" = "true" ] && [ -f "$BUILD_SENTINEL" ]; then
        rm -f "$BUILD_SENTINEL"
    fi
}

# Register cleanup trap (only if not already set by test)
trap cleanup_build_sentinel EXIT

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

# ============================================
# Background Process Management
# ============================================

# Run a command in a container in the background, capturing output to a file
# Returns: "PID:CAT_PID:FIFO:OUTPUT_FILE"
run_in_background() {
    local container=$1
    local timeout=$2
    shift 2
    local command="$@"

    local fifo=$(mktemp -u)
    mkfifo "$fifo"
    local output=$(mktemp)

    (docker exec "$container" timeout "$timeout" $command > "$fifo" 2>&1) &
    local pid=$!

    cat "$fifo" > "$output" &
    local cat_pid=$!

    echo "$pid:$cat_pid:$fifo:$output"
}

# Wait for a background process to complete and return output file path
# Args: handle from run_in_background
# Returns: path to output file
wait_for_background() {
    local handle=$1
    IFS=':' read -r pid cat_pid fifo output <<< "$handle"

    wait "$pid" 2>/dev/null || true
    wait "$cat_pid" 2>/dev/null || true
    rm -f "$fifo"

    echo "$output"
}

# Cleanup background process (graceful kill with timeout)
kill_background() {
    local handle=$1
    local timeout=${2:-5}
    IFS=':' read -r pid cat_pid fifo output <<< "$handle"

    # Kill main process
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true

        # Wait for graceful exit
        for i in $(seq 1 $timeout); do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            sleep 1
        done

        # Force kill if still running
        kill -9 "$pid" 2>/dev/null || true
    fi

    # Kill cat process
    kill "$cat_pid" 2>/dev/null || true
    kill -9 "$cat_pid" 2>/dev/null || true

    # Cleanup
    rm -f "$fifo" "$output"
}

# ============================================
# Destination Hash Helpers
# ============================================

# Wait for destination hash to appear in output file
# Returns: destination hash or empty string on timeout
wait_for_destination_hash() {
    local output_file=$1
    local timeout=${2:-10}
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        if [ -f "$output_file" ] && grep -q "DESTINATION_HASH=" "$output_file" 2>/dev/null; then
            grep "DESTINATION_HASH=" "$output_file" | head -1 | cut -d= -f2
            return 0
        fi
        sleep 1
        ((elapsed++))
    done

    return 1
}

# Extract any field from output file (KEY=VALUE format)
extract_field() {
    local output_file=$1
    local field_name=$2

    if [ -f "$output_file" ] && grep -q "${field_name}=" "$output_file" 2>/dev/null; then
        grep "${field_name}=" "$output_file" | head -1 | cut -d= -f2
        return 0
    fi

    return 1
}

# ============================================
# Temporary File Management
# ============================================

declare -a TEMP_FILES=()

# Create a temporary file and register it for cleanup
create_temp_file() {
    local temp=$(mktemp)
    TEMP_FILES+=("$temp")
    echo "$temp"
}

# Cleanup all registered temporary files
cleanup_temp_files() {
    for file in "${TEMP_FILES[@]}"; do
        rm -f "$file" 2>/dev/null || true
    done
    TEMP_FILES=()
}

# Register cleanup trap (safe to call multiple times)
register_cleanup_trap() {
    trap 'cleanup_temp_files; cleanup_build_sentinel' EXIT INT TERM
}

# ============================================
# Docker Execution Helpers
# ============================================

# Execute command in container with timeout
exec_with_timeout() {
    local container=$1
    local timeout=$2
    shift 2
    docker exec "$container" timeout "$timeout" "$@" 2>&1 || true
}

# ============================================
# Log Collection
# ============================================

# Get container logs (last N lines)
get_container_logs() {
    local container=$1
    local lines=${2:-50}
    docker logs "$container" 2>&1 | tail -"$lines"
}

# Dump logs from all standard containers
dump_all_logs() {
    local lines=${1:-30}
    echo ""
    info "Python hub logs:"
    get_container_logs reticulum-python-hub "$lines"
    echo ""
    info "Rust node logs:"
    get_container_logs reticulum-rust-node "$lines"
}

# ============================================
# Output Validation
# ============================================

# Check if output contains a marker
has_marker() {
    local output=$1
    local marker=$2
    grep -q "$marker" <<< "$output"
}
