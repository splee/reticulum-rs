#!/bin/bash
# Run all integration tests for Python-Rust Reticulum interoperability
#
# Usage:
#   ./tests/integration/run_all.sh          # Run all tests
#   ./tests/integration/run_all.sh --keep   # Keep containers running after tests

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/../../docker"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

KEEP_CONTAINERS=false
TOTAL_PASSED=0
TOTAL_FAILED=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep)
            KEEP_CONTAINERS=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}"
echo "========================================"
echo "Python-Rust Reticulum Integration Tests"
echo "========================================"
echo -e "${NC}"

# Set up build sentinel to avoid rebuilding for each test
BUILD_SENTINEL="/tmp/reticulum-test-images-built"
export BUILD_SENTINEL

# Create sentinel to indicate we're managing builds
touch "$BUILD_SENTINEL"
trap "rm -f '$BUILD_SENTINEL'" EXIT INT TERM

# Build and start containers (only builds once)
echo -e "${YELLOW}Building and starting containers...${NC}"
cd "$DOCKER_DIR"
docker compose up -d --build 2>&1 | grep -v "^$"
cd - > /dev/null

# Wait for containers to be healthy
echo -e "${YELLOW}Waiting for containers to be ready...${NC}"
sleep 10

# Check container status
echo -e "${YELLOW}Container status:${NC}"
docker compose ps

# Run each test
run_test() {
    local test_name=$1
    local test_script=$2

    echo ""
    echo -e "${CYAN}Running: $test_name${NC}"
    echo "----------------------------------------"

    if bash "$test_script"; then
        ((TOTAL_PASSED++))
        echo -e "${GREEN}$test_name: PASSED${NC}"
    else
        ((TOTAL_FAILED++))
        echo -e "${RED}$test_name: FAILED${NC}"
    fi
}

# Make test scripts executable
chmod +x "$SCRIPT_DIR"/*.sh

# Run tests
run_test "Connectivity Test" "$SCRIPT_DIR/test_connectivity.sh"
run_test "Identity Interop Test" "$SCRIPT_DIR/test_identity_interop.sh"
run_test "Local Client Announces (Native)" "$SCRIPT_DIR/test_local_client_announces.sh"
run_test "Python Client via Rust Hub" "$SCRIPT_DIR/test_python_client_via_rust_hub.sh"
run_test "Link Test" "$SCRIPT_DIR/test_link.sh"
run_test "Link Data Test" "$SCRIPT_DIR/test_link_data.sh"
run_test "Resource Test" "$SCRIPT_DIR/test_resource.sh"
run_test "Resource Rust→Python Test" "$SCRIPT_DIR/test_resource_rust_to_python.sh"
run_test "Probe Test" "$SCRIPT_DIR/test_probe.sh"
run_test "Path Test" "$SCRIPT_DIR/test_path.sh"
run_test "Remote Status Test" "$SCRIPT_DIR/test_remote_status.sh"
run_test "Remote Status (Rust Server) Test" "$SCRIPT_DIR/test_remote_status_rust.sh"

# Print final summary
echo ""
echo -e "${CYAN}========================================"
echo "Final Test Summary"
echo "========================================${NC}"
echo -e "Total Passed: ${GREEN}${TOTAL_PASSED}${NC}"
echo -e "Total Failed: ${RED}${TOTAL_FAILED}${NC}"
echo "========================================"

# Show container logs on failure
if [ $TOTAL_FAILED -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}Container logs (last 30 lines each):${NC}"
    echo ""
    echo "=== Python Hub ==="
    docker logs reticulum-python-hub 2>&1 | tail -30
    echo ""
    echo "=== Rust Node ==="
    docker logs reticulum-rust-node 2>&1 | tail -30
fi

# Cleanup
if [ "$KEEP_CONTAINERS" = false ]; then
    echo ""
    echo -e "${YELLOW}Stopping containers...${NC}"
    docker compose down
else
    echo ""
    echo -e "${YELLOW}Containers kept running (use 'docker compose down' to stop)${NC}"
fi

# Exit with appropriate code
if [ $TOTAL_FAILED -gt 0 ]; then
    exit 1
fi
exit 0
