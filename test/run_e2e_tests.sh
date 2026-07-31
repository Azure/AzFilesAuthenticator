#!/bin/bash
# Test Execution Guide
# Runs the original test suite and optional legacy integration tests.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# ============================================================================
# CONFIGURATION
# ============================================================================

print_header "Test Configuration"

# Default values
STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-azfilestesting8661}"
FILE_SHARE="${FILE_SHARE:-testshare}"
TENANT_ID="${TENANT_ID:-72f988bf-86f1-41af-91ab-2d7cd011db47}"
USER_MI_CLIENT_ID="${USER_MI_CLIENT_ID:-}"
WORKLOAD_CLIENT_ID="${WORKLOAD_CLIENT_ID:-}"
WORKLOAD_TOKEN_FILE="${WORKLOAD_TOKEN_FILE:-}"

# VM connection
VM_IP="${VM_IP:-20.219.7.207}"
VM_USER="${VM_USER:-azureuser}"
SSH_KEY="${SSH_KEY:-}"

# Test environment
MOUNT_BASE="/mnt/azfiles_test"
TEST_TIMEOUT=300

print_info "Storage Account: $STORAGE_ACCOUNT"
print_info "File Share: $FILE_SHARE"
print_info "Tenant ID: $TENANT_ID"
print_info "Mount Base: $MOUNT_BASE"

if [ -z "$USER_MI_CLIENT_ID" ]; then
    print_info "User MI Client ID: (not configured - user MI tests will be skipped)"
else
    print_info "User MI Client ID: ${USER_MI_CLIENT_ID:0:8}..."
fi

if [ -z "$WORKLOAD_CLIENT_ID" ]; then
    print_info "Workload Identity: (not configured - workload tests will be skipped)"
else
    print_info "Workload Identity Client ID: ${WORKLOAD_CLIENT_ID:0:8}..."
fi

# ============================================================================
# PREFLIGHT CHECKS
# ============================================================================

print_header "Preflight Checks"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "Tests must run as root (use: sudo $0)"
    exit 1
fi
print_success "Running as root"

# Check if azfilesauthmanager is installed
if ! command -v azfilesauthmanager &> /dev/null; then
    print_error "azfilesauthmanager not found in PATH"
    echo "Install the azfilesauth package:"
    echo "  sudo apt-get install ./azfilesauth_*.deb"
    exit 1
fi
print_success "azfilesauthmanager installed"

# Check if cifs-utils is installed
if ! command -v mount.cifs &> /dev/null; then
    print_error "cifs-utils not installed"
    echo "Install with: sudo apt-get install cifs-utils"
    exit 1
fi
print_success "cifs-utils installed"

# Check if klist is available
if ! command -v klist &> /dev/null; then
    print_error "krb5-user not installed"
    echo "Install with: sudo apt-get install krb5-user"
    exit 1
fi
print_success "krb5-user installed"

# Check mount directory
if [ ! -d "$MOUNT_BASE" ]; then
    print_info "Creating mount base directory: $MOUNT_BASE"
    mkdir -p "$MOUNT_BASE"
fi
print_success "Mount base directory ready: $MOUNT_BASE"

# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================

print_header "Environment Setup"

# Export test variables
export STORAGE_ACCOUNT
export FILE_SHARE
export TENANT_ID
export USER_MI_CLIENT_ID
export WORKLOAD_CLIENT_ID
export WORKLOAD_TOKEN_FILE

print_success "Environment variables exported"

# Get script directory (this script lives inside test/)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TEST_DIR="$SCRIPT_DIR"

print_info "Test directory: $TEST_DIR"

if [ ! -f "$TEST_DIR/test_imports.py" ]; then
    print_error "test_imports.py not found at $TEST_DIR"
    exit 1
fi

if [ ! -f "$TEST_DIR/test_unit.py" ]; then
    print_error "test_unit.py not found at $TEST_DIR"
    exit 1
fi

print_success "All test files present"

# ============================================================================
# PRE-TEST CLEANUP
# ============================================================================

print_header "Pre-Test Cleanup"

# Unmount any existing test mounts
print_info "Unmounting any existing test mounts..."
while mount | grep "$MOUNT_BASE" > /dev/null; do
    MOUNTS=$(mount | grep "$MOUNT_BASE" | awk '{print $3}')
    for mount_point in $MOUNTS; do
        print_info "Unmounting $mount_point..."
        umount "$mount_point" || true
    done
done
print_success "Test mount cleanup complete"

# Clear any existing credentials
print_info "Clearing existing credentials..."
FILE_ENDPOINT="https://${STORAGE_ACCOUNT}.file.core.windows.net"
azfilesauthmanager clear "$FILE_ENDPOINT" || true
print_success "Credential cleanup complete"

# ============================================================================
# TEST EXECUTION
# ============================================================================

print_header "Running Static and Unit Tests"

# Run static import/syntax checks
print_info "Running test_imports.py..."
echo ""

if python3 "$TEST_DIR/test_imports.py"; then
    print_success "Static analysis tests completed"
    IMPORTS_RESULT=0
else
    print_error "Static analysis tests failed"
    IMPORTS_RESULT=1
fi

# Run unit tests
print_header "Running Unit Tests"

print_info "Running test_unit.py..."
echo ""

if python3 "$TEST_DIR/test_unit.py"; then
    print_success "Unit tests completed"
    UNIT_RESULT=0
else
    print_error "Unit tests failed"
    UNIT_RESULT=1
fi

# Run legacy integration tests only when the required config is present.
print_header "Running Legacy Integration Tests"

if [ -f "$TEST_DIR/test_config.yaml" ]; then
    print_info "Running tests.py run ${FILE_ENDPOINT}..."
    echo ""

    if python3 "$TEST_DIR/tests.py" run "$FILE_ENDPOINT"; then
        print_success "Legacy integration tests completed"
        LEGACY_RESULT=0
    else
        print_error "Legacy integration tests failed"
        LEGACY_RESULT=1
    fi
else
    print_info "Skipping tests.py: $TEST_DIR/test_config.yaml not found"
    LEGACY_RESULT=0
fi

# ============================================================================
# POST-TEST CLEANUP
# ============================================================================

print_header "Post-Test Cleanup"

# Unmount test mounts
print_info "Unmounting test mounts..."
while mount | grep "$MOUNT_BASE" > /dev/null; do
    MOUNTS=$(mount | grep "$MOUNT_BASE" | awk '{print $3}')
    for mount_point in $MOUNTS; do
        print_info "Unmounting $mount_point..."
        umount "$mount_point" || true
    done
done
print_success "Unmount complete"

# Clear credentials
print_info "Clearing test credentials..."
azfilesauthmanager clear "$FILE_ENDPOINT" || true
print_success "Credential cleanup complete"

# ============================================================================
# FINAL SUMMARY
# ============================================================================

print_header "Test Execution Summary"

IMPORTS_STATUS=$([ $IMPORTS_RESULT -eq 0 ] && printf "%b" "${GREEN}PASSED${NC}" || printf "%b" "${RED}FAILED${NC}")
UNIT_STATUS=$([ $UNIT_RESULT -eq 0 ] && printf "%b" "${GREEN}PASSED${NC}" || printf "%b" "${RED}FAILED${NC}")
LEGACY_STATUS=$([ $LEGACY_RESULT -eq 0 ] && printf "%b" "${GREEN}PASSED${NC}" || printf "%b" "${RED}FAILED${NC}")
echo -e "Static Tests (test_imports.py): ${IMPORTS_STATUS}"
echo -e "Unit Tests (test_unit.py): ${UNIT_STATUS}"
echo -e "Legacy Integration (tests.py): ${LEGACY_STATUS}"

if [ $IMPORTS_RESULT -eq 0 ] && [ $UNIT_RESULT -eq 0 ] && [ $LEGACY_RESULT -eq 0 ]; then
    print_success "All tests PASSED ✓"
    exit 0
else
    print_error "Some tests FAILED ✗"
    exit 1
fi
