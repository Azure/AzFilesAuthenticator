#!/bin/bash
# test/test_package_builds.sh
#
# End-to-end test framework for azfilesauth package builds.
# For each target distro:
#   1. Build the package in a Docker container (mirrors CI pipeline)
#   2. Extract the built package
#   3. Install the package on a clean distro image
#   4. Validate: file checks + azfilesauthmanager --version
#
# Usage:
#   ./test/test_package_builds.sh              # test all distros
#   ./test/test_package_builds.sh sles15       # test one distro
#   ./test/test_package_builds.sh ubuntu22 rhel9  # test specific distros

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
RUN_DIR="$SCRIPT_DIR/distro_run"
ARTIFACTS_DIR="$SCRIPT_DIR/artifacts"

# All supported distros (must have matching Dockerfiles in build/ and distro_run/)
ALL_DISTROS=(ubuntu22 ubuntu24 sles15 rhel9 rhel10 azlinux3)

# Package type per distro
declare -A PKG_TYPE=(
    [ubuntu22]=deb
    [ubuntu24]=deb
    [sles15]=rpm
    [rhel9]=rpm
    [rhel10]=rpm
    [azlinux3]=rpm
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

passed=0
failed=0
skipped=0
results=()

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[SKIP]${NC} $*"; }

# Determine which distros to test
if [ $# -gt 0 ]; then
    DISTROS=("$@")
else
    DISTROS=("${ALL_DISTROS[@]}")
fi

# Validate distro names
for distro in "${DISTROS[@]}"; do
    if [ ! -f "$BUILD_DIR/$distro.containerfile" ]; then
        echo "Error: No build containerfile found for '$distro' at $BUILD_DIR/$distro.containerfile"
        echo "Available distros: ${ALL_DISTROS[*]}"
        exit 1
    fi
    if [ ! -f "$RUN_DIR/$distro.containerfile" ]; then
        echo "Error: No run containerfile found for '$distro' at $RUN_DIR/$distro.containerfile"
        exit 1
    fi
done

mkdir -p "$ARTIFACTS_DIR"

echo ""
echo "========================================"
echo " azfilesauth Package Build & Test"
echo "========================================"
echo " Distros: ${DISTROS[*]}"
echo " Source:  $REPO_ROOT"
echo "========================================"
echo ""

for distro in "${DISTROS[@]}"; do
    pkg_type="${PKG_TYPE[$distro]}"
    build_tag="azfilesauth-build-$distro"
    run_tag="azfilesauth-run-$distro"
    distro_artifacts="$ARTIFACTS_DIR/$distro"

    echo ""
    log "========== $distro ($pkg_type) =========="

    # --- Step 1: Build ---
    log "[$distro] Building package..."
    build_log=$(mktemp)
    if ! docker build -f "$BUILD_DIR/$distro.containerfile" -t "$build_tag" "$REPO_ROOT" > "$build_log" 2>&1; then
        tail -20 "$build_log"
        rm -f "$build_log"
        fail "[$distro] Package build failed"
        failed=$((failed + 1))
        results+=("FAIL  $distro  build-failed")
        continue
    fi
    tail -5 "$build_log"
    rm -f "$build_log"
    pass "[$distro] Package built"

    # --- Step 2: Extract artifacts ---
    log "[$distro] Extracting built packages..."
    rm -rf "$distro_artifacts"
    mkdir -p "$distro_artifacts"

    container_id=$(docker create "$build_tag")
    if [ "$pkg_type" = "deb" ]; then
        docker cp "$container_id:/build/PACKAGES/deb/." "$distro_artifacts/" 2>/dev/null
    else
        docker cp "$container_id:/build/PACKAGES/rpm/." "$distro_artifacts/" 2>/dev/null
    fi
    docker rm "$container_id" > /dev/null

    pkg_count=$(find "$distro_artifacts" -name "*.${pkg_type}" | wc -l)
    if [ "$pkg_count" -eq 0 ]; then
        fail "[$distro] No .${pkg_type} packages extracted"
        failed=$((failed + 1))
        results+=("FAIL  $distro  no-packages")
        continue
    fi
    pass "[$distro] Extracted $pkg_count package(s)"
    ls "$distro_artifacts"/*.${pkg_type}

    # --- Step 3: Install & Validate ---
    log "[$distro] Installing and validating on clean image..."
    run_log=$(mktemp)
    if ! docker build -f "$RUN_DIR/$distro.containerfile" -t "$run_tag" "$distro_artifacts" > "$run_log" 2>&1; then
        tail -30 "$run_log"
        rm -f "$run_log"
        fail "[$distro] Install/validation failed"
        failed=$((failed + 1))
        results+=("FAIL  $distro  install-failed")
        continue
    fi
    tail -20 "$run_log"
    rm -f "$run_log"
    pass "[$distro] Package installed and validated"

    # --- Step 4: Run azfilesauthmanager --version ---
    log "[$distro] Running azfilesauthmanager --version..."
    version_output=$(docker run --rm "$run_tag" azfilesauthmanager --version 2>&1)
    if [ -n "$version_output" ] && [ "$version_output" != "" ]; then
        pass "[$distro] azfilesauthmanager --version => $version_output"
        passed=$((passed + 1))
        results+=("PASS  $distro  version=$version_output")
    else
        fail "[$distro] azfilesauthmanager --version returned empty output"
        failed=$((failed + 1))
        results+=("FAIL  $distro  version-empty")
        continue
    fi

    # --- Step 5: Run azfilesrefresh smoke test ---
    # azfilesrefresh is a long-running daemon; run it briefly to catch import/startup errors.
    # timeout exits 124 when the process is killed (expected), any other non-zero = real error.
    log "[$distro] Running azfilesrefresh for 5s smoke test..."
    refresh_log=$(mktemp)
    refresh_rc=0
    docker run --rm "$run_tag" \
        timeout 5 azfilesrefresh > "$refresh_log" 2>&1 || refresh_rc=$?

    if [ "$refresh_rc" -eq 124 ] || [ "$refresh_rc" -eq 0 ]; then
        # 124 = killed by timeout (expected), 0 = exited cleanly
        pass "[$distro] azfilesrefresh started without errors (exit=$refresh_rc)"
        passed=$((passed + 1))
        results+=("PASS  $distro  azfilesrefresh-smoke")
    else
        tail -20 "$refresh_log"
        fail "[$distro] azfilesrefresh failed on startup (exit=$refresh_rc)"
        failed=$((failed + 1))
        results+=("FAIL  $distro  azfilesrefresh-smoke")
    fi
    rm -f "$refresh_log"

    # --- Step 6: Run unit tests inside distro container ---
    log "[$distro] Running unit tests on distro's Python..."
    unit_log=$(mktemp)
    if docker run --rm \
        -v "$REPO_ROOT/test:/tests:ro" \
        -v "$REPO_ROOT/src:/src:ro" \
        "$run_tag" \
        python3 /tests/test_unit.py 2>&1 | tee "$unit_log" | tail -5; then
        pass "[$distro] Unit tests passed on distro Python"
        passed=$((passed + 1))
        results+=("PASS  $distro  unit-tests")
    else
        tail -20 "$unit_log"
        fail "[$distro] Unit tests failed on distro Python"
        failed=$((failed + 1))
        results+=("FAIL  $distro  unit-tests")
    fi
    rm -f "$unit_log"
done

# --- Summary ---
echo ""
echo "========================================"
echo " Test Summary"
echo "========================================"
for r in "${results[@]}"; do
    echo "  $r"
done
echo ""
echo "  Passed: $passed"
echo "  Failed: $failed"
echo "========================================"

if [ "$failed" -gt 0 ]; then
    exit 1
fi
