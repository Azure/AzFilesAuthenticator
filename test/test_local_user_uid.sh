#!/bin/bash
# test/test_local_user_uid.sh
#
# Functional test for USER_UID resolution. This script expects the package and
# native library to already be installed in the current test environment; the
# package/container orchestration belongs to test_package_builds.sh or
# deploy/run_e2e_in_container.sh.
# It verifies that:
#   1. init_new_user() does NOT create/require a shared "azfilesuser" when
#      USER_UID is the "local" sentinel.
#   2. Each invocation resolves the credential cache to the invoking user's
#      own UID (via SUDO_UID, falling back to the real UID), rather than a
#      single shared cache file — this is what unblocks storing multiple
#      identities against the same storage account.
#
# Does not require real Azure credentials: it only asserts which ccache UID
# the native library resolves to (via file-based logging), not that a real
# ticket gets stored.
#
set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[test_local_user_uid]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

if [ "$EUID" -ne 0 ]; then
    fail "Tests must run as root"
fi
if ! command -v azfilesauthmanager > /dev/null 2>&1; then
    fail "azfilesauthmanager is not installed"
fi

CONFIG_PATH="/etc/azfilesauth/config.yaml"
BACKUP_PATH="$(mktemp)"
USER_EXISTED=0
if getent passwd azfilesuser > /dev/null 2>&1; then
    USER_EXISTED=1
fi

restore_state() {
    if [ -f "$BACKUP_PATH" ]; then
        cp "$BACKUP_PATH" "$CONFIG_PATH"
        rm -f "$BACKUP_PATH"
    fi
    if [ "$USER_EXISTED" -eq 0 ] && getent passwd azfilesuser > /dev/null 2>&1; then
        userdel -r azfilesuser > /dev/null 2>&1 || true
    fi
}
trap restore_state EXIT
cp "$CONFIG_PATH" "$BACKUP_PATH"

log "Running assertions against the installed package..."
output=$(bash -c '
set -e
cat > /etc/azfilesauth/config.yaml << "EOF"
USER_UID: local
LOG_DESTINATION: file
LOG_FILE_PATH: /var/log/azfilesauth.log
EOF

# No shared user should exist before or after any invocation.
getent passwd azfilesuser > /dev/null 2>&1 && echo "UNEXPECTED_USER_EXISTS_BEFORE"

SUDO_UID=2001 azfilesauthmanager list --json > /dev/null 2>&1 || true
SUDO_UID=2002 azfilesauthmanager list --json > /dev/null 2>&1 || true
azfilesauthmanager list --json > /dev/null 2>&1 || true

getent passwd azfilesuser > /dev/null 2>&1 && echo "UNEXPECTED_USER_EXISTS_AFTER"

echo "=== local USER_UID config ==="
cat /etc/azfilesauth/config.yaml

# Verify default shared-account mode with USER_UID absent.
if ! getent passwd azfilesuser > /dev/null 2>&1; then
    useradd -m azfilesuser
fi
shared_uid="$(id -u azfilesuser)"
cat > /etc/azfilesauth/config.yaml << "EOF"
LOG_DESTINATION: file
LOG_FILE_PATH: /var/log/azfilesauth.log
EOF
azfilesauthmanager list --json > /dev/null 2>&1 || true
echo "=== absent USER_UID config ==="
cat /etc/azfilesauth/config.yaml
echo "=== absent USER_UID log ==="
tail -5 /var/log/azfilesauth.log

echo "=== log ==="
cat /var/log/azfilesauth.log
')

echo "$output"

if [ "$USER_EXISTED" -eq 0 ]; then
    echo "$output" | grep -q "UNEXPECTED_USER_EXISTS_BEFORE" && fail "azfilesuser existed before any invocation"
    echo "$output" | grep -q "UNEXPECTED_USER_EXISTS_AFTER" && fail "azfilesuser was created despite USER_UID: local"
    pass "No shared azfilesuser was created"
else
    pass "Existing azfilesuser preserved while testing local mode"
fi

echo "$output" | awk '/=== local USER_UID config ===/{flag=1; next} /=== absent USER_UID config ===/{flag=0} flag' | grep -q "^USER_UID: local$" || fail "config.yaml USER_UID sentinel was overwritten"
pass "USER_UID sentinel left untouched in config.yaml"

echo "$output" | grep -q "Using default per-user ccache for UID: 2001" || fail "Did not resolve SUDO_UID=2001 to its own ccache"
pass "SUDO_UID=2001 resolved to its own ccache"

echo "$output" | grep -q "Using default per-user ccache for UID: 2002" || fail "Did not resolve SUDO_UID=2002 to its own ccache"
pass "SUDO_UID=2002 resolved to its own ccache (distinct from 2001)"

echo "$output" | grep -q "Using default per-user ccache for UID: 0" || fail "Did not fall back to the real UID when SUDO_UID is unset"
pass "Falls back to the real UID when SUDO_UID is unset"

echo "$output" | grep -q "Using default per-user ccache for UID: ${shared_uid}" || fail "Native library did not resolve existing azfilesuser UID ${shared_uid}"
pass "Native library resolved existing azfilesuser without USER_UID"

if echo "$output" | awk '/=== absent USER_UID config ===/{flag=1; next} /=== absent USER_UID log ===/{flag=0} flag' | grep -q "USER_UID"; then
    fail "Absent USER_UID config was modified"
fi
pass "Absent USER_UID config remained unchanged"

pass "All USER_UID: local assertions passed"
