#!/bin/bash
# deploy/run_e2e_in_container.sh
#
# Runs test/run_e2e_tests.sh (with real managed-identity SMB mount) inside a
# privileged Docker container for a single distro, on a host that already has
# network access to Azure IMDS and the target storage account (e.g. a VM in
# the same VNet with a system-assigned managed identity and the
# "Storage File Data SMB MI Admin" role on the storage account).
#
# Usage (run on the VM, from the repo root):
#   STORAGE_ACCOUNT=<acct> FILE_SHARE=<share> \
#     bash deploy/run_e2e_in_container.sh <distro> <path-to-package>
#
# <distro> must have a matching test/distro_run/<distro>.containerfile.
set -euo pipefail

DISTRO="$1"
PKG_PATH="$2"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_TAG="azfilesauth-e2e-${DISTRO}"

STORAGE_ACCOUNT="${STORAGE_ACCOUNT:?Set STORAGE_ACCOUNT}"
FILE_SHARE="${FILE_SHARE:-testshare}"
USER_MI_CLIENT_ID="${USER_MI_CLIENT_ID:-5fa7364f-4339-4abd-ac64-92e29ee053a2}"

# Extra packages each distro needs for a real e2e run.
declare -A EXTRA_INSTALL=(
    [ubuntu20]="apt-get update -qq && apt-get install -y -qq cifs-utils keyutils krb5-user"
    [ubuntu22]="apt-get update -qq && apt-get install -y -qq cifs-utils keyutils krb5-user"
    [ubuntu24]="apt-get update -qq && apt-get install -y -qq cifs-utils keyutils krb5-user"
    [rhel9]="dnf install -y cifs-utils keyutils krb5-workstation"
    [rhel10]="dnf install -y cifs-utils keyutils krb5-workstation"
    [azlinux3]="tdnf install -y cifs-utils keyutils krb5 util-linux"
    [sles15]="zypper --non-interactive install -y cifs-utils keyutils krb5-client"
)

echo "=== [$DISTRO] Building run image from $(basename "$PKG_PATH") ==="
PKG_DIR="$(mktemp -d)"
cp "$PKG_PATH" "$PKG_DIR/"
docker build -f "$REPO_ROOT/test/distro_run/${DISTRO}.containerfile" -t "$RUN_TAG" "$PKG_DIR"
rm -rf "$PKG_DIR"

echo "=== [$DISTRO] Running e2e tests (RUN_MI_LIFECYCLE_TESTS=1) ==="
# Plain `docker run` has no login session, so MIT krb5's default KEYRING
# ccache (and its per-session keyring requirements) doesn't work reliably.
# Force a FILE-based ccache directly in /etc/krb5.conf, matching the config
# already used on the real VM (deploy/test-vms.sh applies the same override
# for RHEL/SLES; here we need it unconditionally since there's no session).
KRB5_FILE_CACHE_CMD='printf "[libdefaults]\n  default_ccache_name = FILE:/tmp/krb5cc_%%{uid}\n" > /etc/krb5.conf'

docker run --rm --privileged \
    -v "$REPO_ROOT/test:/repo/test:ro" \
    -v "$REPO_ROOT/src:/repo/src:ro" \
    -e STORAGE_ACCOUNT="$STORAGE_ACCOUNT" \
    -e FILE_SHARE="$FILE_SHARE" \
    -e USER_MI_CLIENT_ID="$USER_MI_CLIENT_ID" \
    -e RUN_MI_LIFECYCLE_TESTS=1 \
    -e PYTHON=/opt/azfilesauth/venv/bin/python \
    "$RUN_TAG" \
    bash -c "${EXTRA_INSTALL[$DISTRO]} && ${KRB5_FILE_CACHE_CMD} && bash /repo/test/run_e2e_tests.sh"
