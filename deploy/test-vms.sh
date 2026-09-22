#!/bin/bash
# test-vms.sh — Build packages, provision Azure VMs, install and run E2E tests.
#
# Supported distros: Ubuntu 24.04, RHEL 9, SLES 15 SP7
#
# Usage:
#   bash deploy/test-vms.sh [--skip-build] [--skip-infra] [--distro ubuntu|rhel9|sles15]
#
# Environment overrides:
#   SUBSCRIPTION_ID, RESOURCE_GROUP, LOCATION
#   STORAGE_ACCOUNT   (auto-generated if not set)
#   USER_MI_CLIENT_ID (optional — enables user-assigned MI tests)
#   SSH_PRIVATE_KEY   (default: ~/.ssh/azfilesauth-test; generated if absent)
set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────
SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-1a55ef16-6bc5-43da-b0ac-efdc2f56f1a8}"
RESOURCE_GROUP="${RESOURCE_GROUP:-sprasad-azfiles-final-test}"
LOCATION="${LOCATION:-centralindia}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-}"
FILE_SHARE="testshare"

VM_USER="azureuser"
SSH_PRIVATE_KEY="${SSH_PRIVATE_KEY:-$HOME/.ssh/azfilesauth-test}"
SSH_PUBLIC_KEY="${SSH_PRIVATE_KEY}.pub"

UBUNTU_VM="azfiles-ubuntu24-vm"
RHEL9_VM="azfiles-rhel9-vm"
SLES15_VM="azfiles-sles15sp7-vm"

UBUNTU_IMAGE="Ubuntu2404"
RHEL9_IMAGE="RedHat:RHEL:9-lvm-gen2:9.8.2026062323"
SLES15_IMAGE="SUSE:sles-15-sp7:gen2:2026.07.22"

UBUNTU_PKG="$REPO_ROOT/PACKAGES/deb/azfilesauth_1.0-11_amd64.noble.deb"
RHEL9_PKG="$REPO_ROOT/PACKAGES/rpm/azfilesauth-1.0-11.el9.x86_64.rpm"
SLES15_PKG="$REPO_ROOT/PACKAGES/rpm/azfilesauth-1.0-11.x86_64.rpm"

SSH_OPTS=(
    -i "$SSH_PRIVATE_KEY"
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=no
    -o ConnectTimeout=30
    -o ServerAliveInterval=10
)

# ─── Parse flags ──────────────────────────────────────────────────────────────
SKIP_BUILD=0
SKIP_INFRA=0
DISTRO_FILTER=""   # empty = all

for arg in "$@"; do
    case "$arg" in
        --skip-build)   SKIP_BUILD=1 ;;
        --skip-infra)   SKIP_INFRA=1 ;;
        --distro=*)     DISTRO_FILTER="${arg#--distro=}" ;;
    esac
done

# ─── Helpers ──────────────────────────────────────────────────────────────────
green() { echo -e "\033[0;32m✓ $*\033[0m"; }
red()   { echo -e "\033[0;31m✗ $*\033[0m"; exit 1; }
warn()  { echo -e "\033[0;33m⚠ $*\033[0m"; }
info()  { echo -e "\033[0;34mℹ $*\033[0m"; }
step()  { echo -e "\n\033[1;33m=== $* ===\033[0m"; }

ensure_ssh_key() {
    if [ ! -f "$SSH_PRIVATE_KEY" ]; then
        info "Generating SSH key: $SSH_PRIVATE_KEY"
        mkdir -p "$(dirname "$SSH_PRIVATE_KEY")"
        ssh-keygen -q -t ed25519 -N "" -f "$SSH_PRIVATE_KEY"
    fi
    [ -f "$SSH_PUBLIC_KEY" ] || ssh-keygen -y -f "$SSH_PRIVATE_KEY" > "$SSH_PUBLIC_KEY"
    chmod 600 "$SSH_PRIVATE_KEY"
}

ssh_vm()    { ssh "${SSH_OPTS[@]}" "$VM_USER@$1" "${@:2}"; }
scp_to_vm() { scp "${SSH_OPTS[@]}" -r "$1" "$VM_USER@$2:$3"; }

ensure_vm_ssh_key() {
    local vm_name="$1" ip="$2"
    if ssh_vm "$ip" "true" &>/dev/null; then
        return
    fi

    info "Installing SSH public key on existing VM $vm_name..."
    az vm user update --subscription "$SUBSCRIPTION_ID" \
        --resource-group "$RESOURCE_GROUP" --name "$vm_name" \
        --username "$VM_USER" --ssh-key-value "$SSH_PUBLIC_KEY" \
        --only-show-errors --output none
}

wait_for_ssh() {
    local ip="$1" name="$2"
    info "Waiting for SSH on $name ($ip)..."
    for i in $(seq 1 40); do
        ssh_vm "$ip" "echo ok" &>/dev/null && { green "SSH ready on $name"; return 0; }
        echo -n "."; sleep 10
    done
    red "SSH never became available on $name"
}

harden_ssh() {
    local ip="$1" name="$2"
    info "Disabling password-based SSH access on $name..."
    ssh_vm "$ip" "sudo mkdir -p /etc/ssh/sshd_config.d && \
        printf '%s\\n' \
            'PasswordAuthentication no' \
            'KbdInteractiveAuthentication no' \
            'ChallengeResponseAuthentication no' \
            'PermitRootLogin prohibit-password' | \
        sudo tee /etc/ssh/sshd_config.d/00-azfilesauth-hardening.conf > /dev/null && \
        sudo sshd -t && \
        (sudo systemctl reload sshd 2>/dev/null || sudo systemctl reload ssh)"
    ssh_vm "$ip" "sudo sshd -T | grep -q '^passwordauthentication no$' && \
        sudo sshd -T | grep -q '^kbdinteractiveauthentication no$'"
    green "Password-based SSH disabled on $name"
}

ensure_ssh_key

vm_running() {
    az vm get-instance-view --subscription "$SUBSCRIPTION_ID" \
        --resource-group "$RESOURCE_GROUP" --name "$1" \
        --query "instanceView.statuses[?starts_with(code,'PowerState')].displayStatus" \
        -o tsv 2>/dev/null | grep -q "running"
}

# ─── Step 1: Build packages ───────────────────────────────────────────────────
step "Building packages in Docker"

if [ "$SKIP_BUILD" -eq 1 ]; then
    info "Skipping build (--skip-build)"
else
    mkdir -p "$REPO_ROOT/PACKAGES/deb" "$REPO_ROOT/PACKAGES/rpm"

    build_distros=()
    [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "ubuntu" ]] && build_distros+=("ubuntu24")
    [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "rhel9"  ]] && build_distros+=("rhel9")
    [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "sles15" ]] && build_distros+=("sles15")

    pids=()
    for d in "${build_distros[@]}"; do
        info "Building $d..."
        docker build -f "$REPO_ROOT/test/build/${d}.containerfile" \
            -t "azfilesauth-build-${d}" "$REPO_ROOT" > /tmp/build-${d}.log 2>&1 &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid" || red "Docker build failed — check /tmp/build-*.log"; done

    # Extract packages
    if [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "ubuntu" ]]; then
        docker run --rm -v "$REPO_ROOT/PACKAGES:/out" azfilesauth-build-ubuntu24 \
            bash -c "cp /build/PACKAGES/deb/*.deb /out/deb/"
    fi
    if [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "rhel9" ]]; then
        docker run --rm -v "$REPO_ROOT/PACKAGES:/out" azfilesauth-build-rhel9 \
            bash -c "cp /build/PACKAGES/rpm/*.rpm /out/rpm/"
    fi
    if [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "sles15" ]]; then
        docker run --rm -v "$REPO_ROOT/PACKAGES:/out" azfilesauth-build-sles15 \
            bash -c "cp /build/PACKAGES/rpm/*.rpm /out/rpm/"
    fi

    green "Packages built:"
    ls -lh "$REPO_ROOT/PACKAGES/deb/" "$REPO_ROOT/PACKAGES/rpm/" 2>/dev/null | grep -v "^total"
fi

# Verify packages exist for the selected distros
if [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "ubuntu" ]]; then
    [ -f "$UBUNTU_PKG" ] || red "Ubuntu DEB not found: $UBUNTU_PKG (run without --skip-build)"
fi
if [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "rhel9" ]]; then
    [ -f "$RHEL9_PKG"  ] || red "RHEL9 RPM not found: $RHEL9_PKG (run without --skip-build)"
fi
if [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "sles15" ]]; then
    [ -f "$SLES15_PKG" ] || red "SLES15 RPM not found: $SLES15_PKG (run without --skip-build)"
fi

# ─── Step 2: Infrastructure ───────────────────────────────────────────────────
step "Provisioning Azure infrastructure"

if [ "$SKIP_INFRA" -eq 1 ]; then
    info "Skipping infra (--skip-infra)"
    # Still need to resolve the storage account name
    STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-$(az storage account list \
        --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" \
        --query "[0].name" -o tsv 2>/dev/null)}"
    info "Using existing storage account: $STORAGE_ACCOUNT"
else
    # Resource group
    az group create --subscription "$SUBSCRIPTION_ID" \
        --name "$RESOURCE_GROUP" --location "$LOCATION" > /dev/null
    green "Resource group: $RESOURCE_GROUP"

    # Storage account
    if [ -z "$STORAGE_ACCOUNT" ]; then
        STORAGE_ACCOUNT="azfilestest$(shuf -i 10000-99999 -n1)"
    fi
    az storage account create --subscription "$SUBSCRIPTION_ID" \
        -g "$RESOURCE_GROUP" -n "$STORAGE_ACCOUNT" \
        --location "$LOCATION" --sku Standard_LRS --kind StorageV2 > /dev/null
    az storage share create --subscription "$SUBSCRIPTION_ID" \
        --account-name "$STORAGE_ACCOUNT" --name "$FILE_SHARE" --quota 100 > /dev/null
    az storage account update --subscription "$SUBSCRIPTION_ID" \
        -g "$RESOURCE_GROUP" -n "$STORAGE_ACCOUNT" \
        --enable-smb-oauth true > /dev/null
    green "Storage: $STORAGE_ACCOUNT/$FILE_SHARE (SMBOAuth enabled)"

    # Network
    az network vnet create --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" \
        --name azfiles-vnet --address-prefix 10.0.0.0/16 > /dev/null
    az network vnet subnet create --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" \
        --vnet-name azfiles-vnet --name default --address-prefixes 10.0.0.0/24 \
        --default-outbound-access false > /dev/null
    az network nsg create --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" \
        --name azfiles-nsg > /dev/null
    az network nsg rule create --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" \
        --nsg-name azfiles-nsg --name allow-ssh --priority 1000 \
        --protocol Tcp --destination-port-ranges 22 --access Allow > /dev/null
    az network nsg rule create --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" \
        --nsg-name azfiles-nsg --name allow-smb --priority 1001 \
        --protocol Tcp --destination-port-ranges 445 --access Allow > /dev/null
    green "Network: azfiles-vnet / azfiles-nsg"

    # Create VMs
    declare -A VM_MAP  # name → image
    [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "ubuntu" ]] && VM_MAP[$UBUNTU_VM]="$UBUNTU_IMAGE"
    [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "rhel9"  ]] && VM_MAP[$RHEL9_VM]="$RHEL9_IMAGE"
    [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "sles15" ]] && VM_MAP[$SLES15_VM]="$SLES15_IMAGE"

    STORAGE_RESOURCE_ID=$(az storage account show --subscription "$SUBSCRIPTION_ID" \
        -g "$RESOURCE_GROUP" -n "$STORAGE_ACCOUNT" --query "id" -o tsv)

    for vm_name in "${!VM_MAP[@]}"; do
        image="${VM_MAP[$vm_name]}"
        ip_name="${vm_name}-ip"
        nic_name="${vm_name}-nic"

        az network public-ip create --subscription "$SUBSCRIPTION_ID" \
            -g "$RESOURCE_GROUP" --name "$ip_name" \
            --allocation-method Static --sku Standard > /dev/null
        az network nic create --subscription "$SUBSCRIPTION_ID" \
            -g "$RESOURCE_GROUP" --name "$nic_name" \
            --vnet-name azfiles-vnet --subnet default \
            --public-ip-address "$ip_name" \
            --network-security-group azfiles-nsg > /dev/null
        az vm create --subscription "$SUBSCRIPTION_ID" \
            -g "$RESOURCE_GROUP" --name "$vm_name" \
            --nics "$nic_name" --image "$image" --size Standard_B2ms \
            --admin-username "$VM_USER" --ssh-key-values "$SSH_PUBLIC_KEY" \
            --authentication-type ssh \
            --assign-identity '[system]' --no-wait > /dev/null
        green "VM created: $vm_name"
    done

    # Wait for VMs and assign RBAC
    for vm_name in "${!VM_MAP[@]}"; do
        info "Waiting for $vm_name..."
        for i in $(seq 1 30); do
            vm_running "$vm_name" && { green "$vm_name running"; break; }
            echo -n "."; sleep 10
        done

        PRINCIPAL_ID=$(az vm show --subscription "$SUBSCRIPTION_ID" \
            -g "$RESOURCE_GROUP" --name "$vm_name" \
            --query "identity.principalId" -o tsv)
        for role in "Storage Account Contributor" "Storage File Data SMB MI Admin"; do
            az role assignment create --subscription "$SUBSCRIPTION_ID" \
                --role "$role" --assignee-object-id "$PRINCIPAL_ID" \
                --assignee-principal-type ServicePrincipal \
                --scope "$STORAGE_RESOURCE_ID" > /dev/null 2>&1 || true
        done
        green "RBAC assigned for $vm_name"
    done

    info "Waiting 60s for RBAC to propagate..."
    sleep 60
fi

FILE_ENDPOINT="https://${STORAGE_ACCOUNT}.file.core.windows.net"
UNC_PATH="//${STORAGE_ACCOUNT}.file.core.windows.net/${FILE_SHARE}"

# ─── Step 3: Install packages and run tests ───────────────────────────────────

run_tests_on_vm() {
    local vm_name="$1" vm_ip="$2" pkg="$3" install_cmd="$4" krb5_conf="$5"

    step "[$vm_name] Install package and run tests"

    ensure_vm_ssh_key "$vm_name" "$vm_ip"
    wait_for_ssh "$vm_ip" "$vm_name"
    harden_ssh "$vm_ip" "$vm_name"

    # Copy package and test scripts
    ssh_vm "$vm_ip" "mkdir -p ~/AzFilesAuthenticator"
    scp_to_vm "$pkg"              "$vm_ip" "~/"
    scp_to_vm "$REPO_ROOT/src"    "$vm_ip" "~/AzFilesAuthenticator/"
    scp_to_vm "$REPO_ROOT/test"   "$vm_ip" "~/AzFilesAuthenticator/"
    scp_to_vm "$REPO_ROOT/deploy" "$vm_ip" "~/AzFilesAuthenticator/"

    # Install package
    # Note: on Ubuntu, apt-get uses -o DPkg::Lock::Timeout=300 to wait
    # for background auto-upgrades that run at first boot to complete.
    ssh_vm "$vm_ip" "bash -s" << INSTALL
set -e
${install_cmd}
INSTALL
    green "[$vm_name] Package installed"

    # Configure Kerberos FILE cache (required on RHEL and SLES)
    if [ -n "$krb5_conf" ]; then
        ssh_vm "$vm_ip" "sudo tee /etc/krb5.conf.d/00-azfilesauth.conf > /dev/null << 'EOF'
${krb5_conf}
EOF"
    fi

    # Run E2E tests
    ssh_vm "$vm_ip" "
        cd ~/AzFilesAuthenticator
        sudo STORAGE_ACCOUNT=${STORAGE_ACCOUNT} \
             FILE_SHARE=${FILE_SHARE} \
             USER_MI_CLIENT_ID=${USER_MI_CLIENT_ID:-} \
             RUN_MI_LIFECYCLE_TESTS=${RUN_MI_LIFECYCLE_TESTS:-0} \
             bash ~/AzFilesAuthenticator/test/run_e2e_tests.sh
    "
    green "[$vm_name] All tests PASSED"
}

KRB5_FILE_CACHE="[libdefaults]
  default_ccache_name = FILE:/tmp/krb5cc_%{uid}"

# Get IPs for configured VMs
get_ip() {
    az network public-ip show --subscription "$SUBSCRIPTION_ID" \
        -g "$RESOURCE_GROUP" --name "${1}-ip" \
        --query "ipAddress" -o tsv 2>/dev/null
}

# Run in parallel for all three distros
pids=()
results=()

if [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "ubuntu" ]]; then
    UBUNTU_IP=$(get_ip "$UBUNTU_VM")
    info "Ubuntu 24.04 IP: $UBUNTU_IP"
    UBUNTU_DEB=$(basename "$UBUNTU_PKG")
    run_tests_on_vm "$UBUNTU_VM" "$UBUNTU_IP" "$UBUNTU_PKG" \
        "sudo systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
         sudo env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 update -qq
         sudo env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y -qq cifs-utils krb5-user
         sudo env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y -qq ~/${UBUNTU_DEB}" \
        "" &   # Ubuntu uses default ccache; no extra krb5 config needed
    pids+=($!)
    results+=("Ubuntu 24.04")
fi

if [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "rhel9" ]]; then
    RHEL9_IP=$(get_ip "$RHEL9_VM")
    info "RHEL9 IP: $RHEL9_IP"
    run_tests_on_vm "$RHEL9_VM" "$RHEL9_IP" "$RHEL9_PKG" \
        "sudo dnf install -y cifs-utils krb5-workstation 2>&1 | tail -2 && sudo rpm -Uvh --force --nodeps ~/\$(basename $RHEL9_PKG)" \
        "$KRB5_FILE_CACHE" &
    pids+=($!)
    results+=("RHEL 9")
fi

if [[ -z "$DISTRO_FILTER" || "$DISTRO_FILTER" == "sles15" ]]; then
    SLES15_IP=$(get_ip "$SLES15_VM")
    info "SLES15-SP7 IP: $SLES15_IP"
    run_tests_on_vm "$SLES15_VM" "$SLES15_IP" "$SLES15_PKG" \
        "sudo zypper --non-interactive install -y python311 cifs-utils krb5-client 2>&1 | tail -3
         sudo rpm -Uvh --force --nodeps ~/\$(basename $SLES15_PKG)" \
        "$KRB5_FILE_CACHE" &
    pids+=($!)
    results+=("SLES 15 SP7")
fi

# Wait for all parallel test runs
failed=0
for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
        green "${results[$i]}: PASSED"
    else
        warn "${results[$i]}: FAILED"
        failed=$((failed + 1))
    fi
done

# ─── Summary ──────────────────────────────────────────────────────────────────
step "Summary"
echo ""
echo "  Storage Account : $STORAGE_ACCOUNT"
echo "  File Share      : $FILE_SHARE"
for vm_name in "$UBUNTU_VM" "$RHEL9_VM" "$SLES15_VM"; do
    IP=$(get_ip "$vm_name" 2>/dev/null || echo "N/A")
    echo "  $vm_name : $IP"
done
echo ""

if [ "$failed" -eq 0 ]; then
    green "All tests PASSED on all distros"
    exit 0
else
    red "$failed distro(s) FAILED — check output above"
fi
