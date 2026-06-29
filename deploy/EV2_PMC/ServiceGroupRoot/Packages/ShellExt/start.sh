#!/bin/sh
# Ev2 Shell Extension wrapper script
# usage: 'start.sh [rollback]'

set -ex

pwd
ls

echo "1) Install PMC CLI"
python3 -V
pip3 install python_dl/*.whl


echo "2) Test pmc-cli"
command -v pmc
pmc -d -c settings.toml repo list --name "$PMC_REPO_NAME" || exit 1

if [ -f "$(pwd)/settings.toml" ]; then
    mkdir -p ~/.config/pmc
    cp "$(pwd)/settings.toml" ~/.config/pmc/
fi

# echo "1) Installing pmc-cli"
# pip install pmc-cli
# pmc --version

# Move settings.toml into the ~/.config/pmc directory

PMC_BASE_URL="https://pmc-ingest.trafficmanager.net/api/v4"
# For test/debug: 
# PMC="echo pmc --auth-type wif --base-url $PMC_BASE_URL"
# PMC="pmc --auth-type wif --base-url $PMC_BASE_URL"
PMC="pmc"

# $PMC repo list --path-contains "noble"
# $PMC repo list --path-contains "rhel"
# $PMC repo list --path-contains "sles"

check_repo() {
    if ! $PMC repo list --name "$1" | grep -q "$1"; then
        echo "ERROR: repo not found: $1"; exit 1
    fi
    echo "  ok: $1"
}

check_package() {
    if [ ! -e "packages/$1" ]; then
        echo "ERROR: package not found: packages/$1"; exit 1
    fi
    echo "  ok: $1"
}

if [ "$1" = "test" ]; then
    echo "3) Preflight validation (no publish)"

    echo "3a) Verify pmc-cli is installed and reachable"
    command -v pmc || { echo "ERROR: pmc not on PATH"; exit 1; }
    pmc --version || { echo "ERROR: pmc-cli not runnable"; exit 1; }

    echo "3b) Verify package artifacts are present"
    ls -l packages/ || { echo "ERROR: packages/ missing"; exit 1; }
    check_package azfilesauth_1.0-11_amd64.jammy.deb
    check_package azfilesauth_1.0-11_amd64.noble.deb
    check_package azfilesauth_1.0-11_arm64.jammy.deb
    check_package azfilesauth_1.0-11_arm64.noble.deb
    check_package azfilesauth-1.0-11.azl3.x86_64.rpm
    check_package azfilesauth-1.0-11.azl3.aarch64.rpm
    check_package azfilesauth-1.0-11.el9.x86_64.rpm
    check_package azfilesauth-1.0-11.el9.aarch64.rpm
    check_package azfilesauth-1.0-11.el10.x86_64.rpm
    check_package azfilesauth-1.0-11.el10.aarch64.rpm
    check_package azfilesauth-1.0-11.x86_64.rpm
    check_package azfilesauth-1.0-11.aarch64.rpm

    echo "3c) Verify target repos exist"
    check_repo microsoft-ubuntu-jammy-prod-apt
    check_repo microsoft-ubuntu-noble-prod-apt
    check_repo azurelinux-3.0-prod-ms-oss-x86_64-yum
    check_repo azurelinux-3.0-prod-ms-oss-aarch64-yum
    check_repo microsoft-rhel9.0-prod-yum
    check_repo microsoft-rhel10-prod-yum
    check_repo microsoft-sles15-prod-yum

    echo "Preflight validation passed"
    exit 0
fi

publish_package() {
    local pattern="$1"
    local repo_name="$2"
    local release_name="${3:-}"

    local files=( packages/$pattern )

    if [ ! -e ${files[@]} ]; then
        echo "No files matched pattern: $pattern"
        return 1
    fi

    echo "Uploading ${files[*]} to PMC..."
    PKG_ID=$($PMC --id-only package upload "${files[@]}") || {
        echo "Failed to upload ${files[*]}"
            return 1
        }

    if [ -n "$release_name" ]; then
        echo "Adding package(s) $PKG_ID to repo $repo_name (release=$release_name)"
        $PMC repo package update --add-packages "$PKG_ID" "$repo_name" "$release_name"
    else
        echo "Adding package(s) $PKG_ID to repo $repo_name"
        $PMC repo package update --add-packages "$PKG_ID" "$repo_name"
    fi

    echo "Publishing repo $repo_name"
    $PMC repo publish "$repo_name"
}



if [ "$1" = "rollback" ]; then
    echo "3) Remove packages"
    ls -l packages/
    for PKG_FILE in packages/*.deb packages/*.rpm; do
        if [ -f "$PKG_FILE" ]; then
            PKG_NAME=$(basename "$PKG_FILE" | cut -d_ -f1)
            PKG_VERSION=$(basename "$PKG_FILE" | cut -d_ -f2 | cut -d. -f1-3)
            PKG_ID=$(pmc -c settings.toml package $(echo $PKG_FILE | grep -q '.deb' && echo deb || echo rpm) list --name "$PKG_NAME" --version "$PKG_VERSION" --repo "$PMC_REPO_NAME" | jq -r '.results[0].id')
            echo "file '$PKG_FILE', package '$PKG_NAME', version '$PKG_VERSION': queried => PKG_ID=$PKG_ID"
            if [ -n "$PKG_ID" ]; then
                pmc -c settings.toml repo package update --remove-packages "$PKG_ID" "$PMC_REPO_NAME"
            else
                echo "no PKG_ID found for '$PKG_NAME' '$PKG_VERSION' in '$PMC_REPO_NAME'"
                exit 1
            fi
        fi
    done
    echo "4) Repo publish"
    pmc -c settings.toml repo publish "$PMC_REPO_NAME"
else
    FAILURES=""

    NL='
'

    echo "Publish amd deb packages"
    # TODO: focal commented out due to issue with "debconf: unable to initialize frontend: Dialog"
    # publish_package "azfilesauth_1.0-11_amd64.focal.deb" microsoft-ubuntu-focal-prod-apt focal || FAILURES="${FAILURES}${NL}  - azfilesauth_1.0-11_amd64.focal.deb -> microsoft-ubuntu-focal-prod-apt (focal)"
    publish_package "azfilesauth_1.0-11_amd64.jammy.deb" microsoft-ubuntu-jammy-prod-apt jammy || FAILURES="${FAILURES}${NL}  - azfilesauth_1.0-11_amd64.jammy.deb -> microsoft-ubuntu-jammy-prod-apt (jammy)"
    publish_package "azfilesauth_1.0-11_amd64.noble.deb" microsoft-ubuntu-noble-prod-apt noble || FAILURES="${FAILURES}${NL}  - azfilesauth_1.0-11_amd64.noble.deb -> microsoft-ubuntu-noble-prod-apt (noble)"

    echo "Publish arm deb packages"
    # TODO: focal commented out due to issue with "debconf: unable to initialize frontend: Dialog"
    # publish_package "azfilesauth_1.0-11_arm64.focal.deb" microsoft-ubuntu-focal-prod-apt focal || FAILURES="${FAILURES}${NL}  - azfilesauth_1.0-11_arm64.focal.deb -> microsoft-ubuntu-focal-prod-apt (focal)"
    publish_package "azfilesauth_1.0-11_arm64.jammy.deb" microsoft-ubuntu-jammy-prod-apt jammy || FAILURES="${FAILURES}${NL}  - azfilesauth_1.0-11_arm64.jammy.deb -> microsoft-ubuntu-jammy-prod-apt (jammy)"
    publish_package "azfilesauth_1.0-11_arm64.noble.deb" microsoft-ubuntu-noble-prod-apt noble || FAILURES="${FAILURES}${NL}  - azfilesauth_1.0-11_arm64.noble.deb -> microsoft-ubuntu-noble-prod-apt (noble)"

    echo "Publish Az linux 3 packages"
    publish_package "azfilesauth-1.0-11.azl3.x86_64.rpm" azurelinux-3.0-prod-ms-oss-x86_64-yum || FAILURES="${FAILURES}${NL}  - azfilesauth-1.0-11.azl3.x86_64.rpm -> azurelinux-3.0-prod-ms-oss-x86_64-yum"
    publish_package "azfilesauth-1.0-11.azl3.aarch64.rpm" azurelinux-3.0-prod-ms-oss-aarch64-yum || FAILURES="${FAILURES}${NL}  - azfilesauth-1.0-11.azl3.aarch64.rpm -> azurelinux-3.0-prod-ms-oss-aarch64-yum"

    echo "Publish Rhel 9 packages"
    publish_package "azfilesauth-1.0-11.el9.x86_64.rpm" microsoft-rhel9.0-prod-yum || FAILURES="${FAILURES}${NL}  - azfilesauth-1.0-11.el9.x86_64.rpm -> microsoft-rhel9.0-prod-yum"
    publish_package "azfilesauth-1.0-11.el9.aarch64.rpm" microsoft-rhel9.0-prod-yum || FAILURES="${FAILURES}${NL}  - azfilesauth-1.0-11.el9.aarch64.rpm -> microsoft-rhel9.0-prod-yum"

    echo "Publish Rhel 10 packages"
    publish_package "azfilesauth-1.0-11.el10.x86_64.rpm" microsoft-rhel10-prod-yum || FAILURES="${FAILURES}${NL}  - azfilesauth-1.0-11.el10.x86_64.rpm -> microsoft-rhel10-prod-yum"
    publish_package "azfilesauth-1.0-11.el10.aarch64.rpm" microsoft-rhel10-prod-yum || FAILURES="${FAILURES}${NL}  - azfilesauth-1.0-11.el10.aarch64.rpm -> microsoft-rhel10-prod-yum"

    echo "Publish Sles 15 packages"
    publish_package "azfilesauth-1.0-11.x86_64.rpm" microsoft-sles15-prod-yum || FAILURES="${FAILURES}${NL}  - azfilesauth-1.0-11.x86_64.rpm -> microsoft-sles15-prod-yum"
    publish_package "azfilesauth-1.0-11.aarch64.rpm" microsoft-sles15-prod-yum || FAILURES="${FAILURES}${NL}  - azfilesauth-1.0-11.aarch64.rpm -> microsoft-sles15-prod-yum"

    if [ -n "$FAILURES" ]; then
        printf '\n============================================\n'
        printf 'ERROR: The following packages failed to publish:%s\n' "$FAILURES"
        printf '============================================\n'
        exit 1
    fi
fi
