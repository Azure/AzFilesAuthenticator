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
$PMC repo list --path-contains "noble"

publish_package() {
    local pattern="$1"
    local repo_name="$2"
    local release_name="${3:-}"

    local files=( packages/$pattern )

    if [ ! -e ${files[@]} ]; then
        echo "No files matched pattern: $pattern"
        exit 1
    fi

    echo "Uploading ${files[*]} to PMC..."
    PKG_ID=$($PMC --id-only package upload "${files[@]}") || {
        echo "Failed to upload ${files[*]}"
            exit 1
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
    echo "Publish amd deb packages"
    # publish_package "azfilesauth*_amd64.focal.deb" microsoft-ubuntu-focal-prod-apt focal
    # publish_package "azfilesauth*_amd64.jammy.deb" microsoft-ubuntu-jammy-prod-apt jammy
    # publish_package "azfilesauth*_amd64.noble.deb" microsoft-ubuntu-noble-prod-apt noble

    # echo "Publish arm deb packages"
    # publish_package "azfilesauth*_arm64.jammy.deb" microsoft-ubuntu-jammy-prod-apt jammy
    # publish_package "azfilesauth*_arm64.noble.deb" microsoft-ubuntu-noble-prod-apt noble

    # publish_package "azfilesauth*.azl3.x86_64.rpm" azurelinux-3.0-prod-ms-oss-x86_64-yum
    # publish_package "azfilesauth*.azl3.aarch64.rpm" azurelinux-3.0-prod-ms-oss-aarch64-yum
fi
