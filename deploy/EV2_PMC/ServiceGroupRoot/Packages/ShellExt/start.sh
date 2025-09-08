#!/bin/sh
# Ev2 Shell Extension wrapper script
# usage: 'start.sh [rollback]'

set -e

echo "1) Install PMC CLI"
python3 -V
pip3 install python_dl/*.whl
python3 -m pip debug --verbose

echo "2) Test pmc-cli"
which pmc
pmc -d -c settings.toml repo list --name "$PMC_REPO_NAME" || exit 1

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
    echo "3) Upload packages"
    ls -l packages/
    ID_LIST=""
    for PKG_FILE in packages/*.deb packages/*.rpm; do
        if [ -f "$PKG_FILE" ]; then
            PKG_ID=$(pmc -c settings.toml --id-only package upload "$PKG_FILE")
            echo "file '$PKG_FILE' uploaded => PKG_ID=$PKG_ID"
            if [ -z "$ID_LIST" ]; then
                ID_LIST=$PKG_ID
            else
                ID_LIST="$ID_LIST,$PKG_ID"
            fi
        fi
    done
    echo "4) Add packages to repo and publish"
    if [ -n "$ID_LIST" ]; then
        echo "adding packages '$ID_LIST' to repo '$PMC_REPO_NAME' dist '$PMC_REPO_DIST'"
        pmc -c settings.toml repo package update --add-packages "$ID_LIST" "$PMC_REPO_NAME" "$PMC_REPO_DIST"
        echo "repo publish"
        pmc -c settings.toml repo publish "$PMC_REPO_NAME"
    else
        echo "no packages added to the repo"
        exit 1
    fi
fi
