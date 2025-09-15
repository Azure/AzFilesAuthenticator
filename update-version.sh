#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <major.minor> <release>"
    echo "Example: $0 1.0 2"
    exit 1
fi

NEW_VERSION="$1"   # e.g. 1.0
NEW_RELEASE="$2"   # e.g. 2
DEB_VERSION="${NEW_VERSION}-${NEW_RELEASE}"

# --- Update debian/changelog ---
if [[ -f debian/changelog ]]; then
    sed -i "1s|(.*)|(${DEB_VERSION})|" debian/changelog
    echo "Updated debian/changelog → ${DEB_VERSION}"
fi

# --- Update rpm.spec ---
if [[ -f rpm.spec ]]; then
    sed -i "s/^Version:.*/Version:        ${NEW_VERSION}/" rpm.spec
    sed -i "s/^Release:.*/Release:        ${NEW_RELEASE}%{?dist}/" rpm.spec
    echo "Updated rpm.spec → Version=${NEW_VERSION}, Release=${NEW_RELEASE}"
fi

# --- Update configure.ac ---
if [[ -f configure.ac ]]; then
    sed -i "s/AC_INIT(\[azfilesauth\],\[.*\],/AC_INIT([azfilesauth],[${NEW_VERSION}],/" configure.ac
    echo "Updated configure.ac → ${NEW_VERSION}"
fi

# --- Update package-rpm.sh ---
if [[ -f package-rpm.sh ]]; then
    sed -i -E "s/azfilesauth-[0-9]+\.[0-9]+/azfilesauth-${NEW_VERSION}/g" package-rpm.sh
    echo "Updated package-rpm.sh → ${NEW_VERSION}"
fi

echo "✅ All files updated successfully."
