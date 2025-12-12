#!/bin/bash
set -xeuo pipefail

if command -v tdnf >/dev/null 2>&1; then
    echo "Azure Linux (tdnf found)"
    PKG=tdnf
elif command -v dnf >/dev/null 2>&1; then
    echo "Other RPM distro (dnf found)"
    PKG=dnf
elif command -v yum >/dev/null 2>&1; then
    PKG=yum
else
    echo "No supported package manager found (tdnf/dnf/yum)"
    exit 1
fi

sudo $PKG -y install rpm-build rpmdevtools autoconf libtool make gcc gcc-c++ python3-devel libcurl-devel krb5-devel chrpath git automake binutils glibc-devel kernel-headers
sudo $PKG clean all || true

rpmdev-setuptree ~
# TODO: change the version number here 
git archive --format=tar --prefix=azfilesauth-1.0/ HEAD -- . ':!debian' | gzip > ~/rpmbuild/SOURCES/azfilesauth-1.0.tar.gz
cp rpm.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/rpm.spec

mkdir -p PACKAGES/rpm
cp ~/rpmbuild/RPMS/*/azfilesauth*.rpm PACKAGES/rpm/
