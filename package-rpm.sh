#!/bin/bash
set -xeuo pipefail

if command -v tdnf >/dev/null 2>&1; then
    echo "Azure Linux (tdnf found)"
    PKG=tdnf

elif command -v dnf >/dev/null 2>&1; then
    echo "Other RPM distro (dnf found)"
    PKG=dnf

elif command -v yum >/dev/null 2>&1; then
    echo "RHEL/CentOS (yum found)"
    PKG=yum

elif command -v zypper >/dev/null 2>&1; then
    echo "SUSE / SLES (zypper found)"
    PKG=zypper
else
    echo "No supported package manager found (tdnf/dnf/yum/zypper)"
    exit 1
fi

# Package install block with SUSE-specific packages
if [ "$PKG" = "zypper" ]; then
    # echo 'repo_gpgcheck = off' | sudo tee -a /etc/zypp/zypp.conf
    sudo zypper addrepo -G https://download.opensuse.org/repositories/devel:tools/15.7/devel:tools.repo
    sudo zypper --non-interactive refresh
    sudo zypper --non-interactive install \
        rpm-build rpmdevtools autoconf libtool make gcc gcc-c++ \
        python3-devel libcurl-devel krb5-devel chrpath git automake \
        binutils glibc-devel kernel-default-devel

    sudo zypper --non-interactive clean --all || true

else
    sudo $PKG -y install rpm-build rpmdevtools autoconf libtool make gcc gcc-c++ python3-devel \
        libcurl-devel krb5-devel chrpath git automake binutils glibc-devel kernel-headers
    sudo $PKG clean all || true
fi

rpmdev-setuptree ~
# TODO: change the version number here 
git archive --format=tar --prefix=azfilesauth-1.0/ HEAD -- . ':!debian' | gzip > ~/rpmbuild/SOURCES/azfilesauth-1.0.tar.gz
cp rpm.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/rpm.spec

mkdir -p PACKAGES/rpm
cp ~/rpmbuild/RPMS/*/azfilesauth*.rpm PACKAGES/rpm/

