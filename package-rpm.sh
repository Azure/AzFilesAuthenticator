#!/bin/bash
set -x

setup_rpmbuild_tree() {
    local topdir="${HOME}/rpmbuild"
    local dirs=("BUILD" "RPMS" "SOURCES" "SPECS" "SRPMS")

    echo "Creating RPM build tree in: $topdir"

    for dir in "${dirs[@]}"; do
        mkdir -p "${topdir}/${dir}"
    done

    echo "%_topdir ${topdir}" > "${HOME}/.rpmmacros"
    echo "RPM build tree created successfully."
    echo "~/.rpmmacros file set with %_topdir ${topdir}"
}

# Check if the system is Debian/apt-based
if [ -x "$(command -v apt-get)" ] || [ -f /etc/debian_version ]; then
    # Debian/Ubuntu system
    sudo apt-get update
    sudo apt-get install rpm -y
    sudo apt-get install -y git autoconf libtool build-essential python3 libcurl4-openssl-dev libkrb5-dev debhelper-compat
    setup_rpmbuild_tree
else
    # Assuming it's an RPM-based system (Fedora, CentOS, RHEL, etc.)
    sudo dnf -y install rpm-build rpmdevtools autoconf libtool make gcc gcc-c++ python3-devel libcurl-devel krb5-devel chrpath git
    dnf clean all
    rpmdev-setuptree ~
fi


# TODO: change the version number here 
git archive --format=tar --prefix=azfilesauth-1.0/ HEAD -- . ':!debian' | gzip > ~/rpmbuild/SOURCES/azfilesauth-1.0.tar.gz
cp rpm.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/rpm.spec

mkdir -p PACKAGES/rpm
cp ~/rpmbuild/RPMS/x86_64/azfilesauth*.rpm PACKAGES/rpm/
