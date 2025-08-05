#!/bin/bash
set -x

# Check if the system is Debian/apt-based
if [ -x "$(command -v apt-get)" ] || [ -f /etc/debian_version ]; then
    # Debian/Ubuntu system
    sudo apt-get install rpm -y
else
    # Assuming it's an RPM-based system (Fedora, CentOS, RHEL, etc.)
    sudo dnf -y install rpm-build rpmdevtools autoconf libtool make gcc gcc-c++ python3-devel libcurl-devel krb5-devel chrpath git
    dnf clean all
fi

rpmdev-setuptree ~
# TODO: change the version number here 
git archive --format=tar --prefix=azfilesauth-1.0/ HEAD -- . ':!debian' | gzip > ~/rpmbuild/SOURCES/azfilesauth-1.0.tar.gz
cp rpm.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/rpm.spec

cp ~/rpmbuild/RPMS/x86_64/azfilesauth*.rpm PACKAGES/rpm/
