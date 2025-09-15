#!/bin/bash
set -x

sudo dnf -y install rpm-build rpmdevtools autoconf libtool make gcc gcc-c++ python3-devel libcurl-devel krb5-devel chrpath git automake
sudo dnf clean all

rpmdev-setuptree ~
# TODO: change the version number here 
git archive --format=tar --prefix=azfilesauth-1.0/ HEAD -- . ':!debian' | gzip > ~/rpmbuild/SOURCES/azfilesauth-1.0.tar.gz
cp rpm.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/rpm.spec

mkdir -p PACKAGES/rpm
cp ~/rpmbuild/RPMS/x86_64/azfilesauth*.rpm PACKAGES/rpm/
