#!/usr/bin/bash
set -x

sudo apt-get update
sudo apt-get install -y git autoconf libtool build-essential python3 libcurl4-openssl-dev libkrb5-dev debhelper-compat
sudo dpkg-buildpackage -us -uc

mkdir -p PACKAGES/deb
cp ../azfilesauth_*.deb PACKAGES/deb/
