#!/usr/bin/bash
set -x

RELEASENAME="$1"

sudo apt-get update
sudo apt-get install -y git autoconf libtool build-essential python3 libcurl4-openssl-dev libkrb5-dev debhelper-compat
sudo dpkg-buildpackage -us -uc

mkdir -p PACKAGES/deb


for deb in ../azfilesauth_*.deb; do
    if [ -n "$RELEASENAME" ]; then
        # Insert release name before .deb
        base=$(basename "$deb" .deb)
        newname="${base}.${RELEASENAME}.deb"
        cp "$deb" "PACKAGES/deb/$newname"
    else
        cp "$deb" PACKAGES/deb/
    fi
done
