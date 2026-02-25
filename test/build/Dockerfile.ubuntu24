# Build azfilesauth DEB on Ubuntu 24.04 (noble)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y git autoconf libtool build-essential python3 \
        libcurl4-openssl-dev libkrb5-dev debhelper-compat && \
    apt-get clean

WORKDIR /build
COPY . /build/

# autoreconf needed so dpkg-buildpackage clean step works
RUN autoreconf -fi && \
    rm -f ../azfilesauth_*.deb && \
    dpkg-buildpackage -us -uc && \
    mkdir -p /build/PACKAGES/deb && \
    for deb in ../azfilesauth_*.deb; do \
        base=$(basename "$deb" .deb); \
        cp "$deb" "/build/PACKAGES/deb/${base}.noble.deb"; \
    done && \
    echo "=== Built DEBs ===" && ls -l /build/PACKAGES/deb/
