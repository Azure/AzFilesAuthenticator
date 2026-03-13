# Build azfilesauth DEB on Ubuntu 20.04 (focal)
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository -y "deb http://archive.ubuntu.com/ubuntu focal-backports main" && \
    apt-get update && \
    apt-get install -y git autoconf libtool build-essential python3 \
        libcurl4-openssl-dev libkrb5-dev && \
    apt-get install -y -t focal-backports debhelper && \
    apt-get clean

WORKDIR /build
COPY . /build/

# autoreconf needed so dpkg-buildpackage clean step works
RUN autoreconf -fi && \
    rm -f ../azfilesauth_*.deb && \
    dpkg-buildpackage -us -uc && \
    rm -rf /build/PACKAGES && \
    mkdir -p /build/PACKAGES/deb && \
    for deb in ../azfilesauth_*.deb; do \
        base=$(basename "$deb" .deb); \
        cp "$deb" "/build/PACKAGES/deb/${base}.focal.deb"; \
    done && \
    echo "=== Built DEBs ===" && ls -l /build/PACKAGES/deb/
