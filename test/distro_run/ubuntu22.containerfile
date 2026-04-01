# Test azfilesauth DEB installation on Ubuntu 22.04
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

COPY *.deb /tmp/

RUN apt-get update && \
    apt-get install -y python3 python3-requests libcurl4 libkrb5-3 && \
    dpkg -i /tmp/azfilesauth_*.deb || apt-get install -f -y && \
    apt-get clean

# Validate
RUN echo "=== Package info ===" && dpkg -s azfilesauth && \
    echo "=== Files ===" && dpkg -L azfilesauth && \
    echo "=== Library ===" && ls -l /usr/lib/libazfilesauth* /usr/lib/*/libazfilesauth* 2>/dev/null || true && \
    echo "=== Binaries ===" && \
    test -x /usr/bin/azfilesauthmanager && echo "azfilesauthmanager OK" && \
    test -x /usr/bin/azfilesrefresh && echo "azfilesrefresh OK" && \
    echo "=== Config ===" && test -f /etc/azfilesauth/config.yaml && echo "config.yaml OK" && \
    echo "=== Service ===" && test -f /etc/systemd/system/azfilesrefresh.service && echo "service OK" && \
    echo "=== Version ===" && azfilesauthmanager --version && \
    echo "=== List credentials ===" && azfilesauthmanager list && \
    echo "=== ALL CHECKS PASSED ==="
