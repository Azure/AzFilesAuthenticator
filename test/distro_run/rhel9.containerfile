# Test azfilesauth RPM installation on RHEL 9
FROM registry.access.redhat.com/ubi9/ubi:latest

COPY *.rpm /tmp/

RUN dnf -y install --allowerasing python3 python3-requests curl krb5-libs && \
    rpm -ivh /tmp/azfilesauth-*.x86_64.rpm && \
    dnf clean all

# Validate
RUN echo "=== Package info ===" && rpm -qi azfilesauth && \
    echo "=== Files ===" && rpm -ql azfilesauth && \
    echo "=== Library ===" && ls -l /usr/lib64/libazfilesauth* && \
    echo "=== Binaries ===" && \
    test -x /usr/bin/azfilesauthmanager && echo "azfilesauthmanager OK" && \
    test -x /usr/bin/azfilesrefresh && echo "azfilesrefresh OK" && \
    echo "=== Config ===" && test -f /etc/azfilesauth/config.yaml && echo "config.yaml OK" && \
    echo "=== Service ===" && test -f /etc/systemd/system/azfilesrefresh.service && echo "service OK" && \
    echo "=== Dependencies ===" && rpm -qR azfilesauth && \
    echo "=== Version ===" && azfilesauthmanager --version && \
    echo "=== List credentials ===" && azfilesauthmanager list && \
    echo "=== ALL CHECKS PASSED ==="
