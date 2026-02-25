# Test azfilesauth RPM installation on Azure Linux 3
FROM mcr.microsoft.com/azurelinux/base/core:3.0

COPY *.rpm /tmp/

RUN tdnf -y install python3 python3-requests curl krb5-libs shadow-utils && \
    rpm -ivh /tmp/azfilesauth-*.x86_64.rpm && \
    tdnf clean all

# Validate
RUN echo "=== Package info ===" && rpm -qi azfilesauth && \
    echo "=== Files ===" && rpm -ql azfilesauth && \
    echo "=== Library ===" && ls -l /usr/lib/libazfilesauth* /usr/lib64/libazfilesauth* 2>/dev/null || true && \
    echo "=== Binaries ===" && \
    test -x /usr/bin/azfilesauthmanager && echo "azfilesauthmanager OK" && \
    test -x /usr/bin/azfilesrefresh && echo "azfilesrefresh OK" && \
    echo "=== Config ===" && test -f /etc/azfilesauth/config.yaml && echo "config.yaml OK" && \
    echo "=== Service ===" && test -f /etc/systemd/system/azfilesrefresh.service && echo "service OK" && \
    echo "=== Dependencies ===" && rpm -qR azfilesauth && \
    echo "=== Version ===" && azfilesauthmanager --version && \
    echo "=== List credentials ===" && azfilesauthmanager list && \
    echo "=== ALL CHECKS PASSED ==="
