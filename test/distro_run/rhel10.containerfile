# Test azfilesauth RPM installation on RHEL 10
FROM registry.access.redhat.com/ubi10/ubi:latest

COPY *.rpm /tmp/

# cifs-utils/keyutils aren't published in the free UBI repos (only in the
# real entitled RHEL BaseOS channel), so pull them from the freely-accessible,
# ABI-compatible CentOS Stream 10 BaseOS mirror instead of requiring registration.
RUN printf '[cs10-baseos]\nname=CentOS Stream 10 BaseOS\nbaseurl=https://mirror.stream.centos.org/10-stream/BaseOS/x86_64/os/\ngpgcheck=0\nenabled=1\n' \
        > /etc/yum.repos.d/centos-stream-baseos.repo && \
    dnf -y install cifs-utils keyutils && \
    dnf -y install --allowerasing /tmp/azfilesauth-*.x86_64.rpm && \
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
