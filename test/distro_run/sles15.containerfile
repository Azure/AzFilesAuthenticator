# Test azfilesauth RPM installation on SLES 15 SP6
FROM registry.suse.com/bci/bci-base:15.6

COPY *.rpm /tmp/

RUN zypper --non-interactive refresh && \
    zypper --non-interactive --no-gpg-checks install -y cifs-utils keyutils libcurl4 libyaml-0-2 python311 && \
    rpm -Uvh --nodeps /tmp/azfilesauth-*.rpm

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
