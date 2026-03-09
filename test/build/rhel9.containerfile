# Build azfilesauth RPM on RHEL 9
FROM registry.access.redhat.com/ubi9/ubi:latest

RUN dnf -y install rpm-build rpmdevtools autoconf libtool make gcc gcc-c++ \
        python3-devel libcurl-devel krb5-devel chrpath git automake \
        binutils glibc-devel kernel-headers && \
    dnf clean all

WORKDIR /build
COPY . /build/

RUN rpmdev-setuptree ~ && \
    tar --exclude=debian -czf ~/rpmbuild/SOURCES/azfilesauth-1.0.tar.gz \
        --transform 's,^\./,azfilesauth-1.0/,' -C /build . && \
    cp rpm.spec ~/rpmbuild/SPECS/ && \
    rpmbuild -ba ~/rpmbuild/SPECS/rpm.spec && \
    mkdir -p /build/PACKAGES/rpm && \
    cp ~/rpmbuild/RPMS/*/azfilesauth*.rpm /build/PACKAGES/rpm/ && \
    rm -f /build/PACKAGES/rpm/*debuginfo* /build/PACKAGES/rpm/*debugsource* && \
    echo "=== Built RPMs ===" && ls -l /build/PACKAGES/rpm/
