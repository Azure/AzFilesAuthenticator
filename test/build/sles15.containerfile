# Build azfilesauth RPM on SLES 15 SP6
FROM registry.suse.com/bci/bci-base:15.6

RUN zypper --non-interactive refresh && \
    zypper --non-interactive install \
        rpm-build autoconf libtool make gcc gcc-c++ \
        python3-devel python3 libcurl-devel krb5-devel chrpath git automake \
        binutils glibc-devel kernel-default-devel tar gzip && \
    zypper --non-interactive clean --all || true

WORKDIR /build
COPY . /build/

RUN TOPDIR=/usr/src/packages && \
    mkdir -p $TOPDIR/{BUILD,RPMS,SOURCES,SPECS,SRPMS} && \
    tar --exclude=debian -czf $TOPDIR/SOURCES/azfilesauth-1.0.tar.gz \
        --transform 's,^\./,azfilesauth-1.0/,' -C /build . && \
    cp rpm.spec $TOPDIR/SPECS/ && \
    rpmbuild -ba $TOPDIR/SPECS/rpm.spec && \
    mkdir -p /build/PACKAGES/rpm && \
    cp $TOPDIR/RPMS/*/azfilesauth*.rpm /build/PACKAGES/rpm/ && \
    rm -f /build/PACKAGES/rpm/*debuginfo* /build/PACKAGES/rpm/*debugsource* && \
    echo "=== Built RPMs ===" && ls -l /build/PACKAGES/rpm/
