Name:           azfilesauth
Version:        1.0
Release:        11%{?dist}
Summary:        Azure Files Authentication Library
License:        MIT
Source0:        %{name}-%{version}.tar.gz
URL:            https://example.com
BuildRequires:  gcc-c++, make, automake, autoconf, libtool, curl-devel, krb5-devel, python3, glibc-devel, binutils, kernel-headers, chrpath, systemd-rpm-macros

%if 0%{?suse_version}
Requires:       curl, krb5, python3, python3-pip
%else
Requires:       curl, krb5-libs, python3, python3-pip
%endif

%description
Azure Files Authentication Library provides a C++ library with a Python script to manage authentication.

%global _hardened_build 1  # Enable security hardening
%global python3_sitelib %(%{__python3} -c "import sysconfig; print(sysconfig.get_paths()['stdlib'])")

%prep
%setup -q

%build
# Run autotools-based build
autoreconf -i
%configure --prefix=%{_prefix} --libdir=%{_libdir}
make

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install

# Ensure the config directory is created
mkdir -p %{buildroot}/etc/azfilesauth
install -m 644 config/config.yaml %{buildroot}/etc/azfilesauth/config.yaml

# Ensure the license directory exists and install LICENSE
mkdir -p %{buildroot}%{_licensedir}/%{name}
install -m 644 LICENSE %{buildroot}%{_licensedir}/%{name}/

# -- Remove RPATH (Only if the library exists) --
if [ -f "%{buildroot}%{_libdir}/libazfilesauth.so.0.0.0" ]; then
    chrpath --delete %{buildroot}%{_libdir}/libazfilesauth.so.0.0.0
fi

%files
%license %{_licensedir}/%{name}/LICENSE
%doc README.md
%{_libdir}/libazfilesauth.*
%{_bindir}/azfilesauthmanager
%{_bindir}/azfilesrefresh
%{_includedir}/azfilesauth.h
%{_includedir}/azfilesauthversion.h
%{python3_sitelib}/azfilesauth/
/etc/systemd/system/azfilesrefresh.service
%config(noreplace) /etc/azfilesauth/config.yaml

%post
%systemd_post azfilesrefresh.service
# Fallback: install Azure Python SDK via pip (set AZFILESAUTH_SKIP_PIP_INSTALL=1 to skip)
if [ "${AZFILESAUTH_SKIP_PIP_INSTALL:-0}" -ne 1 ]; then
    python3 -c "import azure.identity" 2>/dev/null || \
        PIP_DISABLE_PIP_VERSION_CHECK=1 python3 -m pip install --quiet --no-input --no-cache-dir --retries 2 --timeout 15 "azure-identity>=1.14.0" "azure-core>=1.26.0" 2>/dev/null || \
        PIP_DISABLE_PIP_VERSION_CHECK=1 python3 -m pip install --quiet --no-input --no-cache-dir --retries 2 --timeout 15 --break-system-packages "azure-identity>=1.14.0" "azure-core>=1.26.0" || \
        echo "WARNING: azure-identity could not be installed. Add packages.microsoft.com repo or run: pip3 install azure-identity azure-core"
else
    echo "INFO: Skipping azure-identity pip fallback because AZFILESAUTH_SKIP_PIP_INSTALL=1"
fi

%preun
%systemd_preun azfilesrefresh.service

%postun
%systemd_postun_with_restart azfilesrefresh.service

%changelog
* Thu Feb 20 2025 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-1
- Initial RPM release
