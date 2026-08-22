Name:           azfilesauth
Version:        1.0
Release:        11%{?dist}
Summary:        Azure Files Authentication Library
License:        MIT
Source0:        %{name}-%{version}.tar.gz
URL:            https://example.com
BuildRequires:  gcc-c++, make, automake, autoconf, libtool, curl-devel, krb5-devel, glibc-devel, binutils, kernel-headers, chrpath, systemd-rpm-macros

%if 0%{?suse_version}
BuildRequires:  python311, python311-devel
Requires:       curl, krb5, python311, python311-pip
%else
BuildRequires:  python3 >= 3.8
Requires:       curl, krb5-libs, python3 >= 3.8, python3-pip
%endif

%description
Azure Files Authentication Library provides a C++ library with a Python script to manage authentication.

%global _hardened_build 1  # Enable security hardening
%prep
%setup -q

%build
# Run autotools-based build
autoreconf -i
PYTHON=%{__python3} %configure --prefix=%{_prefix} --libdir=%{_libdir}
make

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install

# Ensure both installed scripts use the interpreter selected for this package.
sed -i "1c#!%{__python3}" %{buildroot}%{_bindir}/azfilesauthmanager %{buildroot}%{_bindir}/azfilesrefresh

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
    if ! %{__python3} -c "import azure.identity" 2>/dev/null; then
        if ! PIP_DISABLE_PIP_VERSION_CHECK=1 %{__python3} -m pip install --quiet --no-input --no-cache-dir --retries 2 --timeout 15 "azure-identity>=1.14.0" "azure-core>=1.26.0" 2>/dev/null; then
            if ! PIP_DISABLE_PIP_VERSION_CHECK=1 %{__python3} -m pip install --quiet --no-input --no-cache-dir --retries 2 --timeout 15 --break-system-packages "azure-identity>=1.14.0" "azure-core>=1.26.0"; then
                echo "ERROR: azfilesauth requires azure-identity and azure-core, but installation failed. Add packages.microsoft.com repo or install them manually: pip3 install azure-identity azure-core" >&2
                exit 1
            fi
        fi
    fi
else
    echo "INFO: Skipping azure-identity pip fallback because AZFILESAUTH_SKIP_PIP_INSTALL=1"
    if ! %{__python3} -c "import azure.identity" 2>/dev/null; then
        echo "ERROR: azfilesauth requires azure-identity/azure-core to function. Install them manually or remove AZFILESAUTH_SKIP_PIP_INSTALL." >&2
        exit 1
    fi
fi

%preun
%systemd_preun azfilesrefresh.service

%postun
%systemd_postun_with_restart azfilesrefresh.service

%changelog
* Thu Feb 20 2025 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-1
- Initial RPM release
