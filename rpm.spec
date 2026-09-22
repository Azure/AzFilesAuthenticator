Name:           azfilesauth
Version:        1.0
Release:        11%{?dist}
Summary:        Azure Files Authentication Library
License:        MIT
Source0:        %{name}-%{version}.tar.gz
URL:            https://example.com
BuildRequires:  gcc-c++, make, automake, autoconf, libtool, curl-devel, krb5-devel, libyaml-devel, glibc-devel, binutils, kernel-headers, chrpath, systemd-rpm-macros

%if 0%{?suse_version}
BuildRequires:  python311, python311-devel
Requires:       curl, krb5, python311
%else
BuildRequires:  python3 >= 3.8
%if 0%{?azl}
Requires:       curl, krb5-libs, python3 >= 3.8
%else
Requires:       curl, krb5-libs, python3 >= 3.8
%endif
%endif

%description
Azure Files Authentication Library provides a C++ library with a Python script to manage authentication.

%global _hardened_build 1  # Enable security hardening
%global debug_package %{nil}
# The entrypoint shebang intentionally targets the package-owned interpreter.
# Do not turn its temporary buildroot path into an RPM dependency.
%global __requires_exclude ^(python\(abi\).*|/.*BUILDROOT.*/opt/azfilesauth/venv/bin/python|/opt/azfilesauth/venv/bin/python3)$
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
sed -i "1c#!/opt/azfilesauth/venv/bin/python" %{buildroot}%{_bindir}/azfilesauthmanager %{buildroot}%{_bindir}/azfilesrefresh

# Ensure the config directory is created
mkdir -p %{buildroot}/etc/azfilesauth
install -m 600 config/config.yaml %{buildroot}/etc/azfilesauth/config.yaml

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
%dir /opt/azfilesauth
%dir /opt/azfilesauth/venv
/opt/azfilesauth/venv/**
%{_includedir}/azfilesauth.h
%{_includedir}/azfilesauthversion.h
%{python3_sitelib}/azfilesauth/
/etc/systemd/system/azfilesrefresh.service
%attr(0600,root,root) %config(noreplace) /etc/azfilesauth/config.yaml

%post
%systemd_post azfilesrefresh.service
chown root:root /etc/azfilesauth
chmod 0755 /etc/azfilesauth

if ! /opt/azfilesauth/venv/bin/python -c "import azure.identity, azure.core, yaml" 2>/dev/null; then
    echo "ERROR: azfilesauth Python dependencies are not available in the packaged virtual environment." >&2
    exit 1
fi

%preun
%systemd_preun azfilesrefresh.service

%postun
%systemd_postun_with_restart azfilesrefresh.service

%changelog
* Thu Feb 20 2025 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-1
- Initial RPM release
