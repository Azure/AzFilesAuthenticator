Name:           azfilesauth
Version:        1.0
Release:        1%{?dist}
Summary:        Azure Files Authentication Library
License:        MIT
Source0:        %{name}-%{version}.tar.gz
URL:            https://example.com
BuildRequires:  gcc-c++, make, automake, autoconf, libtool, curl-devel, krb5-devel, python3, glibc-devel, binutils, kernel-headers, chrpath
Requires:       curl, krb5-libs, python3

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
%{_libdir}/libazfilesauth.so*
%{_bindir}/azfilesauthmanager
%{_bindir}/azfilesrefresh
%{python3_sitelib}/azfilesauth/
%{python3_sitelib}/azfilesauth/__init__.py
%{python3_sitelib}/azfilesauth/azfilesauthmanager.py
%{python3_sitelib}/azfilesauth/azfiles_get_token.py
/etc/systemd/system/azfilesrefresh.service
%config(noreplace) /etc/azfilesauth/config.yaml

%post
%systemd_post azfilesrefresh.service

%preun
%systemd_preun azfilesrefresh.service

%postun
%systemd_postun_with_restart azfilesrefresh.serviceuy

%changelog
* Thu Feb 20 2025 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-1
- Initial RPM release
