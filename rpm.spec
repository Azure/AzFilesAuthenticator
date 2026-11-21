Name:           azfilesauth
Version:        1.0
Release:        13%{?dist}
Summary:        Azure Files Authentication Library
License:        MIT
Source0:        %{name}-%{version}.tar.gz
URL:            https://example.com
BuildRequires:  gcc-c++, make, automake, autoconf, libtool, curl-devel, krb5-devel, libyaml-devel, glibc-devel, binutils, kernel-headers, chrpath, systemd-rpm-macros

%if 0%{?suse_version}
BuildRequires:  python311, python311-devel
Requires:       curl, krb5, python311, python311-pip, python311-PyYAML
%else
BuildRequires:  python3 >= 3.8
%if 0%{?azl}
Requires:       curl, krb5-libs, python3 >= 3.8, python3-pip, PyYAML
%else
Requires:       curl, krb5-libs, python3 >= 3.8, python3-pip, python3-pyyaml
%endif
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
%doc README.md CHANGELOG.md
%{_libdir}/libazfilesauth.*
%{_bindir}/azfilesauthmanager
%{_bindir}/azfilesrefresh
%{_includedir}/azfilesauth.h
%{_includedir}/azfilesauthversion.h
%{python3_sitelib}/azfilesauth/
/etc/systemd/system/azfilesrefresh.service
%attr(0600,root,root) %config(noreplace) /etc/azfilesauth/config.yaml

%post
%systemd_post azfilesrefresh.service
chown root:root /etc/azfilesauth
chmod 0755 /etc/azfilesauth
# Fallback: install Azure Python SDK via pip (set AZFILESAUTH_SKIP_PIP_INSTALL=1 to skip)
if [ "${AZFILESAUTH_SKIP_PIP_INSTALL:-0}" -ne 1 ]; then
    if ! %{__python3} -c "import azure.identity, yaml" 2>/dev/null; then
        if ! PIP_DISABLE_PIP_VERSION_CHECK=1 %{__python3} -m pip install --quiet --no-input --no-cache-dir --retries 2 --timeout 15 "azure-identity>=1.14.0" "azure-core>=1.26.0" "PyYAML>=5.4" 2>/dev/null; then
            if ! PIP_DISABLE_PIP_VERSION_CHECK=1 %{__python3} -m pip install --quiet --no-input --no-cache-dir --retries 2 --timeout 15 --break-system-packages "azure-identity>=1.14.0" "azure-core>=1.26.0" "PyYAML>=5.4"; then
                echo "ERROR: azfilesauth Python dependency installation failed. Install them manually: pip3 install azure-identity azure-core PyYAML" >&2
                exit 1
            fi
        fi
    fi
else
    echo "INFO: Skipping azure-identity pip fallback because AZFILESAUTH_SKIP_PIP_INSTALL=1"
    if ! %{__python3} -c "import azure.identity, yaml" 2>/dev/null; then
        echo "ERROR: azfilesauth requires azure-identity, azure-core, and PyYAML to function. Install them manually or remove AZFILESAUTH_SKIP_PIP_INSTALL." >&2
        exit 1
    fi
fi
if ! %{__python3} -c "import azure.identity, azure.core, yaml" 2>/dev/null; then
    echo "ERROR: azfilesauth Python dependencies are not importable after installation. Required: azure-identity, azure-core, and PyYAML." >&2
    exit 1
fi

%preun
%systemd_preun azfilesrefresh.service

%postun
%systemd_postun_with_restart azfilesrefresh.service

%changelog
* Thu Nov 12 2026 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-13
- Security: Validate Kerberos FILE credential cache ownership, permissions, and file type before use.
- Security: Create missing credential cache files exclusively with mode 0600.
- Changed: Update package signing to ESRP signing v6.

* Tue Sep 08 2026 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-12
- Added: Support Azure Identity SDK environment settings through the YAML ENVIRONMENT mapping.
- Added: Add managed-identity lifecycle tests and configurable refresh timing for test scenarios.
- Changed: Use the Azure Identity SDK for managed identity and workload identity token acquisition.
- Changed: Parse configuration as YAML in both the native library and Python manager, preserving existing settings when updating USER_UID.
- Changed: Require Python 3.8 or newer and use Python 3.11 for SLES packages.
- Changed: Add Azure Identity, Azure Core, and PyYAML dependencies, with package post-install fallback installation.
- Changed: Migrate build and publishing pipelines to governed OneBranch templates and an Azure Linux 3.0 publishing environment.
- Security: Install configuration files with root-only mode 0600.
- Fixed: Initialize native cleanup pointers and Python local variables before error paths use them.
- Fixed: Correct RPM Python installation paths and align installed scripts with the selected interpreter.

* Thu Jun 25 2026 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-11
- Added: Support sovereign-cloud authority hosts and custom Azure Storage resources for workload identity.
- Added: Add Ubuntu 20.04 package-test infrastructure and Ubuntu 24.04 build-pipeline coverage.
- Changed: Temporarily disable Ubuntu 20.04 builds in the package pipeline.

* Fri Mar 13 2026 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-10
- Added: Add RHEL 10 package build and installation tests.
- Added: Add Python unit and import tests and a pre-push test hook.
- Added: Add shared pre-commit support for incrementing deployment build numbers.
- Fixed: Emit an empty JSON array when credential listing produces no JSON output.
- Fixed: Import user initialization in the refresh daemon and exclude trailing parentheses from parsed mount usernames.
- Fixed: Prevent stale package artifacts from leaking into container-build outputs.
- Fixed: Collect package-publishing failures and report them rather than suppressing errors.

* Wed Feb 25 2026 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-9
- Added: Add RHEL 10 package-signing key support.
- Added: Add container-based package build and installation tests for Azure Linux, RHEL, SLES, and Ubuntu.
- Fixed: Initialize the authentication user when starting the refresh daemon.
- Fixed: Support the wheel group when the sudo group is unavailable on RPM-based distributions.
- Fixed: Handle the version command without creating or updating the authentication user.
- Fixed: Sign each package once with its matching key and restore a flat artifact layout after signing.
- Fixed: Declare systemd RPM macro build dependencies and distribution-specific Kerberos and Python Requests dependencies.

* Thu Dec 18 2025 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-8
- Added: Support system-assigned managed identity authentication in the CLI and refresh daemon.
- Added: Support workload identity authentication using a federated token file.
- Added: Add EV2-based package publishing and expand package build and signing automation.
- Fixed: Parse service expiration timestamps, including fractional seconds, to return credential lifetime through the native API.
- Fixed: Release the libcurl handle after a successful Kerberos ticket request.
- Fixed: Include the generated version header in RPM packages and distribution names in Debian artifact filenames.

* Mon Sep 15 2025 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-7
- Added: Support configurable file logging as an alternative to syslog.
- Added: Add a version-update script to synchronize package and source version files.

* Tue Sep 09 2025 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-6
- Notes: Historical source-version checkpoint only: configure.ac set 1.0.6 while RPM and Debian package versions remained 1.0-1.
- Added: Add the automatic credential-refresh daemon and its systemd service.
- Added: Add configurable HTTP connection and request timeouts.
- Added: Report ticket start, end, and renewal times in local time and epoch form, with consistent JSON output.
- Added: Add native and CLI version reporting and generate the installed version header.
- Added: Add RPM packaging, package-build scripts, and build and release pipelines.
- Changed: Consolidate public headers under the lowercase azfilesauth.h and install the generated version header.
- Fixed: Extract the credential-cache realm when clearing service tickets instead of relying on the default Kerberos realm.
- Fixed: Restore the effective user ID after Kerberos operations.
- Fixed: Correct daemon user handling, Python imports, and Debian Python Requests dependencies.
- Fixed: Restrict mount-option discovery to Kerberos-authenticated mounts.
- Fixed: Suppress the HTTP Expect header and explicitly set an empty POST body size.

* Thu May 08 2025 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-2
- Fixed: Request managed identity tokens for the Azure Storage resource rather than the individual file endpoint.
- Fixed: Clear an existing credential for the same storage account before inserting its replacement.
- Fixed: Correct credential-list output and update the documented output and test fixtures.

* Mon Mar 17 2025 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-1
- Added: Introduce the native Azure Files authentication library and Python command-line manager.
- Added: Support listing, setting, and clearing Kerberos credentials, including JSON credential listings.
- Added: Add OAuth-token and user-assigned managed identity authentication.
- Added: Add Autotools builds, Debian packaging, and initial integration tests.
