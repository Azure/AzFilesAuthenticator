## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.

# Azure Files Authentication Manager

The Azure Files Authentication Manager is a command-line utility and library designed to manage Azure Files Kerberos authentication credentials on Linux systems. This tool simplifies the process of handling authentication credentials, ensuring secure and efficient access to Azure Files.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Command Line Interface](#command-line-interface)
    - [List Credentials](#list-credentials)
    - [Set Credentials](#set-credentials)
    - [Clear Credentials](#clear-credentials)
    - [Version](#version)
- [Automatic Credential Refresh (azfilesrefresh)](#automatic-credential-refresh-azfilesrefresh)
  - [Features](#features)
  - [Installation & Usage](#installation--usage)
  - [Logs](#logs)
- [Library API Reference](#library-api-reference)
- [Configuration](#configuration)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Packaging](#packaging)
  - [RPM Package](#rpm-package)
  - [.deb package](#deb-package)
- [Building from Source](#building-from-source)
- [Developer Setup](#developer-setup)
- [Testing Package Builds](#testing-package-builds)
- [License](#license)

## Installation

You can install the Azure Files Authentication Manager from Microsoft packages or build it from source.

### Install from Microsoft Packages (Recommended)

The package location and installation steps differ depending on your Linux distro. The following distros are currently supported.

> For the full end-to-end guide (storage account setup, managed identity configuration, mounting, and troubleshooting), see [Access SMB Azure file shares by using managed identities](https://learn.microsoft.com/en-us/azure/storage/files/files-managed-identities?tabs=linux).

### Python Dependencies

`azfilesauthmanager` requires the [Azure Identity SDK for Python](https://learn.microsoft.com/en-us/python/api/overview/azure/identity-readme) (`azure-identity >= 1.14.0`, `azure-core >= 1.26.0`) and PyYAML. When you install via the Microsoft package feed these are satisfied by native packages. When installing from a local `.deb`/`.rpm` build, the post-install script installs the Python dependencies automatically (falling back to `--break-system-packages` on Ubuntu 24.04+ which enforces PEP 668).

### Storage Account Prerequisite

For managed identity authentication to work, the storage account must have the **SMBOAuth** feature enabled:

```bash
az storage account update \
  --resource-group <resource-group> \
  --name <storage-account> \
  --enable-smb-oauth true
```

The managed identity (system or user-assigned) must also have the **Storage File Data SMB MI Admin** role assigned on the storage account.

#### Azure Linux 3.0

```bash
sudo tdnf update -y
sudo tdnf install -y azfilesauth
```

#### Ubuntu 22.04 (Jammy)

```bash
curl -sSL -O https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y azfilesauth
```

#### Ubuntu 24.04 (Noble)

```bash
curl -sSL -O https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y azfilesauth
```

#### RHEL 9.6+ / RHEL 10.1+

```bash
curl -sSL -O https://packages.microsoft.com/config/$(source /etc/os-release && echo "$ID/${VERSION_ID%%.*}")/packages-microsoft-prod.rpm
sudo rpm -i packages-microsoft-prod.rpm
rm packages-microsoft-prod.rpm
sudo dnf update -y
sudo dnf install -y azfilesauth
```

RHEL uses KCM/KEYRING as the default Kerberos credential cache. Switch to a FILE-based cache used by `azfilesauth`:

```bash
sudo tee /etc/krb5.conf.d/00-azfilesauth.conf > /dev/null <<EOF
[libdefaults]
    default_ccache_name = FILE:/tmp/krb5cc_%{uid}
EOF
```

> **Note:** Sometimes RHEL can block kernel upcall access to the credential cache file. If a failure occurs, see `/var/log/messages` for potential causes.

#### SLES 15 SP6+

```bash
curl -sSL -O https://packages.microsoft.com/config/sles/15/packages-microsoft-prod.rpm
sudo rpm -i packages-microsoft-prod.rpm
rm packages-microsoft-prod.rpm
sudo zypper refresh
sudo zypper install -y azfilesauth
```

SLES uses a persistent credential cache by default. Switch to a FILE-based cache used by `azfilesauth`:

```bash
sudo tee /etc/krb5.conf.d/00-azfilesauth.conf > /dev/null <<EOF
[libdefaults]
    default_ccache_name = FILE:/tmp/krb5cc_%{uid}
EOF
```

## Usage

### Command Line Interface

The Azure Files Authentication Manager tool requires root privileges to execute its commands. The following commands are supported:

#### List Credentials

Displays all stored Azure Files authentication credentials

```bash
sudo azfilesauthmanager list
```

This will result in the format:

```bash
Using Kerberos cache: /tmp/krb5cc_1001
Credential 1:
  Server: cifs/mystorageaccount.file.core.windows.net@FILES.AZURE.STORAGE.MICROSOFT.COM
  Client: AzureFileClient@FILES.AZURE.STORAGE.MICROSOFT.COM
  Realm: FILES.AZURE.STORAGE.MICROSOFT.COM
  Ticket flags: 8388608
  Ticket start time: 12/07/25 04:48:32 UTC (epoch: 1765082912)
  Ticket end time:   12/08/25 04:45:27 UTC (epoch: 1765169127)
  Ticket renew till: 12/08/25 04:45:27 UTC (epoch: 1765169127)
```

If a structured output is required, it can be obtained with the --json flag

```bash
sudo azfilesauthmanager list --json
```

This allows third-party scripts to use the credential output. Currently, it is structured as a JSON list as follows:

```json
[
  {
    "server": "cifs/mystorageaccount.file.core.windows.net@FILES.AZURE.STORAGE.MICROSOFT.COM",
    "client": "AzureFileClient@FILES.AZURE.STORAGE.MICROSOFT.COM",
    "realm": "FILES.AZURE.STORAGE.MICROSOFT.COM",
    "ticket_flags": 8388608,
    "ticket_start_time": "12/07/25 04:48:32 UTC (epoch: 1765082912)",
    "ticket_end_time": "12/08/25 04:45:27 UTC (epoch: 1765169127)",
    "ticket_renew_till": "12/08/25 04:45:27 UTC (epoch: 1765169127)"
  }
]
```

#### Set Credentials

Fetches the Kerberos credentials for the specified storage account endpoint and populates the cache specified by the `KRB5_CC_NAME` variable in `/etc/azfilesauth/config.yaml` (or the default cache if not specified).

**1. Using an OAuth token:**

This method is useful when you have already obtained an OAuth token (e.g., via a service principal or user login) and want to use it to authenticate with Azure Files.

```bash
sudo azfilesauthmanager set <file_endpoint_uri> <oauth_token>
```

*Example:*
```bash
sudo azfilesauthmanager set https://mystorageaccount.file.core.windows.net eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...
```

**2. Using System Assigned Managed Identity:**

If your VM has a System Assigned Managed Identity enabled and granted access to the Azure File Share, you can use the `--system` flag. The tool will automatically fetch the token from the Azure Instance Metadata Service (IMDS).

```bash
sudo azfilesauthmanager set <file_endpoint_uri> --system
```

*Example:*
```bash
sudo azfilesauthmanager set https://mystorageaccount.file.core.windows.net --system
```

**3. Using User Assigned Managed Identity:**

If your VM has a User Assigned Managed Identity assigned, you need to provide the Client ID of that identity.

```bash
sudo azfilesauthmanager set <file_endpoint_uri> --imds-client-id <client_id>
```

*Example:*
```bash
sudo azfilesauthmanager set https://mystorageaccount.file.core.windows.net --imds-client-id 00000000-0000-0000-0000-000000000000
```

**4. Using Workload Identity:**

If your workload is running in a Kubernetes environment with Workload Identity Federation configured, you can authenticate using a federated token. You need to provide the Tenant ID, Client ID, and the path to the projected service account token file.

For sovereign clouds, `--authority-host` selects the Microsoft Entra authority and `--resource` selects the Azure Storage resource. Pass `--resource` as the base resource URI, without the `/.default` suffix; the manager adds that suffix when requesting the token. For example, use `https://storage.azure.com/`, not `https://storage.azure.com/.default`. This matches the [Azure Files CSI driver](https://github.com/kubernetes-sigs/azurefile-csi-driver/blob/master/pkg/azurefile/azurefile.go), which supplies the storage resource without `/.default`.

```bash
sudo azfilesauthmanager set <file_endpoint_uri> --workload-identity --tenant-id <tenant_id> --client-id <client_id> --token-file <token_file>
```

*Example:*
```bash
sudo azfilesauthmanager set https://mystorageaccount.file.core.windows.net --workload-identity --tenant-id 00000000-0000-0000-0000-000000000000 --client-id 00000000-0000-0000-0000-000000000000 --token-file /var/run/secrets/azure/tokens/azure-identity-token
```

#### Clear Credentials

Clears the Kerberos credentials for the specified storage account endpoint from the cache specified by the `KRB5_CC_NAME` variable in `/etc/azfilesauth/config.yaml` (or the default cache if not specified).

```bash
sudo azfilesauthmanager clear <file_endpoint_uri>
```

#### Version

Displays the version of the Azure Files Authentication Manager library.

```bash
sudo azfilesauthmanager --version
```

## Automatic Credential Refresh (azfilesrefresh)

The `azfilesrefresh` daemon is a background service that automatically monitors and refreshes your Kerberos tickets before they expire. This ensures uninterrupted access to your Azure File Shares, especially for long-running applications or mounts.

### Features
- **Automatic Monitoring & Refresh:** Checks ticket expiration every minute and proactively refreshes tickets 5 minutes before they expire.
- **Managed Identity Support:** Automatically detects if a mount was created using a Managed Identity (System or User Assigned) and refreshes the token accordingly.
    - **System Assigned Managed Identity:** If the mount was created using the system-assigned identity, the daemon will automatically fetch a new token from IMDS and update the Kerberos ticket.
    - **User Assigned Managed Identity:** If the mount was created using a user-assigned identity (via `--imds-client-id`), the daemon will use the associated Client ID to fetch the correct token and update the ticket.
- **Systemd Integration:** Runs as a standard system service.

### Installation & Usage

The `azfilesrefresh` service is installed automatically with the package.

To let the daemon refresh credentials for an Azure Files mount declared in `/etc/fstab`, add
`x-systemd.requires=azfilesrefresh.service` to its Kerberos CIFS mount options. The `username`
must be `root` for a system-assigned managed identity or the client ID for a user-assigned identity:

```fstab
//mystorageaccount.file.core.windows.net/share /mnt/share cifs sec=krb5,username=root,x-systemd.requires=azfilesrefresh.service 0 0
```

The `x-systemd.requires=azfilesrefresh.service` option also makes the mount order after the service
at boot. Before the daemon starts, an `ExecStartPre` provisioning step (`azfilesrefresh --provision`)
creates the Kerberos ticket for each opted-in `fstab` entry, so the mount has valid credentials
even on a fresh boot where no ticket exists yet. This requires IMDS reachability and that the managed
identity has access to the share.

**Start the service:**
```bash
sudo systemctl start azfilesrefresh
```

**Start and enable the service to persist across reboots:**
```bash
sudo systemctl enable --now azfilesrefresh
```

> **Important:** Without `enable`, the service will not restart after a reboot and your Kerberos tickets will expire, causing mount failures.

**Check the status:**
```bash
sudo systemctl status azfilesrefresh
```

**Stop the service:**
```bash
sudo systemctl stop azfilesrefresh
```

**Disable the service from starting on boot:**
```bash
sudo systemctl disable azfilesrefresh
```

### Logs

The refresh daemon logs its activities to `/var/log/azfilesrefresh.log`. You can check this file to troubleshoot issues or verify that tickets are being refreshed.

`azfilesauthmanager` logs can be found in `/var/log/syslog` (Debian/Ubuntu) or `/var/log/messages` (RHEL/Azure Linux/SLES).

```bash
tail -f /var/log/azfilesrefresh.log
```

## Library API Reference

The shared library `libazfilesauth.so` is installed at `/usr/lib` (or `/usr/lib64`, `/usr/local/lib` depending on the distro) and provides the following main functions:

```c
int extern_smb_set_credential_oauth_token(char* file_endpoint_uri, char* oauth_token, unsigned int* credential_expires_in_seconds);

int extern_smb_clear_credential(char* file_endpoint_uri);

int extern_smb_list_credential(bool is_json);

const char* extern_smb_version();
```

These functions are used by the command-line utility to perform the required operations.

## Configuration

- **Configuration File:** The main configuration file is located at `/etc/azfilesauth/config.yaml`.
- **Log Destination:** By default, `azfilesauth` logs to syslog (`/var/log/syslog` on Debian/Ubuntu, `/var/log/messages` on RHEL/SLES). To redirect logs to a file instead, add the following to `/etc/azfilesauth/config.yaml`:

  ```yaml
  LOG_DESTINATION: file
  LOG_FILE_PATH: /var/log/azfilesauth.log
  ```

### Azure Identity environment variables

To pass environment-specific settings such as `MSI_ENDPOINT` to the Azure Identity SDK, add them directly under `ENVIRONMENT` in `/etc/azfilesauth/config.yaml`:

```yaml
ENVIRONMENT:
  MSI_ENDPOINT: http://localhost:40342/metadata/identity/oauth2/token
  MSI_SECRET: example-secret
  # AZURE_AUTHORITY_HOST: https://login.microsoftonline.com
```

The configuration is parsed with PyYAML's safe loader and is not executed as shell code. Variable names are case-sensitive, and values are converted to strings without shell expansion. Quote values when YAML might otherwise interpret their type, such as `"true"`, `"123"`, or `"null"`.

The mapping is loaded immediately before each `ManagedIdentityCredential` or `ClientAssertionCredential` is created. This includes token renewal by the `azfilesrefresh` daemon, so no service-level environment configuration is required. Values in the mapping override variables inherited by the process, and added or changed values take effect on the next token request. Removing a key from the mapping does not unset it in an already-running refresh daemon; restart the daemon after removing a variable from the configuration.

The daemon runs as root. Restrict the configuration file to root, especially when it contains secrets:

```bash
sudo chown root:root /etc/azfilesauth/config.yaml
sudo chmod 600 /etc/azfilesauth/config.yaml
```

If `ENVIRONMENT` is omitted, Azure Identity uses the daemon's existing environment. If it is not a mapping or contains an invalid entry, token acquisition fails and the error is logged by the caller.

## Security Notes

- All operations performed by the Azure Files Authentication Manager tool require root privileges to ensure secure handling of authentication credentials.

## Troubleshooting

If you encounter issues, you can debug the main library and command-line tool by checking the log files and verifying common configuration issues.

### Log Files

- **Syslog File:** Contains logs for the main library, system messages, and `cifs-utils` (`/var/log/syslog` or `/var/log/messages`).
    ```bash
    sudo cat /var/log/syslog
    # On RHEL/CentOS/Azure Linux:
    # sudo cat /var/log/messages
    ```

- **Kernel/CIFS Logs:** Contains kernel-level logs for CIFS mounts.
    ```bash
    dmesg | grep cifs
    ```

- **Refresh Daemon Log File:** Contains logs for the automatic refresh service.
    ```bash
    sudo tail -f /var/log/azfilesrefresh.log
    ```

### Common Issues & Solutions

#### 1. Mount error(126): Required key not available
This error usually indicates that the kernel cannot find the Kerberos key in the keyring.
*   **Cause:** `cifs-utils` is not installed, `cifs.upcall` is not configured correctly, the Kerberos ticket in the cache has expired, or the ticket is not populated in the cache.
*   **Solution:**
    *   Ensure `cifs-utils` is installed: `sudo apt-get install cifs-utils` (or `dnf install cifs-utils`).
    *   Ensure the path to `cifs.upcall` is correct (`which cifs.upcall`).
    *   Check for expired tickets: `sudo azfilesauthmanager list`.
    *   Use the `set` command to get and populate the Kerberos cache: `sudo azfilesauthmanager set ...`

#### 2. Mount error(13): Permission denied
This indicates authentication failure.
*   **Cause:** The Kerberos ticket might be missing, expired, or invalid for the target storage account. Or the user/identity does not have RBAC permissions on the Azure File Share.
*   **Solution:**
    *   Check if you have a valid ticket: `sudo azfilesauthmanager list`.
    *   Verify the ticket is for the correct storage account.
    *   Ensure the identity (User/System Managed Identity or OAuth token owner) has the **"Storage File Data SMB MI Admin"** role assigned on the Storage Account.
    *   Refresh the credentials: `sudo azfilesauthmanager set <url> ...`

#### 3. Mount error(126) with `cruid`

After authenticating, the mount command must specify `cruid=<UID>` so the kernel knows which user's Kerberos cache to look in. The UID is the `azfilesuser` account created by `azfilesauthmanager`, stored in `/etc/azfilesauth/config.yaml`:

```bash
CRUID=$(sudo awk '/USER_UID/{print $2}' /etc/azfilesauth/config.yaml)
sudo mount -t cifs //<storage>.file.core.windows.net/<share> /mnt/smb \
  -o sec=krb5,cruid=${CRUID},dir_mode=0777,file_mode=0777,serverino,nosharesock
```

#### 4. Managed Identity Issues
*   **Symptom:** `azfilesauthmanager set ... --system` fails.
*   **Solution:**
    *   Ensure the VM has a System Assigned Managed Identity enabled in the Azure Portal.
    *   Ensure the storage account has SMBOAuth enabled: `az storage account update --enable-smb-oauth true`.
    *   Ensure the VM has network access to the IMDS endpoint (`169.254.169.254`).
    *   Check `curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"` to verify IMDS connectivity manually.
    *   Verify `azure-identity` is importable: `python3 -c "import azure.identity; print('OK')"`

## Packaging

### RPM Package

  Building for RPM requires a machine which uses RPM packages (RHEL, Azure Linux, etc.). The following steps were followed for preparing the RPM package:

  #### Install the required packages

  ```bash
  sudo dnf install rpm-build rpmdevtools
  ```

  #### Prepare the directory structure
  We need the `~/rpmbuild` directory to begin the packaging process:

  ```bash
  cd ~
  rpmdev-setuptree
  ```

  This will create the `~/rpmbuild` directory with a specific file structure, containing subdirectories `BUILD,RPMS,SOURCES,SPECS,SRPMS` or similar.

  #### Set the source code
  > todo change the repo link here and in package setups

  Clone this repository with
  
  ```bash
  git clone https://github.com/Azure/AzFilesAuthenticator
  ```

  Now we need to create a tarball of the source, with the root of the tarball the same name as the package name. In this example, the package name is assumed to be `azfilesauth-1.0`. The git command to directly add the source from the github repo to the RPM build tree is as follows:

  ```bash
  git archive --format=tar --prefix=azfilesauth-1.0/ HEAD -- . ':!debian' | gzip > ~/rpmbuild/SOURCES/azfilesauth-1.0.tar.gz
  ```

  #### Configure the build pipeline
  We are now ready to setup the build specification. To do the same, create and open a file in the `SPEC` folder, and populate with the given config. In this case, since the package is `azfilesauth`, the spec file is called `azfilesauth.spec`.
  
  >**NOTE**: It is important to have your project configured to be built with automake tools, i.e. `autoreconf -i`, `sudo make`, `sudo make install`. 

  ```text
  Name:           azfilesauth
  Version:        1.0
  Release:        1%{?dist}
  Summary:        Azure Files Authentication Library
  License:        MIT
  URL:            https://example.com
  Source0:        %{name}-%{version}.tar.gz
  BuildRequires:  gcc-c++, make, automake, autoconf, libtool, curl-devel, krb5-devel, python3, glibc-devel, binutils, kernel-headers, chrpath, systemd-rpm-macros
  Requires:       curl, krb5-libs, python3, python3-pip

  %description
  Azure Files Authentication Library provides a C++ library with a Python script to manage authentication.

  %global _hardened_build 1  # Enable security hardening

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
  %{_libdir}/libazfilesauth.so*
  %{_libdir}/libazfilesauth.la
  %{_bindir}/azfilesauthmanager
  %config(noreplace) /etc/azfilesauth/config.yaml

  %post
  %systemd_post azfilesrefresh.service
  # Install Azure Python SDK via pip (azure-identity not available in standard repos)
  python3 -c "import azure.identity" 2>/dev/null || \
      python3 -m pip install --quiet "azure-identity>=1.14.0" "azure-core>=1.26.0" 2>/dev/null || \
      python3 -m pip install --quiet --break-system-packages "azure-identity>=1.14.0" "azure-core>=1.26.0" || \
      echo "WARNING: azure-identity could not be installed."

  %preun
  %systemd_preun azfilesrefresh.service

  %postun
  %systemd_postun_with_restart azfilesrefresh.service

  %changelog
  * Thu Feb 20 2025 Ritvik Budhiraja <rbudhiraja@microsoft.com> - 1.0-1
  - Initial RPM release
  ```

  #### Trigger the build
  We are ready to build:
  ```bash
  rpmbuild -ba ~/rpmbuild/SPECS/azfilesauth.spec
  ```
  You can find your freshly baked RPM package at `~/rpmbuild/RPMS/x86_64/`. Woohoo!

  #### Install the packages

  ```bash
  sudo rpm -ivh ~/rpmbuild/RPMS/x86_64/azfilesauth-1.0-1.azl3.x86_64.rpm
  ```

  **NOTE: We need to build cifs-utils from source (until latest version is accepted by distros) and populate /etc/request-key.d/cifs.spnego.conf file to ensure mount succeeds.**

  Make cifs-utils from source:

  ```bash
  git clone https://github.com/smfrench/smb3-utils
  cd ./smb3-utils/
  git fetch
  git checkout for-next
  sudo dnf install autoconf
  sudo dnf install gcc-c++ git fakeroot make automake ncurses-devel xz libssl-devel bc flex elfutils-libelf-devel bison
  sudo dnf install krb5-devel keyutils-libs-devel libtalloc-devel krb5-workstation libcurl-devel pam-devel samba-winbind-clients libcap-devel
  autoreconf -i
  ./configure
  sudo make
  sudo make install
  ```

### .deb package

  The required setup is already present in the `.debian` directory. From the root of the repo, run the following:
  ```bash
  sudo dpkg-buildpackage -us -uc
  ```
  The `.deb` package will be then packaged and be located one directory above the current directory.
  

## Building from Source

To build and install the library from source, follow these steps:

1. **Install Required Packages:**

    Update your package list and install the necessary packages by running the following commands:

    **Debian/Ubuntu:**
    ```bash
    sudo apt-get update
    sudo apt-get install autoconf libtool build-essential python3 libcurl4-openssl-dev libkrb5-dev libyaml-dev
    ```

    **RHEL/Azure Linux:**
    ```bash
    sudo dnf install gcc-c++ make automake autoconf libtool curl-devel krb5-devel libyaml-devel python3
    ```

2. **Build and Install the Library:**

    Generate the configuration scripts, configure the build, compile the source code, and install the library using the following commands:

    ```bash
    autoreconf -i
    ./configure
    make
    sudo make install
    ```

3. **Configure the Tool:**

    Before using the tool, you need to populate the configuration file with the `KRB5_CC_NAME` variable, which specifies the credential cache location. Edit the configuration file using:

    ```bash
    sudo vim /etc/azfilesauth/config.yaml
    ```

    Set the `KRB5_CC_NAME` variable to your desired credential cache location. For example:

    ```yaml
    KRB5_CC_NAME: /tmp/krb5cc_123
    ```

    If the `KRB5_CC_NAME` variable is not specified, the tool will default to `/tmp/krb5cc_<uid>`, where `<uid>` is the user ID of the `azfilesuser` (or the user specified in `USER_UID`).

    If the configuration file does not exist, the library will create it for you. If the credential cache file already exists with a different default client principal, you will need to use a different file. Any issues will be logged in `/var/log/syslog` (or `/var/log/messages` on RHEL/CentOS/Azure Linux), and you can take appropriate action based on the logged errors.

4. **Verify Prerequisites:**

    The following files must be configured correctly before using the library:

    1. Check if the `DEFAULT_REALM` variable is set and uncommented in `/etc/krb5.conf`. If not, uncomment it with your preferred editor (requires sudo).
    2. Check if the file `/etc/request-key.d/cifs.spnego.conf` exists. If not, create it and populate it with the following:

    ```bash
    create  cifs.spnego    * * /usr/sbin/cifs.upcall %k
    ```

    Note that the location `/usr/sbin/cifs.upcall` is the standard install location for cifs.upcall. If the location is different for you, you may point to the correct path or copy the cifs.upcall binary to the required folder. If cifs.upcall is not installed, you may install `cifs-utils` with your package manager, or build it from source. The guide for building it from source is the standard automake process:

    ```bash
    git clone https://github.com/smfrench/smb3-utils
    cd ./smb3-utils
    autoreconf -i
    sudo make
    sudo make install
    sudo cp ./cifs.upcall /usr/sbin/cifs.upcall
    ```

## License

This project is licensed under the MIT License. For more details, see the LICENSE file included with the project.

## Developer Setup

After cloning the repository, run the following to enable the shared git hooks (auto-increments the EV2 `version.txt` build number on each commit):

```bash
git config core.hooksPath hooks
```

## Testing Package Builds

A Docker-based test framework is provided to locally build and validate packages across all supported distros. This mirrors the CI pipeline defined in `.github/azfilesauth-build.yaml`.

### Supported Distros

| Distro | Package Type |
|---|---|
| Ubuntu 22.04 (Jammy) | DEB |
| Ubuntu 24.04 (Noble) | DEB |
| SLES 15 SP6 | RPM |
| RHEL 9 | RPM |
| Azure Linux 3 | RPM |

### Usage

**Test all distros:**

```bash
./test/test_package_builds.sh
```

**Test specific distros:**

```bash
./test/test_package_builds.sh sles15
./test/test_package_builds.sh ubuntu22 rhel9
```

### What It Does

For each distro, the script:

1. **Builds** the package inside a Docker container (using Dockerfiles in `test/build/`)
2. **Extracts** the built `.deb` or `.rpm` to `test/artifacts/<distro>/`
3. **Installs** the package on a clean distro image (using Dockerfiles in `test/distro_run/`)
4. **Validates** installed files, libraries, binaries, config, and systemd service
5. **Runs** `azfilesauthmanager --version` and verifies the output

### Prerequisites

- Docker must be installed and running
- The user must have permission to run Docker commands
