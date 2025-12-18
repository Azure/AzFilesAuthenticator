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
- [License](#license)

## Installation

You can install the Azure Files Authentication Manager from Microsoft packages or build it from source.

### Install from Microsoft Packages (Recommended)

**Azure Linux 3.0:**

```bash
sudo tdnf update
sudo tdnf install azfilesauth
```

**Ubuntu 22.04 (Jammy):**

```bash
curl -sSL -O https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install azfilesauth
```

**Ubuntu 24.04 (Noble):**

```bash
curl -sSL -O https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install azfilesauth
```

### Build from Source

To build and install the library from source, follow these steps:

1. **Install Required Packages:**

    Update your package list and install the necessary packages by running the following commands:

    ```bash
    sudo apt-get update
    sudo apt-get install autoconf libtool build-essential python3 libcurl4-openssl-dev libkrb5-dev
    ```

    > todo: check for /etc/krb5.conf for default_realm uncommented
    
    > todo: check for /etc/request-key.d/cifs.spnego.conf

2. **Build and Install the Library:**

    Generate the configuration scripts, configure the build, compile the source code, and install the library using the following commands:

    ```bash
    autoconf -i
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

    > Todo: proper naming instructions with cruid significance

    Additionally, we require that the following files are configured correctly before using the library:

    1. Check if the `DEFAULT_REALM` variable is set, and uncommented, in `/etc/krb5.conf`. If not, uncomment it with your preferred editor (requires sudo).
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

#### Clear Credentials

Clears the Kerberos credentials for the specified storage account endpoint from the cache specified by the `KRB5_CC_NAME` variable in `/etc/azfilesauth/config.yaml` (or the default cache if not specified).

```bash
sudo azfilesauthmanager clear <file_endpoint_uri>
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

**Start the service:**
```bash
sudo systemctl start azfilesrefresh
```

**Enable the service to start on boot:**
```bash
sudo systemctl enable azfilesrefresh
```

**Check the status:**
```bash
sudo systemctl status azfilesrefresh
```

**Stop the service:**
```bash
sudo systemctl stop azfilesrefresh
```

### Logs

The refresh daemon logs its activities to `/var/log/azfilesrefresh.log`. You can check this file to troubleshoot issues or verify that tickets are being refreshed.

```bash
tail -f /var/log/azfilesrefresh.log
```

## Library API Reference

The shared library `libazfilesauth.so` is installed at `/usr/local/lib` and provides the following main functions:

```c
int extern_smb_set_credential_oauth_token(char* file_endpoint_uri, char* oauth_token, unsigned int* credential_expires_in_seconds);

int extern_smb_clear_credential(char* file_endpoint_uri);

void extern_smb_list_credential(void);
```

These functions are used by the command-line utility to perform the required operations.

## Configuration

- **Configuration File:** The main configuration file is located at `/etc/azfilesauth/config.yaml`.
- **Log Files:** Log files are located at `/var/log/syslog` (or `/var/log/messages`).

> todo: revise log files

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
    *   Ensure the identity (User/System Managed Identity or OAuth token owner) has the **"Storage File Data SMB MI Admin"** (or Reader/Elevated Contributor) role assigned on the Storage Account.
    *   Refresh the credentials: `sudo azfilesauthmanager set <url> ...`

#### 3. Managed Identity Issues
*   **Symptom:** `azfilesauthmanager set ... --system` fails.
*   **Solution:**
    *   Ensure the VM has a System Assigned Managed Identity enabled in the Azure Portal.
    *   Ensure the VM has network access to the IMDS endpoint (`169.254.169.254`).
    *   Check `curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"` to verify IMDS connectivity manually.

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
  BuildRequires:  gcc-c++, make, automake, autoconf, libtool, curl-devel, krb5-devel, python3, glibc-devel, binutils, kernel-headers, chrpath
  Requires:       curl, krb5-libs, python3

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
  %{_libdir}/libazfilesauth.la
  %{_bindir}/azfilesauthmanager
  %config(noreplace) /etc/azfilesauth/config.yaml

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
  

## License

This project is licensed under the MIT License. For more details, see the LICENSE file included with the project.
