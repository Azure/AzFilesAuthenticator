# Changelog

User-visible changes are maintained here, newest release first. Package versions
use `major.minor-release`. Released entries generate the native RPM and Debian
changelogs; Unreleased entries are not included in package metadata.

This follows a Keep a Changelog-style layout: dated releases, grouped changes,
and an Unreleased section. Versions are package versions, not Semantic Versioning.

Historical notes are reconstructed from commits reachable from this branch.
Each section summarizes changes since the preceding recorded version boundary,
including changes in the version-setting commit. Dates are those commits' author
dates, not independently verified package-publication dates.

Early version metadata was inconsistent: Debian advanced to 1.0-2, then reset
to 1.0-1 in [e41fa48](https://github.com/Azure/AzFilesAuthenticator/commit/e41fa48).
The 1.0-6 boundary changed only the source version to 1.0.6; RPM and Debian still
declared 1.0-1. No version-setting commits for 1.0-3, 1.0-4, or 1.0-5 were found
in the available version-file history, so entries for them are not invented.
Unmerged branch-specific versions are not included.

Historical version boundaries:

| Version | Version-setting commit | Evidence |
| --- | --- | --- |
| 1.0-13 | [75e66a6](https://github.com/Azure/AzFilesAuthenticator/commit/75e66a6) | RPM, Debian, and source version |
| 1.0-12 | [bf01a18](https://github.com/Azure/AzFilesAuthenticator/commit/bf01a18) | RPM, Debian, and source version |
| 1.0-11 | [4286c6e](https://github.com/Azure/AzFilesAuthenticator/commit/4286c6e) | RPM, Debian, and source version |
| 1.0-10 | [505eaa0](https://github.com/Azure/AzFilesAuthenticator/commit/505eaa0) | RPM, Debian, and source version |
| 1.0-9 | [cb397ca](https://github.com/Azure/AzFilesAuthenticator/commit/cb397ca) | RPM, Debian, and source version |
| 1.0-8 | [3b4bcfc](https://github.com/Azure/AzFilesAuthenticator/commit/3b4bcfc) | RPM, Debian, and source version |
| 1.0-7 | [92a2820](https://github.com/Azure/AzFilesAuthenticator/commit/92a2820) | RPM and Debian version; source synchronized in [7d38d59](https://github.com/Azure/AzFilesAuthenticator/commit/7d38d59) |
| 1.0-6 | [543c8fc](https://github.com/Azure/AzFilesAuthenticator/commit/543c8fc) | Source version only; not a verified package release |
| 1.0-2 | [4ae53e2](https://github.com/Azure/AzFilesAuthenticator/commit/4ae53e2) | Debian version only |
| 1.0-1 | [e45a3d5](https://github.com/Azure/AzFilesAuthenticator/commit/e45a3d5) | Initial source and Debian package |

## [Unreleased]

## [1.0-13] - 2026-11-12

### Security

- Validate Kerberos FILE credential cache ownership, permissions, and file type before use.
- Create missing credential cache files exclusively with mode 0600.

### Changed

- Update package signing to ESRP signing v6.

## [1.0-12] - 2026-09-08

### Added

- Support Azure Identity SDK environment settings through the YAML ENVIRONMENT mapping.
- Add managed-identity lifecycle tests and configurable refresh timing for test scenarios.

### Changed

- Use the Azure Identity SDK for managed identity and workload identity token acquisition.
- Parse configuration as YAML in both the native library and Python manager, preserving existing settings when updating USER_UID.
- Require Python 3.8 or newer and use Python 3.11 for SLES packages.
- Add Azure Identity, Azure Core, and PyYAML dependencies, with package post-install fallback installation.
- Migrate build and publishing pipelines to governed OneBranch templates and an Azure Linux 3.0 publishing environment.

### Security

- Install configuration files with root-only mode 0600.

### Fixed

- Initialize native cleanup pointers and Python local variables before error paths use them.
- Correct RPM Python installation paths and align installed scripts with the selected interpreter.

## [1.0-11] - 2026-06-25

### Added

- Support sovereign-cloud authority hosts and custom Azure Storage resources for workload identity.
- Add Ubuntu 20.04 package-test infrastructure and Ubuntu 24.04 build-pipeline coverage.

### Changed

- Temporarily disable Ubuntu 20.04 builds in the package pipeline.

## [1.0-10] - 2026-03-13

### Added

- Add RHEL 10 package build and installation tests.
- Add Python unit and import tests and a pre-push test hook.
- Add shared pre-commit support for incrementing deployment build numbers.

### Fixed

- Emit an empty JSON array when credential listing produces no JSON output.
- Import user initialization in the refresh daemon and exclude trailing parentheses from parsed mount usernames.
- Prevent stale package artifacts from leaking into container-build outputs.
- Collect package-publishing failures and report them rather than suppressing errors.

## [1.0-9] - 2026-02-25

### Added

- Add RHEL 10 package-signing key support.
- Add container-based package build and installation tests for Azure Linux, RHEL, SLES, and Ubuntu.

### Fixed

- Initialize the authentication user when starting the refresh daemon.
- Support the wheel group when the sudo group is unavailable on RPM-based distributions.
- Handle the version command without creating or updating the authentication user.
- Sign each package once with its matching key and restore a flat artifact layout after signing.
- Declare systemd RPM macro build dependencies and distribution-specific Kerberos and Python Requests dependencies.

## [1.0-8] - 2025-12-18

### Added

- Support system-assigned managed identity authentication in the CLI and refresh daemon.
- Support workload identity authentication using a federated token file.
- Add EV2-based package publishing and expand package build and signing automation.

### Fixed

- Parse service expiration timestamps, including fractional seconds, to return credential lifetime through the native API.
- Release the libcurl handle after a successful Kerberos ticket request.
- Include the generated version header in RPM packages and distribution names in Debian artifact filenames.

## [1.0-7] - 2025-09-15

### Added

- Support configurable file logging as an alternative to syslog.
- Add a version-update script to synchronize package and source version files.

## [1.0-6] - 2025-09-09

### Notes

- Historical source-version checkpoint only: configure.ac set 1.0.6 while RPM and Debian package versions remained 1.0-1.

### Added

- Add the automatic credential-refresh daemon and its systemd service.
- Add configurable HTTP connection and request timeouts.
- Report ticket start, end, and renewal times in local time and epoch form, with consistent JSON output.
- Add native and CLI version reporting and generate the installed version header.
- Add RPM packaging, package-build scripts, and build and release pipelines.

### Changed

- Consolidate public headers under the lowercase azfilesauth.h and install the generated version header.

### Fixed

- Extract the credential-cache realm when clearing service tickets instead of relying on the default Kerberos realm.
- Restore the effective user ID after Kerberos operations.
- Correct daemon user handling, Python imports, and Debian Python Requests dependencies.
- Restrict mount-option discovery to Kerberos-authenticated mounts.
- Suppress the HTTP Expect header and explicitly set an empty POST body size.

## [1.0-2] - 2025-05-08

### Fixed

- Request managed identity tokens for the Azure Storage resource rather than the individual file endpoint.
- Clear an existing credential for the same storage account before inserting its replacement.
- Correct credential-list output and update the documented output and test fixtures.

## [1.0-1] - 2025-03-17

### Added

- Introduce the native Azure Files authentication library and Python command-line manager.
- Support listing, setting, and clearing Kerberos credentials, including JSON credential listings.
- Add OAuth-token and user-assigned managed identity authentication.
- Add Autotools builds, Debian packaging, and initial integration tests.
