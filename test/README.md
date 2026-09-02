# Test Guide

This directory contains unit, static-analysis, package, lifecycle, and legacy integration tests for AzFilesAuthenticator.

## Execution Summary

| Test surface | Command or caller | Runs by default? | External requirements |
| --- | --- | --- | --- |
| `test_unit.py` | `python3 test/test_unit.py` | Yes in `run_e2e_tests.sh` and package-container tests | Python, mocked native dependencies |
| `test_imports.py` | `python3 test/test_imports.py` | Yes in `run_e2e_tests.sh` | Python |
| `test_mi_lifecycle.py` | `RUN_MI_LIFECYCLE_TESTS=1 ./test/run_e2e_tests.sh` | No; opt-in | Root, installed package, Azure identity, CIFS, Kerberos, Azure resources |
| `tests.py` | `./test/run_e2e_tests.sh` when `test/test_config.yaml` exists | No; conditional legacy path | Root, `requests`, client-secret config, mounted Azure Files share |
| `test_package_builds.sh` | `./test/test_package_builds.sh [distros...]` | No; manual | Docker and supported distro images |
| `test_open_handles.sh` | Called by the disabled stress-test code in `tests.py` | No direct invocation | Mounted share, `sudo`, `dd`, write capacity |
| `test_signing_sort.sh` | No caller | No | Empty file; currently contains no test |
| `list_cred_op` | Fixture/sample JSON | Not a test | None |

`run_e2e_tests.sh` runs static checks and unit tests on every invocation. It marks the lifecycle and legacy suites as passed when they are skipped, so a successful runner exit does not prove those suites executed.

## Unit Tests: `test_unit.py`

Run with:

```bash
python3 test/test_unit.py
# or
python3 -m unittest discover -s test -p 'test_unit.py'
```

The suite imports the Python sources with mocked native-library, Azure SDK, filesystem, subprocess, and logging dependencies.

### YAML configuration and local user initialization

Class: `TestYamlConfig`

- `test_config_round_trip_preserves_nested_mappings`: preserves existing nested configuration while adding `USER_UID`.
- `test_save_config_secures_new_file`: creates a new config with mode `0600` without changing its ownership or mode after creation.
- `test_load_config_treats_empty_document_as_empty_mapping`: treats an empty YAML document as an empty mapping.
- `test_load_config_rejects_falsy_non_mapping_roots`: rejects lists, booleans, and numbers as configuration roots.
- `test_init_new_user_preserves_existing_config`: records the local user UID without discarding existing settings.
- `test_init_new_user_exits_when_config_cannot_be_loaded`: exits without creating a user or writing configuration when the config cannot be loaded.

### Azure Identity environment configuration

Class: `TestAzureIdentityEnvironment`

- `test_reload_restores_inherited_values_and_removes_config_only_values`: removes stale configured values and restores inherited values when keys disappear.
- `test_invalid_reload_does_not_partially_mutate_environment`: rejects an invalid mapping without partially changing the process environment.

### Azure managed-identity token acquisition

Class: `TestGetOauthToken`

- `test_system_assigned_returns_token`: uses `ManagedIdentityCredential()` and returns a system-assigned token.
- `test_user_assigned_passes_client_id`: passes the client ID to the user-assigned credential.
- `test_loads_environment_before_managed_identity_credential`: loads configured Azure Identity environment variables before constructing the credential.
- `test_empty_client_id_uses_system_assigned_identity`: treats an empty client ID as system-assigned authentication.
- `test_missing_access_token_returns_none`: rejects a credential response with no token.
- `test_request_failure_returns_none`: converts credential acquisition failures to `None`.
- `test_missing_sdk_dependency_returns_none`: reports missing `azure-identity`/`azure-core` and returns `None`.

### Workload identity token acquisition

Class: `TestGetWorkloadIdentityToken`

- `test_missing_params_returns_none`: rejects missing tenant ID, client ID, or token-file path.
- `test_successful_token_fetch`: reads the assertion file, constructs `ClientAssertionCredential` with `func`, and requests the public Storage scope.
- `test_loads_environment_before_client_assertion_credential`: loads and uses the configured authority before constructing the credential.
- `test_default_authority_is_public`: verifies the default Microsoft Entra public-cloud authority.
- `test_resource_is_used_as_base_uri`: verifies a trailing slash is normalized and `/.default` is appended exactly once.
- `test_sovereign_authority_and_resource_override`: verifies custom authority and resource values for sovereign/custom clouds.

### Runtime endpoint authentication state

Class: `TestEndpointAuthMetadata`

- `test_metadata_uses_runtime_state_file`: writes and reads endpoint metadata through the runtime JSON state path using an isolated temporary directory.
- `test_metadata_rejects_different_client_id_for_same_endpoint`: raises `AuthMetadataConflict` when a second identity (different `client_id`) tries to claim an endpoint already owned by another identity, and leaves the original owner's metadata untouched.
- `test_metadata_write_takes_exclusive_lock`: proves the state-file `flock` is exclusive by showing a second non-blocking lock attempt fails with `EWOULDBLOCK`/`EAGAIN` while a writer holds it.

### Native-library wrappers

Classes: `TestAzfilesSetOauth`, `TestAzfilesClear`, and `TestAzfilesList`

- `test_set_calls_lib`: passes the endpoint and OAuth token to the native setter.
- `test_set_nonzero_rc_exits`: exits when the native setter returns an error.
- `test_set_persists_metadata_after_successful_lib_call`: confirms auth metadata is only written after the native credential-set call succeeds.
- `test_set_direct_token_persists_token_auth_mode`: confirms a direct OAuth token set (no `--system`/`--imds-client-id`/`--workload-identity`) is persisted with `auth_mode="token"`.
- `test_set_conflict_raised_before_lib_call`: confirms an identity conflict raises `AuthMetadataConflict` and the native setter is never called, so the krb5/keyring store is never touched for a rejected request.
- `test_set_force_bypasses_conflict_and_overwrites_metadata`: confirms `force=True` skips the conflict check, still calls the native setter, and overwrites the endpoint's metadata with the new identity.
- `test_clear_calls_lib`: calls the native credential-clear function.
- `test_clear_nonzero_rc_exits`: exits when credential clearing fails.
- `test_clear_removes_metadata`: confirms a successful clear also removes the endpoint's persisted auth metadata.
- `test_list_plain`: requests plain credential output.
- `test_list_json`: requests JSON credential output.
- `test_list_nonzero_rc_exits`: propagates a nonzero list return code.

### Refresh daemon environment configuration

Class: `TestRefreshEnvironment`

- `test_valid_sleep_overrides_at_or_above_minimum`: accepts refresh sleep intervals of at least five seconds.
- `test_sleep_overrides_below_minimum_use_default`: rejects shorter intervals and retains the packaged default.
- `test_invalid_timing_overrides_log_and_use_defaults`: logs malformed daemon timing overrides and retains the packaged defaults.

### Ticket expiry logic

Class: `TestIsExpiring`

- `test_ticket_far_from_expiry`: does not refresh a ticket with ample lifetime.
- `test_ticket_about_to_expire`: refreshes a ticket inside the configured refresh window.
- `test_ticket_already_expired`: refreshes an expired ticket.
- `test_missing_end_time_forces_refresh`: refreshes when the end time is absent.
- `test_unparsable_end_time_forces_refresh`: refreshes when the end time has no epoch.
- `test_no_end_time_key_forces_refresh`: refreshes when the field is missing entirely.

### Principal and mount parsing

Classes: `TestGetEndpointFromPrincipal` and `TestGetMountOptions`

- `test_cifs_prefix`: extracts an endpoint from a `cifs/` Kerberos principal.
- `test_https_prefix`: extracts an endpoint from an `https://` principal.
- `test_unknown_prefix_returns_empty`: rejects unsupported principal prefixes.
- `test_parses_krb5_mounts`: includes Kerberos CIFS mounts and ignores non-Kerberos mounts.
- `test_root_username_detected`: detects `username=root` for system-assigned identity mounts.
- `test_no_cifs_mounts_returns_empty`: returns no mount mappings when there are no CIFS mounts.

### Daemon refresh dispatch

Class: `TestRefreshTicket`

- `test_refresh_uses_system_mi_for_root_username`: uses system-assigned managed identity for a root mount.
- `test_refresh_uses_user_mi_for_client_id_username`: uses the mount username as the user-assigned client ID.
- `test_refresh_skips_if_metadata_client_id_differs_from_mount_user`: skips refresh (no token fetch, no credential write) when the persisted `client_id` does not match the current mount's username, preventing a stale/foreign identity from being refreshed onto the wrong endpoint.
- `test_refresh_skips_workload_identity_metadata_when_present`: skips refresh entirely for endpoints persisted with workload-identity metadata, since workload-identity refresh is not currently supported.
- `test_refresh_skips_token_auth_mode`: skips refresh entirely for endpoints persisted with `auth_mode="token"`, even when the mount's username would otherwise map to a managed identity, since a direct token has no credential source to refresh from.
- `test_refresh_skips_when_identity_changes_during_token_fetch`: covers the race where an endpoint's identity is reassigned (e.g. via `set --force`) while the daemon's token fetch was in flight; `azfiles_set_oauth` re-validates the stale metadata under its own lock, raises `AuthMetadataConflict`, and `refresh_ticket` catches it as a skip instead of clobbering the new identity's credential.

### Epoch parsing

Class: `TestParseEpoch`

- `test_standard_format`: extracts an epoch from the normal ticket timestamp format.
- `test_no_epoch`: returns zero when no epoch exists.
- `test_empty_string`: returns zero for an empty value.
- `test_none_input`: returns zero for `None`.

### CLI routing

Class: `TestCLIArgParsing`

- `test_no_args_prints_usage_and_exits`: rejects an invocation without a command.
- `test_list_command_calls_lib`: routes `list` to the native list wrapper.
- `test_clear_command_calls_lib`: routes `clear` to the native clear wrapper.
- `test_set_direct_token`: routes a direct OAuth token to the native setter.
- `test_set_direct_token_conflict_exits_before_touching_krb5_cache`: end-to-end CLI check that a direct-token `set` against an endpoint already owned by a different identity exits with code `3`, never calls the native credential setter, and leaves the original owner's metadata intact.
- `test_set_system_mi_conflict_exits_before_touching_krb5_cache`: end-to-end CLI check that `set ... --system` against an endpoint already owned by a different identity exits with code `3`, never calls the native credential setter, and leaves the original owner's metadata intact.
- `test_set_system_mi_force_overwrites_conflicting_metadata`: end-to-end CLI check that `set ... --system --force` against an endpoint already owned by a different identity succeeds, calls the native credential setter, and overwrites the metadata to reflect the new identity.

### Ticket listing and daemon orchestration

Classes: `TestGetTickets` and `TestStartDaemon`

- `test_parses_json_tickets`: parses JSON returned by `azfilesauthmanager list --json`.
- `test_handles_empty_output`: returns an empty list when the list command fails.
- `test_only_expiring_tickets_are_refreshed`: refreshes only the expiring ticket among three tickets.
- `test_no_tickets_means_no_refresh`: performs no refresh for an empty ticket list.
- `test_all_expiring_tickets_refreshed`: refreshes every ticket when all are expiring.
- `test_no_expiring_tickets_skips_refresh`: skips refresh when no ticket is near expiry.

## Static Checks: `test_imports.py`

Run with:

```bash
python3 test/test_imports.py
```

The file contains the following test methods:

- `test_azfilesrefresh_syntax`: parses the autoconf template for the refresh daemon.
- `test_azfilesauthmanager_syntax`: parses the manager source.
- `test_config_syntax`: parses `src/config.py` if that optional file exists; it is skipped by the implementation when absent.
- `test_azfilesrefresh_imports_from_azfilesauth`: verifies every refresh-daemon import exists in the manager module.
- `test_azfilesrefresh_adds_configured_package_path_before_import`: verifies the configured Python package path is added before importing `azfilesauth`.
- `test_azfilesrefresh_no_undefined`: checks for potentially undefined names in the refresh daemon.
- `test_azfilesauthmanager_no_undefined`: checks for potentially undefined names in the manager.
- `test_all_refresh_dependencies_available`: verifies the package export pattern supplies everything imported by the daemon.

These are AST-based checks, not runtime import or Azure connectivity tests.

## Managed-Identity Lifecycle: `test_mi_lifecycle.py`

Run only when the environment is prepared:

```bash
sudo RUN_MI_LIFECYCLE_TESTS=1 ./test/run_e2e_tests.sh
# or directly
sudo python3 test/test_mi_lifecycle.py \
  https://<storage-account>.file.core.windows.net \
  --storage-account <storage-account> \
  --file-share <share>
```

The script always tests system-assigned identity. It also tests user-assigned identity when `USER_MI_CLIENT_ID` or `--user-mi-client-id` is supplied. For each enabled mode, `run_mode` executes four scenarios:

- `scenario_authenticate`: clears credentials, sets the requested identity mode, and verifies CIFS credentials exist.
- `scenario_mount`: mounts the share with Kerberos, writes and reads a probe file, then cleans up.
- `scenario_expiry`: forces the daemon’s expiry check with environment overrides, requires the target ticket’s start epoch to advance, and rejects an end-time regression.
- `scenario_daemon_refresh`: keeps a mount active while the daemon refreshes, requires a newly issued target ticket, and verifies post-refresh I/O.

This suite does not currently exercise workload identity federation. It requires a live Azure environment and root privileges.

## Legacy Integration: `tests.py`

Run only when `test/test_config.yaml` exists:

```bash
sudo python3 test/tests.py run https://<storage-account>.file.core.windows.net
```

`run_e2e_tests.sh` skips this file when the config is absent. The configuration must provide client-secret authentication and mount settings.

Implemented legacy cases:

- `test_basic_mount`: obtains a token, mounts a share, and unmounts it successfully.
- `test_mount_post_cred_expiry_and_renewal`: expects a mount after ticket expiry to fail, renews credentials, and expects the next mount to succeed.
- `test_second_cred_validity_post_initial_expiry`: inserts a second ticket before the first expires and checks the share remains mountable after the first expires.
- `test_heavy_writes_at_ticket_switch`: starts large concurrent writes around ticket rollover.

Current invocation status: `run_azfilesauthtests()` calls the first three cases for normal and multichannel mounts. `test_heavy_writes_at_ticket_switch` is defined but not called; its call is commented out under `PENDING IMPLEMENTATION`.

## Package Validation: `test_package_builds.sh`

Run with Docker:

```bash
./test/test_package_builds.sh
./test/test_package_builds.sh ubuntu22 rhel9
```

For each selected distro (`ubuntu20`, `ubuntu22`, `ubuntu24`, `sles15`, `rhel9`, `rhel10`, `azlinux3`) it:

1. Builds the package using the matching `test/build/*.containerfile`.
2. Extracts and checks that a package artifact exists.
3. Installs it in a clean image using `test/distro_run/*.containerfile`.
4. Requires `/etc/azfilesauth/config.yaml` to have mode `0600` and owner/group `root:root`.
5. Requires `azure.identity`, `azure.core`, and `yaml` to import with the distro’s packaged Python.
6. Runs `azfilesauthmanager --version` and requires nonempty output.
7. Starts `azfilesrefresh` for five seconds and accepts timeout exit 124 or clean exit 0.
8. Mounts `test/` and `src/` read-only into the distro image and runs `test_unit.py` with that distro’s Python.

This is not run by `run_e2e_tests.sh` and is a separate manual/package CI test.

## Shell Helper: `test_open_handles.sh`

Usage:

```bash
./test/test_open_handles.sh <mounted-share-path> <file-descriptor-index>
```

It validates the mount path, writes a 10 GB file using `dd` from `/dev/urandom`, reports timing, and prints `BYE` through an exit trap. It is a workload helper, not an assertion-based test. It is only referenced by the currently disabled heavy-write legacy test.

## Empty or Fixture Files

- `test_signing_sort.sh` is empty. It is checked in but currently performs no checks and has no caller.
- `list_cred_op` contains sample credential-list JSON used as an artifact/example. It is not executed by any runner.

## What Is Actually Run

The default lightweight validation is:

```bash
python3 test/test_imports.py
python3 test/test_unit.py
```

The repository’s `run_e2e_tests.sh` invokes exactly those two suites by default. Managed-identity lifecycle tests are opt-in, legacy integration is config-gated, package tests are separate, and the signing-sort file currently has no implementation.
