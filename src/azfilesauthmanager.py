#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import ctypes
import pwd
import json
import fcntl
import contextlib
try:
    import yaml
    YAML_IMPORT_ERROR = None
except ImportError as e:
    yaml = None
    YAML_IMPORT_ERROR = e

try:
    from azure.identity import ManagedIdentityCredential, ClientAssertionCredential
    from azure.core.exceptions import ClientAuthenticationError
    AZURE_IDENTITY_IMPORT_ERROR = None
except ImportError as e:
    ManagedIdentityCredential = None
    ClientAssertionCredential = None
    ClientAuthenticationError = Exception
    AZURE_IDENTITY_IMPORT_ERROR = e


CONFIG_FILE_PATH = "/etc/azfilesauth/config.yaml"
AUTH_STATE_DIR = "/run/azfilesauth"
AUTH_STATE_FILE_PATH = f"{AUTH_STATE_DIR}/endpoint-auth-state.json"

USAGE_MESSAGE = """Usage:
    azfilesauthmanager list [--json]
    azfilesauthmanager set <file_endpoint_uri> <oauth_token> [--force]
    azfilesauthmanager set <file_endpoint_uri> --system [--force]
    azfilesauthmanager set <file_endpoint_uri> --imds-client-id <client_id> [--force]
    azfilesauthmanager set <file_endpoint_uri> --workload-identity --tenant-id <tenant_id> --client-id <client_id> --token-file <token_file> [--authority-host <authority_host>] [--resource <resource>] [--force]
    azfilesauthmanager clear <file_endpoint_uri>
    azfilesauthmanager --version
"""

library_paths = [
    '/usr/lib/libazfilesauth.so',
    '/usr/lib64/libazfilesauth.so',
    '/usr/local/lib/libazfilesauth.so'
]

found_path = False
for path in library_paths:
    if os.path.exists(path):
        lib = ctypes.CDLL(path)
        found_path = True 
        break

if not found_path:
    print("Library libazfilesauth.so not found in /usr/local/lib or /usr/lib")
    sys.exit(1)

# Define the function signatures
lib.extern_smb_set_credential_oauth_token.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
lib.extern_smb_set_credential_oauth_token.restype = ctypes.c_int

lib.extern_smb_clear_credential.argtypes = [ctypes.c_char_p]
lib.extern_smb_clear_credential.restype = ctypes.c_int
lib.extern_smb_list_credential.argtypes = [ctypes.c_bool]
lib.extern_smb_list_credential.restype = ctypes.c_int
lib.extern_smb_version.restype = ctypes.c_char_p


def load_config():
    if yaml is None:
        raise RuntimeError("PyYAML is required to read the configuration")

    with open(CONFIG_FILE_PATH, "r") as config_file:
        config = yaml.safe_load(config_file)
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("configuration root must be a mapping")
    return config


def save_config(config):
    if yaml is None:
        raise RuntimeError("PyYAML is required to write the configuration")
    if not isinstance(config, dict):
        raise ValueError("configuration root must be a mapping")

    def config_opener(path, flags):
        return os.open(path, flags, 0o600)

    with open(CONFIG_FILE_PATH, "w", opener=config_opener) as config_file:
        yaml.safe_dump(config, config_file, default_flow_style=False, sort_keys=False)


def ensure_azure_identity_dependencies():
    if yaml is not None and ManagedIdentityCredential is not None and ClientAssertionCredential is not None:
        return True

    print(
        "Missing Python dependencies: azure-identity and azure-core; PyYAML is also required. "
        "Install them (e.g. 'pip3 install azure-identity azure-core PyYAML') and retry."
    )
    if AZURE_IDENTITY_IMPORT_ERROR is not None:
        print(f"Dependency import error: {AZURE_IDENTITY_IMPORT_ERROR}")
    if YAML_IMPORT_ERROR is not None:
        print(f"Dependency import error: {YAML_IMPORT_ERROR}")
    return False


def load_azure_identity_environment():
    if yaml is None:
        print("Missing Python dependency: PyYAML. Install it (e.g. 'pip3 install PyYAML') and retry.")
        return False

    try:
        config = load_config()
    except FileNotFoundError:
        return True
    except Exception as e:
        print(f"Error reading the config file from {CONFIG_FILE_PATH}: {e}")
        return False

    try:
        if not isinstance(config, dict):
            raise ValueError("configuration root must be a mapping")

        environment = config.get("ENVIRONMENT", {})
        if not isinstance(environment, dict):
            raise ValueError("ENVIRONMENT must be a mapping")

        for key, value in environment.items():
            if not isinstance(key, str) or not key or not key.replace("_", "a").isalnum() or key[0].isdigit():
                raise ValueError(f"invalid environment variable name: {key}")
            if not isinstance(value, (str, int, float, bool)):
                raise ValueError(f"environment variable {key} must have a scalar value")
            os.environ[key] = str(value)
    except Exception as e:
        print(f"Error loading Azure Identity environment from {CONFIG_FILE_PATH}: {e}")
        return False

    return True


def init_new_user():
    # Create a new linux user, and get its UID from the syscall's return
    new_user = "azfilesuser"

    # check if USER_UID is already populated in config file
    try:
        config = load_config()
        uid = config.get("USER_UID")
        if uid is not None:
            try:
                pwd.getpwuid(int(uid))
                return str(uid)
            except (KeyError, TypeError, ValueError):
                print(f"User with UID {uid} does not exist.")
    except Exception as e:
        print(f"Error reading the config file from {CONFIG_FILE_PATH}: {e}")
        sys.exit(1)

    # Check if the azfilesuser already exists
    if os.system(f"getent passwd {new_user} > /dev/null 2>&1") == 0:
        new_user_uid = subprocess.check_output(f"id -u {new_user}", shell=True).decode().strip()

    else:
        rc = os.system(f"useradd -m {new_user} > /dev/null 2>&1")
        if rc != 0:
            print("Failed to create new user")
            sys.exit(1)
        # Add the user to the sudo/wheel group (SLES/RHEL use 'wheel', Debian/Ubuntu use 'sudo')
        rc = os.system(f"usermod -aG sudo {new_user} > /dev/null 2>&1")
        if rc != 0:
            # 'sudo' group not found; try 'wheel' (SLES/RHEL), creating it if needed
            os.system("groupadd -f wheel > /dev/null 2>&1")
            rc = os.system(f"usermod -aG wheel {new_user} > /dev/null 2>&1")
        if rc != 0:
            print("Failed to add user to sudo/wheel group")
            sys.exit(1)

        new_user_uid = subprocess.check_output(f"id -u {new_user}", shell=True).decode().strip()
        print(f"New user {new_user} created with UID: {new_user_uid}")

    try:
        config["USER_UID"] = int(new_user_uid)
        save_config(config)
    except Exception:
        print(f"Error writing the config file at {CONFIG_FILE_PATH}")
        sys.exit(1)

    return new_user_uid


def get_oauth_token(client_id=None):
    if not load_azure_identity_environment():
        return None

    # Use ManagedIdentityCredential for IMDS: system-assigned (no client_id) or user-assigned (with client_id)
    if not ensure_azure_identity_dependencies():
        return None

    try:
        # Instantiate ManagedIdentityCredential
        # If client_id is None, it will use system-assigned managed identity
        # If client_id is provided, it will use user-assigned managed identity
        credential = ManagedIdentityCredential(client_id=client_id) if client_id else ManagedIdentityCredential()
        
        # Get token for Azure Storage
        token_response = credential.get_token("https://storage.azure.com/.default")
        tok = token_response.token
        
        if not tok:
            print("Access token missing from managed identity credential")
            return None
        return tok
    except ClientAuthenticationError as e:
        if client_id:
            print(f"Error fetching user-assigned managed identity token: {e}")
        else:
            print(f"Error fetching system-assigned managed identity token: {e}")
        return None
    except Exception as e:
        if client_id:
            print(f"Error fetching user-assigned managed identity token: {e}")
        else:
            print(f"Error fetching system-assigned managed identity token: {e}")
        return None

def get_workload_identity_token(tenant_id, client_id, token_file, authority_host=None, resource=None):
    if not load_azure_identity_environment():
        return None

    if not all([tenant_id, client_id, token_file]):
        print("Error: Missing parameters for Workload Identity.")
        return None

    if not ensure_azure_identity_dependencies():
        return None

    try:
        with open(token_file, 'r') as f:
            client_assertion = f.read().strip()
    except Exception as e:
        print(f"Error reading federated token file: {e}")
        return None

    # Default to public Azure AD / storage resource.
    # Sovereign clouds (e.g. Mooncake, US Gov) pass a cloud-specific authority host.
    # The resource is the base URI without the `/.default` scope suffix. This
    # matches the Azure Files CSI driver's resource configuration.
    authority = (
        authority_host
        or os.environ.get("AZURE_AUTHORITY_HOST")
        or "https://login.microsoftonline.com"
    ).rstrip("/")
    storage_resource = (resource or "https://storage.azure.com").rstrip("/")

    try:
        # Define a token provider callback that returns the federated token
        def token_provider():
            return client_assertion
        
        # Use ClientAssertionCredential for Workload Identity Federation
        # Pass the authority as the authority parameter for sovereign cloud support
        credential = ClientAssertionCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            func=token_provider,
            authority=authority,
        )

        # Get token for Azure Storage
        scope = f"{storage_resource}/.default"
        token_response = credential.get_token(scope)
        tok = token_response.token
        
        if not tok:
            print("Access token missing from workload identity credential")
            return None
        return tok
    except ClientAuthenticationError as e:
        print(f"Error fetching Workload Identity token: {e}")
        return None
    except Exception as e:
        print(f"Error fetching Workload Identity token: {e}")
        return None


def _normalize_endpoint(file_endpoint_uri):
    return str(file_endpoint_uri).strip().rstrip("/")


class AuthMetadataConflict(Exception):
    """Raised when persisted auth metadata belongs to a different identity than requested."""


@contextlib.contextmanager
def _locked_state_file(exclusive, create=True):
    # Taking the flock before touching contents keeps read-modify-write atomic
    # across concurrent azfilesauthmanager/azfilesrefresh invocations. `create`
    # is only needed for writers; readers/no-op callers skip creating the dir
    # and file so a not-yet-existing state file is treated as empty state.
    if create:
        os.makedirs(AUTH_STATE_DIR, mode=0o750, exist_ok=True)
        os.chmod(AUTH_STATE_DIR, 0o750)
        fd = os.open(AUTH_STATE_FILE_PATH, os.O_RDWR | os.O_CREAT, 0o640)
    else:
        try:
            fd = os.open(AUTH_STATE_FILE_PATH, os.O_RDWR)
        except FileNotFoundError:
            yield None
            return

    state_file = os.fdopen(fd, "r+")
    try:
        fcntl.flock(state_file.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield state_file
        finally:
            fcntl.flock(state_file.fileno(), fcntl.LOCK_UN)
    finally:
        state_file.close()


def _load_locked_state(state_file):
    state_file.seek(0)
    content = state_file.read()
    if not content.strip():
        return {}
    try:
        state = json.loads(content)
    except json.JSONDecodeError:
        return {}
    return state if isinstance(state, dict) else {}


def _save_locked_state(state_file, state):
    state_file.seek(0)
    state_file.truncate()
    json.dump(state, state_file, indent=2, sort_keys=True)
    state_file.write("\n")
    state_file.flush()
    os.fsync(state_file.fileno())


def get_endpoint_auth_metadata(file_endpoint_uri):
    endpoint = _normalize_endpoint(file_endpoint_uri)
    if not endpoint:
        return None

    try:
        with _locked_state_file(exclusive=False, create=False) as state_file:
            if state_file is None:
                return None
            state = _load_locked_state(state_file)
    except OSError as e:
        print(f"Error reading auth metadata from {AUTH_STATE_FILE_PATH}: {e}")
        return None

    return state.get(endpoint)


def _describe_auth_metadata_conflict(previous_metadata, auth_mode, tenant_id, client_id):
    """Return a human-readable conflict reason, or None if the identities agree."""
    previous_mode = previous_metadata.get("auth_mode")
    previous_client_id = previous_metadata.get("client_id")
    previous_tenant_id = previous_metadata.get("tenant_id")

    if previous_mode and previous_mode != auth_mode:
        return f"existing auth_mode='{previous_mode}' does not match requested auth_mode='{auth_mode}'"

    if auth_mode == "user-assigned" and client_id and previous_client_id and previous_client_id != client_id:
        return f"existing client_id='{previous_client_id}' does not match requested client_id='{client_id}'"

    if auth_mode == "workload-identity":
        if client_id and previous_client_id and previous_client_id != client_id:
            return f"existing client_id='{previous_client_id}' does not match requested client_id='{client_id}'"
        if tenant_id and previous_tenant_id and previous_tenant_id != tenant_id:
            return f"existing tenant_id='{previous_tenant_id}' does not match requested tenant_id='{tenant_id}'"

    return None


def azfiles_set_oauth(file_endpoint_uri, oauth_token, auth_mode=None, tenant_id=None, client_id=None, token_file=None, authority_host=None, resource=None, force=False):
    """Write the oauth token via the native lib and (if auth_mode is given) persist
    endpoint auth metadata, as a single operation under one exclusive lock so the
    krb5/keyring credential store and the state file can never observe each other
    mid-update. Raises AuthMetadataConflict before touching either store if the
    endpoint is already owned by a different identity, unless force=True."""
    endpoint = _normalize_endpoint(file_endpoint_uri)

    try:
        with _locked_state_file(exclusive=True) as state_file:
            state = _load_locked_state(state_file)
            previous_metadata = state.get(endpoint) if endpoint else None

            if auth_mode and previous_metadata:
                conflict_reason = _describe_auth_metadata_conflict(previous_metadata, auth_mode, tenant_id, client_id)
                if conflict_reason:
                    if not force:
                        raise AuthMetadataConflict(f"Endpoint {endpoint}: {conflict_reason}")
                    print(f"[!] Forcing overwrite for endpoint {endpoint}: {conflict_reason}")

            validity_in_sec = ctypes.c_uint()
            rc = lib.extern_smb_set_credential_oauth_token(
                file_endpoint_uri.encode('utf-8'),
                oauth_token.encode('utf-8'),
                ctypes.byref(validity_in_sec)
                )

            if rc != 0:
                print(f"[-] Error calling AzAuthenticatorLib: {rc}")
                sys.exit(1)

            if auth_mode and endpoint:
                metadata = {"auth_mode": auth_mode}
                optional_metadata = {
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "token_file": token_file,
                    "authority_host": authority_host,
                    "resource": resource,
                }
                for metadata_key, metadata_value in optional_metadata.items():
                    if metadata_value is not None:
                        metadata[metadata_key] = metadata_value
                state[endpoint] = metadata
                _save_locked_state(state_file, state)
    except OSError as e:
        print(f"Error accessing auth metadata at {AUTH_STATE_FILE_PATH}: {e}")
        sys.exit(1)


def azfiles_clear(file_endpoint_uri):
    endpoint = _normalize_endpoint(file_endpoint_uri)

    try:
        with _locked_state_file(exclusive=True) as state_file:
            state = _load_locked_state(state_file)

            rc = lib.extern_smb_clear_credential(file_endpoint_uri.encode())
            print(f"azfilesauthmanager clear: {rc}")

            if rc != 0:
                print(f"[-] Error calling AzAuthenticatorLib: {rc}")
                sys.exit(1)

            if endpoint and endpoint in state:
                del state[endpoint]
                _save_locked_state(state_file, state)
    except OSError as e:
        print(f"Error accessing auth metadata at {AUTH_STATE_FILE_PATH}: {e}")
        sys.exit(1)


def azfiles_list(is_json):
    try:
        with _locked_state_file(exclusive=False) as state_file:
            rc = lib.extern_smb_list_credential(is_json)
            # The C function returns 0 on success, non-zero on error. ctypes will not raise.
            if rc != 0:
                # Propagate the exact code so callers / scripts can branch on it.
                print(f"[-] Error calling AzAuthenticatorLib: {rc}")
                sys.exit(rc)
    except OSError as e:
        print(f"Error accessing auth metadata at {AUTH_STATE_FILE_PATH}: {e}")
        sys.exit(1)


def run_azfilesauthmanager():
    if len(sys.argv) < 2:
        print(USAGE_MESSAGE)
        sys.exit(1)

    try:
        config = load_config()
        ccache_name = config.get("KRB5_CC_NAME")
        if ccache_name is not None:
            os.environ["KRB5CCNAME"] = str(ccache_name)
    except Exception:
        print(f"Error reading the config file from {CONFIG_FILE_PATH}")
        sys.exit(1)

    command = sys.argv[1]

    if command == "--version":
        v = lib.extern_smb_version()
        print(v.decode() if isinstance(v, (bytes, bytearray)) else v)
        sys.exit(0)

    user_id = int(init_new_user())

    if command == "list":
        if len(sys.argv) != 2 and len(sys.argv) != 3:
            print(USAGE_MESSAGE)
            sys.exit(1)

        # check if the user has used the --json switch
        if "--json" in sys.argv:
            azfiles_list(True)
        else:
            azfiles_list(False)

    elif command == "set":
        # Supported patterns:
        #   set <endpoint> <token>
        #   set <endpoint> --system
        #   set <endpoint> --imds-client-id <client_id>
        file_endpoint_uri = None
        oauth_token = None

        argv = sys.argv
        if len(argv) < 4:
            print(USAGE_MESSAGE)
            sys.exit(1)

        # Strip --force up front so it doesn't disturb the positional argument
        # counts/indices the rest of the parsing below relies on.
        force = "--force" in argv
        if force:
            argv = [arg for arg in argv if arg != "--force"]

        file_endpoint_uri = argv[2]

        is_system_mi = False
        is_user_mi = False
        is_workload_identity = False

        if "--system" in argv:
            is_system_mi = True
        if "--imds-client-id" in argv:
            is_user_mi = True
        if "--workload-identity" in argv:
            is_workload_identity = True

        if sum([is_system_mi, is_user_mi, is_workload_identity]) > 1:
            print("Cannot specify more than one of --system, --imds-client-id, or --workload-identity")
            sys.exit(1)

        # User-assigned MI path
        if is_user_mi:
            if len(argv) != 5:
                print(USAGE_MESSAGE)
                sys.exit(1)
            client_id = argv[4]
            oauth_token = get_oauth_token(client_id)
            if oauth_token is None:
                sys.exit(1)
            try:
                azfiles_set_oauth(file_endpoint_uri, oauth_token, auth_mode="user-assigned", client_id=client_id, force=force)
            except AuthMetadataConflict as e:
                print(f"[-] Refusing to set credential: {e}")
                sys.exit(3)
        # System-assigned MI path
        elif is_system_mi:
            if len(argv) != 4:  # set <endpoint> --system
                print(USAGE_MESSAGE)
                sys.exit(1)
            oauth_token = get_oauth_token()
            if oauth_token is None:
                sys.exit(1)
            try:
                azfiles_set_oauth(file_endpoint_uri, oauth_token, auth_mode="system", force=force)
            except AuthMetadataConflict as e:
                print(f"[-] Refusing to set credential: {e}")
                sys.exit(3)
        # Workload Identity path
        elif is_workload_identity:
            tenant_id = None
            client_id = None
            token_file = None
            authority_host = None
            resource = None

            try:
                if "--tenant-id" in argv:
                    tenant_id = argv[argv.index("--tenant-id") + 1]
                if "--client-id" in argv:
                    client_id = argv[argv.index("--client-id") + 1]
                if "--token-file" in argv:
                    token_file = argv[argv.index("--token-file") + 1]
                if "--authority-host" in argv:
                    authority_host = argv[argv.index("--authority-host") + 1]
                if "--resource" in argv:
                    resource = argv[argv.index("--resource") + 1]
            except IndexError:
                print(USAGE_MESSAGE)
                sys.exit(1)

            if not all([tenant_id, client_id, token_file]):
                print("Missing required parameters for workload identity.")
                print(USAGE_MESSAGE)
                sys.exit(1)

            oauth_token = get_workload_identity_token(
                tenant_id,
                client_id,
                token_file,
                authority_host=authority_host,
                resource=resource,
            )
            if oauth_token is None:
                sys.exit(1)
            try:
                azfiles_set_oauth(
                    file_endpoint_uri,
                    oauth_token,
                    auth_mode="workload-identity",
                    tenant_id=tenant_id,
                    client_id=client_id,
                    token_file=token_file,
                    authority_host=authority_host,
                    resource=resource,
                    force=force,
                )
            except AuthMetadataConflict as e:
                print(f"[-] Refusing to set credential: {e}")
                sys.exit(3)
        else:
            # Direct token form: set <endpoint> <oauth_token>
            if len(argv) != 4:
                print(USAGE_MESSAGE)
                sys.exit(1)
            oauth_token = argv[3]
            try:
                azfiles_set_oauth(file_endpoint_uri, oauth_token, auth_mode="token", force=force)
            except AuthMetadataConflict as e:
                print(f"[-] Refusing to set credential: {e}")
                sys.exit(3)

    elif command == "clear":
        if len(sys.argv) != 3:
            print(USAGE_MESSAGE)
            sys.exit(1)

        file_endpoint_uri = sys.argv[2]
        # TODO - Check formats?

        azfiles_clear(file_endpoint_uri)

    else:
        print(USAGE_MESSAGE)
        sys.exit(1)

if __name__ == "__main__":
    if os.geteuid() == 0:
        run_azfilesauthmanager()
    else:
        print("Script is not running as root. Please run as root.")
        sys.exit(1)
