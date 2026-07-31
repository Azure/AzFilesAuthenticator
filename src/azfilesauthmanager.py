#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import ctypes
import pwd
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

USAGE_MESSAGE = """Usage:
    azfilesauthmanager list [--json]
    azfilesauthmanager set <file_endpoint_uri> <oauth_token>
    azfilesauthmanager set <file_endpoint_uri> --system
    azfilesauthmanager set <file_endpoint_uri> --imds-client-id <client_id>
    azfilesauthmanager set <file_endpoint_uri> --workload-identity --tenant-id <tenant_id> --client-id <client_id> --token-file <token_file> [--authority-host <authority_host>] [--resource <resource>]
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


def ensure_azure_identity_dependencies():
    if ManagedIdentityCredential is not None and ClientAssertionCredential is not None:
        return True

    print(
        "Missing Python dependencies: azure-identity and azure-core. "
        "Install them (e.g. 'pip3 install azure-identity azure-core') and retry."
    )
    if AZURE_IDENTITY_IMPORT_ERROR is not None:
        print(f"Dependency import error: {AZURE_IDENTITY_IMPORT_ERROR}")
    return False


def init_new_user():
    # Create a new linux user, and get its UID from the syscall's return
    new_user = "azfilesuser"

    # check if USER_UID is already populated in config file
    try:
        with open(CONFIG_FILE_PATH, "r") as config_file:
            for line in config_file:
                if "USER_UID" in line:
                    uid = line.split(":")[1].strip()
                    # check if the uid is for a valid user
                    try:
                        pwd.getpwuid(int(uid))
                        return uid
                    except:
                        print(f"User with UID {uid} does not exist.")
                        break
    except:
        print(f"Either user {new_user} does not exist, or error reading the config file from {CONFIG_FILE_PATH}.")

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
        with open(CONFIG_FILE_PATH, "a") as config_file:
            config_file.write(f"USER_UID: {new_user_uid}\n")

    except:
        print(f"Error reading the config file from {CONFIG_FILE_PATH}")
        sys.exit(1)

    return new_user_uid


def get_oauth_token(client_id=None):
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
    authority = (authority_host or "https://login.microsoftonline.com").rstrip("/")
    storage_resource = (resource or "https://storage.azure.com").rstrip("/")
    
    try:
        # Define a token provider callback that returns the federated token
        def token_provider():
            return client_assertion
        
        # Use ClientAssertionCredential for Workload Identity Federation
        # Pass the authority as the authority parameter for sovereign cloud support
        try:
            credential = ClientAssertionCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                token_provider=token_provider,
                authority=authority
            )
        except TypeError:
            # Backward compatibility for azure-identity versions that expect `func`.
            credential = ClientAssertionCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                func=token_provider,
                authority=authority
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


def azfiles_set_oauth(file_endpoint_uri, oauth_token):

    validity_in_sec = ctypes.c_uint()

    try:
        rc = lib.extern_smb_set_credential_oauth_token(
            file_endpoint_uri.encode('utf-8'), 
            oauth_token.encode('utf-8'),
            ctypes.byref(validity_in_sec)
            )

        if rc != 0:
            print(f"[-] Error calling AzAuthenticatorLib: {rc}")
            sys.exit(1)

    except subprocess.CalledProcessError as e:
        print(f"Error calling AzAuthenticatorLib: {e.stderr}")
        sys.exit(1)


def azfiles_clear(file_endpoint_uri):

    try:
        rc = lib.extern_smb_clear_credential(file_endpoint_uri.encode())
        print(f"azfilesauthmanager clear: {rc}")

        if rc != 0:
            print(f"[-] Error calling AzAuthenticatorLib: {rc}")
            sys.exit(1)

    except subprocess.CalledProcessError as e:
        print(f"Error calling AzAuthenticatorLib: {e.stderr}")
        sys.exit(1)


def azfiles_list(is_json):
    try:
        rc = lib.extern_smb_list_credential(is_json)
        # The C function returns 0 on success, non-zero on error. ctypes will not raise.
        if rc != 0:
            # Propagate the exact code so callers / scripts can branch on it.
            print(f"[-] Error calling AzAuthenticatorLib: {rc}")
            sys.exit(rc)

    except subprocess.CalledProcessError as e:
        print(f"Error calling AzAuthenticatorLib: {e.stderr}")
        sys.exit(1)


def run_azfilesauthmanager():
    if len(sys.argv) < 2:
        print(USAGE_MESSAGE)
        sys.exit(1)

    # read the CONFIG_FILE_PATH and get the "KRB5_CC_NAME" from the yaml file
    try:
        with open(CONFIG_FILE_PATH, "r") as config_file:
            for line in config_file:
                if "KRB5_CC_NAME" in line:
                    os.environ["KRB5CCNAME"] = line.split(":")[1].strip()
                    break
    except:
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
        # System-assigned MI path
        elif is_system_mi:
            if len(argv) != 4:  # set <endpoint> --system
                print(USAGE_MESSAGE)
                sys.exit(1)
            oauth_token = get_oauth_token()
            if oauth_token is None:
                sys.exit(1)
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
        else:
            # Direct token form: set <endpoint> <oauth_token>
            if len(argv) != 4:
                print(USAGE_MESSAGE)
                sys.exit(1)
            oauth_token = argv[3]

        azfiles_set_oauth(file_endpoint_uri, oauth_token)
    
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
