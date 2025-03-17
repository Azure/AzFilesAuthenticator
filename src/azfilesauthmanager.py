#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import ctypes
import requests
import pwd


CONFIG_FILE_PATH = "/etc/azfilesauth/config.yaml"

USAGE_MESSAGE = """
Usage: 
        azfilesauthmanager list
        azfilesauthmanager set <file_endpoint_uri> <oauth_token>
        azfilesauthmanager set <file_endpoint_uri> --imds-client-id <client_id>
        azfilesauthmanager clear <file_endpoint_uri>
"""
if os.path.exists('/usr/lib/libazfilesauth.so'):
    lib = ctypes.CDLL('/usr/lib/libazfilesauth.so')
elif os.path.exists('/usr/local/lib/libazfilesauth.so'):
    lib = ctypes.CDLL('/usr/local/lib/libazfilesauth.so')
else:
    print("Library libazfilesauth.so not found in /usr/local/lib or /usr/lib")
    sys.exit(1)

# Define the function signatures
lib.extern_smb_set_credential_oauth_token.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
lib.extern_smb_set_credential_oauth_token.restype = ctypes.c_int

lib.extern_smb_clear_credential.argtypes = [ctypes.c_char_p]
lib.extern_smb_clear_credential.restype = ctypes.c_int 


def init_new_user():
    # Create a new linux user, and get its UID from the syscall's return
    new_user = "azfilesuser"

    # check if USR_UID is already populated in config file
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
        # Add the user to the sudo group
        rc = os.system(f"sudo usermod -aG sudo {new_user} > /dev/null 2>&1")
        if rc != 0:
            print("Failed to add user to sudo group")
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


def get_oauth_token(file_endpoint_uri, client_id):
    # check if file URI ends with '/', if it does, remove it
    if file_endpoint_uri.endswith('/'):
        file_endpoint_uri = file_endpoint_uri[:-1]

    url = f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={file_endpoint_uri}/&client_id={client_id}"
    headers = {"Metadata": "true"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError("No access token found in the response")
        return access_token
    
    except Exception as e:
        print(f"Error fetching OAuth token: {e}")
        sys.exit(1)
    

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
        result = lib.extern_smb_list_credential(is_json)

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
        oauth_token = None
        is_client_id = False

        # check if the user has used the --client-id switch
        if "--imds-client-id" in sys.argv:
            is_client_id = True
            if len(sys.argv) != 5:
                print(USAGE_MESSAGE)
                sys.exit(1)

        elif len(sys.argv) != 4:
            print(USAGE_MESSAGE)
            sys.exit(1)

        file_endpoint_uri = sys.argv[2]

        if is_client_id:
            client_id = sys.argv[4]
            oauth_token = get_oauth_token(file_endpoint_uri, client_id)
        else:
            oauth_token = sys.argv[3]

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
