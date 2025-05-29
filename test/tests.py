#!/usr/bin/env python3

import ctypes.util
import os
import sys
import subprocess
import time
import ctypes
import requests
import json

LOG_FILE = "/var/log/azfilestests.log"
CONFIG_FILE_PATH = "./test_config.yaml"

USAGE_MESSAGE = """
Usage: 
        ./tests.py run <file_endpoint_uri>
"""


def load_lib(lib_name="azfilesauth"):
    # Try system library paths first
    lib_path = ctypes.util.find_library(lib_name)
    if lib_path:
        return ctypes.CDLL(lib_path)

    # Check common library directories manually
    for path in ["/usr/lib", "/usr/local/lib", "/lib", "/lib64", "/usr/lib64"]:
        full_path = os.path.join(path, f"lib{lib_name}.so")
        if os.path.exists(full_path):
            return ctypes.CDLL(full_path)

    raise FileNotFoundError(f"Library {lib_name} not found.")

lib = load_lib()


# Define the function signatures
lib.extern_smb_set_credential_oauth_token.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
lib.extern_smb_set_credential_oauth_token.restype = ctypes.c_int

lib.extern_smb_clear_credential.argtypes = [ctypes.c_char_p]
lib.extern_smb_clear_credential.restype = ctypes.c_int 

lib.extern_smb_list_credential.argtypes = [ctypes.c_bool]

config = {}


def list_credentials():
    # list the credentials with --json to get the expiry time
    result = subprocess.run(["sudo", "sh", "-c", "azfilesauthmanager list --json"], 
            capture_output=True, 
            text=True)
    if result.returncode != 0:
        print(f"Test failed")
        print(f"Error listing credentials: {result.stderr}")
        cleanup(1)

    with open("./list_cred_op", "w") as f:
        f.write(result.stdout)
    
    # result.stdout is JSON, parse it
    credentials = json.loads(str(result.stdout))

    # select and return a list of all credentials where server: 'cifs'
    credentials = [cred for cred in credentials if cred["server"].startswith("cifs")]
    return credentials


def cleanup(rc):
    print(f"\n[+] Cleaning up: ", flush=True)
    if "MOUNT_PATH" in config:
        os.system(f"sudo umount {config['MOUNT_PATH']} > /dev/null 2>&1")

    print("[+] Done")
    sys.exit(rc)


def clear_credentials(file_endpoint_uri):
    rc = os.system(f"sudo azfilesauthmanager clear {file_endpoint_uri} > /dev/null 2>&1")

    if rc != 0:
        print(f"clear creds failed")


def init_new_user():
    # Create a new linux user, and get its UID from the syscall's return
    new_user = "azfilesuser"
    print(f"[+] Testing user {new_user}'s existence: ", end="", flush=True)

    if os.system(f"getent passwd {new_user}") == 0:
        print(f"[+] User {new_user} already exists with UID: ", end="", flush=True)
        new_user_uid = subprocess.check_output(f"id -u {new_user}", shell=True).decode().strip()
        print(new_user_uid)
        return new_user_uid

    rc = os.system(f"useradd -m {new_user}")
    if rc != 0:
        print("[-] Failed to create new user")
        cleanup(1)

    new_user_uid = subprocess.check_output(f"id -u {new_user}", shell=True).decode().strip()
    print(f"[+] New user {new_user} created with UID: {new_user_uid}")
    return new_user_uid


def get_oauth_token():
    token_url = f'https://login.microsoftonline.com/{config["TENANT_ID"]}/oauth2/v2.0/token'
    
    body = {
        "client_id": config["CLIENT_ID"],
        "scope": f"{config['RESOURCE']}/.default",
        "client_secret": config['CLIENT_SECRET'],
        "grant_type": "client_credentials"
    }
    
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    
    try:
        response = requests.post(token_url, data=body, headers=headers)
        response.raise_for_status()
        return response.json().get("access_token")
    
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response: {response.text}")
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}")
    except Exception as err:
        print(f"An unexpected error occurred: {err}")
    
    return None


def config_setup():
    cruid = init_new_user()
    config["CRUID"] = cruid

    print(f"\n[+] Changing KRB5_CC_NAME in /etc/azfileauth/config.yaml to: /tmp/krb5cc_{config['CRUID']}", flush=True)
    command = f"""sudo sh -c 'echo "KRB5_CC_NAME: /tmp/krb5cc_{config['CRUID']}" > /etc/azfilesauth/config.yaml'"""
    rc = os.system(command)

    if rc != 0:
        print("[-] Failed to update KRB5_CC_NAME in azfilesauth config.yaml")
        cleanup(1)

    try:
        with open(CONFIG_FILE_PATH, "r") as config_file:
            for line in config_file:
                if "CLIENT_ID" in line:
                    config["CLIENT_ID"] = line.split(":", 1)[1].strip()
                if "TENANT_ID" in line:
                    config["TENANT_ID"] = line.split(":", 1)[1].strip()
                if "CLIENT_SECRET" in line:
                    config["CLIENT_SECRET"] = line.split(":", 1)[1].strip()
                if "RESOURCE" in line:
                    config["RESOURCE"] = line.split(":", 1)[1].strip()    
                if "MOUNT_PATH" in line:
                    config["MOUNT_PATH"] = line.split(":", 1)[1].strip()
                if "SHARE_NAME" in line:
                    config["SHARE_NAME"] = line.split(":", 1)[1].strip()
    except:
        print(f"Error reading the config file from {CONFIG_FILE_PATH}. Check if the file exists.")
        cleanup(1)

    # check if config has all fields set
    if not all(key in config for key in ["CLIENT_ID", "TENANT_ID", "CLIENT_SECRET", "RESOURCE", "MOUNT_PATH", "SHARE_NAME"]):
        print("[-] Config file is missing one or more fields. Please check the config file.")
        print("[-] Expected fields: CLIENT_ID, TENANT_ID, CLIENT_SECRET, RESOURCE, MOUNT_PATH, SHARE_NAME")
        cleanup(1)


def insert_credentials(file_endpoint_uri):
    validity_in_sec = ctypes.c_uint()
    oauth_token = get_oauth_token()

    rc = os.system(f"sudo azfilesauthmanager set {file_endpoint_uri} {oauth_token}")
    
    if rc != 0:
        print(f"Test failed")
        cleanup(1)


def test_basic_mount(file_endpoint_uri, mount_command):
    print(f"\nTest 1: Basic Mount")
    os.system(f"sudo umount {config['MOUNT_PATH']} > /dev/null 2>&1")
    print(f"    [+] Basic mount: ", end="", flush=True)

    insert_credentials(file_endpoint_uri)
    mount_rc = os.system(mount_command)

    if mount_rc != 0:
        print(f"Test failed")
        cleanup(1)

    os.system(f"sudo umount {config['MOUNT_PATH']} > /dev/null 2>&1")
    print(f"Test passed")

    clear_credentials(file_endpoint_uri)
    print(f"[+] Cleared credentials")


def test_mount_post_cred_expiry_and_renewal(file_endpoint_uri, mount_command):
    print(f"\nTest 2 + 3: Try mount post expiry (should fail) and renewal (should pass)")
    os.system(f"sudo umount {config['MOUNT_PATH']} > /dev/null 2>&1")
    print(f"    [+] Waiting for ticket expiry: ", end="", flush=True)

    insert_credentials(file_endpoint_uri)

    credentials = list_credentials()
    expiry = credentials[-1]["ticket_renew_till"]

    # wait for the ticket to expire
    time_to_wait = expiry - int(time.time())
    print(f"Sleeping for {time_to_wait} seconds ({time_to_wait//60} min)")
    time.sleep(time_to_wait + 10)

    print(f"    [+] Mount post expiry: ", end="", flush=True)
    mount_rc = os.system(mount_command)

    if mount_rc == 0:
        print(f"Test failed (mount succeeded)")
        cleanup(1)
    
    print("    [+] Mount failed as expected, continuing test")

    print(f"    [+] Renewing credentials", flush=True)
    insert_credentials(file_endpoint_uri)

    print(f"    [+] Mount post renewal: ", end="", flush=True)
    mount_rc = os.system(mount_command)

    if mount_rc != 0:
        print(f"Test failed (mount failed)")
        cleanup(1)

    print(f"Test passed")

    os.system(f"sudo umount {config['MOUNT_PATH']} > /dev/null 2>&1")
    clear_credentials(file_endpoint_uri)
    print(f"[+] Cleared credentials")


def test_second_cred_validity_post_initial_expiry(file_endpoint_uri, mount_command):
    print(f"\nTest 4: Insert second ticket before first ticket expiry, and ensure operations work after first ticket expires")
    os.system(f"sudo umount {config['MOUNT_PATH']} > /dev/null 2>&1")
    print(f"    [+] Inserting first ticket: ", end="", flush=True)

    insert_credentials(file_endpoint_uri)

    credentials = list_credentials()
    expiry = credentials[-1]["ticket_renew_till"]

    # wait for the ticket to expire
    time_to_wait = expiry - int(time.time())
    print(f"Sleeping for {time_to_wait} seconds ({time_to_wait//60} min)")
    time.sleep(time_to_wait/2)

    print(f"    [+] Halfway through first expiry, inserting second ticket: ", end="", flush=True)
    insert_credentials(file_endpoint_uri)
    credentials = list_credentials()
    print(f"[+] Current credentials: {credentials}")

    print(f"    [+] Waiting for first ticket expiry: ", end="", flush=True)
    time_to_wait = expiry - int(time.time())
    print(f"Sleeping for {time_to_wait} seconds ({time_to_wait//60} min)")
    time.sleep(time_to_wait + 10)

    print(f"    [+] Is first ticket expired: ", end="", flush=True)
    credentials = list_credentials()
    expiry = credentials[-1]["ticket_renew_till"]
    if expiry < int(time.time()):
        print(f"Expired")
    else:
        print(f"Not expired, test failed (possibly using wrong set of tickets)")
        for cred in credentials:
            time_left = cred["ticket_renew_till"] - int(time.time())
            print(f"Credential: {cred}\nTime left: {time_left} seconds")
        cleanup(1)

    print(f"    [+] Testing mount post first ticket expiry: ", end="", flush=True)
    mount_rc = os.system(mount_command)

    if mount_rc != 0:
        print(f"Test failed (mount failed)")
        cleanup(1)

    print(f"Test passed")

    os.system(f"sudo umount {config['MOUNT_PATH']} > /dev/null 2>&1")
    clear_credentials(file_endpoint_uri)
    print(f"[+] Cleared credentials")


def test_heavy_writes_at_ticket_switch(file_endpoint_uri, mount_command, n_handles):
    print(f"\nTest 5: Insert one ticket, at the halfway point insert a second ticket, 5 mins before expiry trigger heavy writes (10GB) to server from handle (dd) with multiple handles.")
    os.system(f"sudo umount {config['MOUNT_PATH']} > /dev/null 2>&1")
    print(f"    [+] Inserting first ticket", flush=True)

    insert_credentials(file_endpoint_uri)

    credentials = list_credentials()
    expiry = credentials[-1]["ticket_renew_till"]

    print(f"    [+] Mounting share", flush=True)
    mount_rc = os.system(mount_command)
    if mount_rc != 0:
            print(f"Test failed (mount failed)")
            cleanup(1)

    ritvik_dir = os.path.join(config["MOUNT_PATH"], "ritvik")
    if not os.path.exists(ritvik_dir):
        os.makedirs(ritvik_dir)

    # wait for the ticket to expire
    time_to_wait = expiry - int(time.time())
    print(f"Sleeping for {time_to_wait - 300} seconds ({(time_to_wait - 300)//60} min)")
    time.sleep(time_to_wait - 300)

    print(f"    [+] Checking ticket expiry time: ", end="", flush=True)
    credentials = list_credentials()
    expiry = credentials[-1]["ticket_renew_till"]
    print(f"    [+] Expiry time: {expiry}")

    print(f"    [+] 300 seconds to first expiry, inserting second ticket: ", end="", flush=True)
    insert_credentials(file_endpoint_uri)
    credentials = list_credentials()
    print(f"    [+] Current credentials: {credentials}")

    print(f"    [+] Triggering workload with {n_handles} handles: ", end="", flush=True)

    # Start n_handles dd processes to write 10GB to the server using ./test_open_handles.sh <mountpath> <handle index>
    for i in range(n_handles):
        os.system(f"./test_open_handles.sh {config['MOUNT_PATH']} {i} &")

    credentials = list_credentials()
    expiry = credentials[-2]["ticket_renew_till"]

    os.system(f"sudo umount {config['MOUNT_PATH']} > /dev/null 2>&1")
    clear_credentials(file_endpoint_uri)
    print(f"[+] Cleared credentials")


def run_azfilesauthtests():
    if len(sys.argv) < 3:
        print(USAGE_MESSAGE)
        cleanup(1)

    config_setup()

    command = sys.argv[1]
    file_endpoint_uri = sys.argv[2]

    if command == "run":
        
        clear_credentials(file_endpoint_uri)

        print(f"\n[+] Running tests for file endpoint: {file_endpoint_uri}", flush=True)
        
        if not os.path.exists(config["MOUNT_PATH"]):
            os.makedirs(config["MOUNT_PATH"])

        # strip the file_endpoint_uri to get rid of https:// and trailing slashes
        storage_acc = file_endpoint_uri.replace("https://", "//")
        storage_acc = storage_acc.rstrip("/")
        mnt_cmd = f"sudo mount -t cifs {storage_acc}/{config['SHARE_NAME']} {config['MOUNT_PATH']} -o sec=krb5,cruid={config['CRUID']}"
        mnt_cmd_multichannel = f"sudo mount -t cifs {storage_acc}/{config['SHARE_NAME']} {config['MOUNT_PATH']} -o sec=krb5,cruid={config['CRUID']},multichannel,max_channels=4"

        # Insert Ticket to credential cache and validate mount works
        test_basic_mount(file_endpoint_uri, mnt_cmd)

        # Allow ticket to expire, renew ticket and validate operations work
        test_mount_post_cred_expiry_and_renewal(file_endpoint_uri, mnt_cmd)

        # Insert first ticket, 30 mins later insert second ticket and validate operations work after first ticket expires
        test_second_cred_validity_post_initial_expiry(file_endpoint_uri, mnt_cmd)

        # Test multichannel
        print(f"\n---------- Multichannel ----------")
        
        test_basic_mount(file_endpoint_uri, mnt_cmd_multichannel)
        test_mount_post_cred_expiry_and_renewal(file_endpoint_uri, mnt_cmd_multichannel)
        test_second_cred_validity_post_initial_expiry(file_endpoint_uri, mnt_cmd_multichannel)


        ##### PENDING IMPLEMENTATION #####

        # print(f"\n--------- Stress Tests ----------")

        # Insert one ticket, at the halfway point insert a second ticket, 7 mins before expiry trigger heavy writes (15GB) to server from handle (dd)
        # uses the external bash script in this directory 
        # test_heavy_writes_at_ticket_switch(file_endpoint_uri, mnt_cmd, 1)

    else:
        print(USAGE_MESSAGE)
        cleanup(1)

if __name__ == "__main__":
    if os.geteuid() == 0:
        run_azfilesauthtests()
    else:
        print("Please run tests as root.")
        cleanup(1)
