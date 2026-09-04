#!/usr/bin/env python3

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import yaml

EPOCH_RE = re.compile(r"\(epoch:\s*(\d+)\)")
AZFILESAUTH_CONFIG_PATH = Path("/etc/azfilesauth/config.yaml")


def run_cmd(cmd, check=True, capture=True, env=None):
    result = subprocess.run(
        cmd,
        check=False,
        capture_output=capture,
        text=True,
        env=env,
    )
    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout: {stdout}\nstderr: {stderr}"
        )
    return result


def print_step(msg):
    print(f"[+] {msg}", flush=True)


def ensure_root():
    if os.geteuid() != 0:
        print("Please run as root")
        sys.exit(1)


def load_azfilesauth_config():
    if not AZFILESAUTH_CONFIG_PATH.exists():
        return {}
    with AZFILESAUTH_CONFIG_PATH.open("r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}
    if not isinstance(config, dict):
        raise ValueError("azfilesauth configuration root must be a mapping")
    return config


def get_cruid():
    user_uid = load_azfilesauth_config().get("USER_UID")
    if user_uid is not None:
        return str(user_uid)
    result = run_cmd(["id", "-u", "azfilesuser"], check=False)
    if result.returncode == 0:
        return result.stdout.strip()
    return str(os.getuid())


def get_ccache_name(cruid):
    ccache_name = load_azfilesauth_config().get("KRB5_CC_NAME")
    if ccache_name:
        return str(ccache_name)
    return f"FILE:/tmp/krb5cc_{cruid}"


def clear_credentials(endpoint):
    run_cmd(["azfilesauthmanager", "clear", endpoint], check=False)


def list_cifs_credentials():
    result = run_cmd(["azfilesauthmanager", "list", "--json"], check=True)
    payload = json.loads(result.stdout or "[]")
    return [c for c in payload if c.get("server", "").startswith("cifs")]


def extract_epoch(cred, field):
    value = cred.get(field, "")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        match = EPOCH_RE.search(value)
        if match:
            return int(match.group(1))
    return 0


def get_ticket_times(credentials, endpoint):
    hostname = urlparse(endpoint).hostname
    if not hostname:
        raise RuntimeError(f"Could not parse endpoint hostname: {endpoint}")

    server_prefix = f"cifs/{hostname}@"
    matching_times = []
    for credential in credentials:
        if credential.get("server", "").startswith(server_prefix):
            start_epoch = extract_epoch(credential, "ticket_start_time")
            end_epoch = extract_epoch(credential, "ticket_end_time")
            if start_epoch > 0 and end_epoch > 0:
                matching_times.append((start_epoch, end_epoch))

    if not matching_times:
        raise RuntimeError(f"Could not find parseable ticket times for {hostname}")
    return max(matching_times)


def verify_ticket_refreshed(before_times, after_times):
    before_start, before_end = before_times
    after_start, after_end = after_times
    if after_start <= before_start or after_end < before_end:
        raise RuntimeError(
            "Ticket was not refreshed: expected start time to advance and end time not to regress "
            f"(before={before_times}, after={after_times})"
        )


def set_credential(endpoint, mode, user_mi_client_id):
    if mode == "system":
        cmd = ["azfilesauthmanager", "set", endpoint, "--system"]
    elif mode == "user":
        cmd = ["azfilesauthmanager", "set", endpoint, "--imds-client-id", user_mi_client_id]
    else:
        raise ValueError(f"Unknown mode: {mode}")

    run_cmd(cmd, check=True)


def mount_share(storage_account, file_share, mount_point, username, cruid):
    unc = f"//{storage_account}.file.core.windows.net/{file_share}"
    mount_opts = f"sec=krb5,cruid={cruid},username={username}"
    result = run_cmd(
        ["mount", "-t", "cifs", unc, mount_point, "-o", mount_opts],
        check=False,
    )
    return result.returncode == 0, result


def unmount_if_mounted(mount_point):
    while True:
        result = run_cmd(["mount"], check=False)
        if mount_point not in (result.stdout or ""):
            return
        run_cmd(["umount", mount_point], check=False)
        time.sleep(1)


def manage_refresh_service(action):
    if shutil.which("systemctl"):
        run_cmd(["systemctl", action, "azfilesrefresh"], check=False)


def write_and_read_probe(mount_point, tag):
    probe_path = Path(mount_point) / f"azfiles_probe_{tag}.txt"
    payload = f"probe-{tag}-{int(time.time())}"
    probe_path.write_text(payload, encoding="utf-8")
    actual = probe_path.read_text(encoding="utf-8").strip()
    if actual != payload:
        raise RuntimeError("Mount accessibility check failed: probe content mismatch")


def scenario_authenticate(endpoint, mode, user_mi_client_id):
    print_step(f"Scenario 1 [{mode}] Authenticate token")
    clear_credentials(endpoint)
    set_credential(endpoint, mode, user_mi_client_id)
    creds = list_cifs_credentials()
    if not creds:
        raise RuntimeError(f"No CIFS credentials found after {mode} authentication")


def scenario_mount(endpoint, storage_account, file_share, mount_base, mode, user_mi_client_id, cruid):
    print_step(f"Scenario 2 [{mode}] Mount share and validate I/O")
    set_credential(endpoint, mode, user_mi_client_id)
    username = "root" if mode == "system" else user_mi_client_id
    mount_point = os.path.join(mount_base, f"{mode}_mount")
    os.makedirs(mount_point, exist_ok=True)
    unmount_if_mounted(mount_point)

    ok, result = mount_share(storage_account, file_share, mount_point, username, cruid)
    if not ok:
        raise RuntimeError(f"Mount failed for {mode}: {result.stderr}")

    try:
        write_and_read_probe(mount_point, f"mount-{mode}")
    finally:
        unmount_if_mounted(mount_point)
        clear_credentials(endpoint)


def scenario_expiry(endpoint, storage_account, file_share, mount_base, mode, user_mi_client_id, cruid):
    """Scenario 3: daemon detects a near-expiry ticket and refreshes it.

    The daemon's is_expiring() check is:
        (current_time + REFRESH_BEFORE_EXPIRY + SLEEP_TIME) >= ticket_end_time

    Setting AZFILES_REFRESH_BEFORE_EXPIRY_SECONDS to a value larger than the
    ticket's remaining lifetime (Azure Files tickets typically last ~1 h) makes
    the daemon treat the current ticket as about-to-expire without modifying
    the ccache.  An active CIFS mount is required because the daemon reads
    mount options to resolve which managed identity to use when refreshing.
    """
    print_step(f"Scenario 3 [{mode}] Daemon detects near-expiry ticket and refreshes it")

    set_credential(endpoint, mode, user_mi_client_id)

    creds_before = list_cifs_credentials()
    if not creds_before:
        raise RuntimeError("No CIFS credentials found after authentication")
    before_times = get_ticket_times(creds_before, endpoint)

    username = "root" if mode == "system" else user_mi_client_id
    mount_point = os.path.join(mount_base, f"{mode}_expiry")
    os.makedirs(mount_point, exist_ok=True)
    unmount_if_mounted(mount_point)

    ok, result = mount_share(storage_account, file_share, mount_point, username, cruid)
    if not ok:
        raise RuntimeError(f"Mount failed before daemon refresh test: {result.stderr}")

    # Stop the systemd service to avoid running two concurrent daemon instances.
    # The service uses default REFRESH_BEFORE_EXPIRY (5 min) which would not
    # refresh a freshly obtained ticket; we need env-var overrides to force it.
    manage_refresh_service("stop")
    try:
        # AZFILES_REFRESH_BEFORE_EXPIRY_SECONDS > ticket remaining lifetime forces
        # is_expiring() to True so the daemon fetches a fresh ticket.
        daemon_env = os.environ.copy()
        daemon_env["AZFILES_REFRESH_SLEEP_SECONDS"] = "5"
        daemon_env["AZFILES_REFRESH_BEFORE_EXPIRY_SECONDS"] = "86400"

        daemon = run_cmd(
            ["timeout", "20", "azfilesrefresh"],
            check=False,
            capture=True,
            env=daemon_env,
        )
        if daemon.returncode not in (0, 124):
            raise RuntimeError(
                f"azfilesrefresh run failed ({daemon.returncode})\n"
                f"stdout: {daemon.stdout}\nstderr: {daemon.stderr}"
            )

        creds_after = list_cifs_credentials()
        if not creds_after:
            raise RuntimeError("Credentials missing after daemon run")
        after_times = get_ticket_times(creds_after, endpoint)
        verify_ticket_refreshed(before_times, after_times)
    finally:
        manage_refresh_service("start")
        unmount_if_mounted(mount_point)
        clear_credentials(endpoint)


def scenario_daemon_refresh(endpoint, storage_account, file_share, mount_base, mode, user_mi_client_id, cruid):
    print_step(f"Scenario 4 [{mode}] Run daemon refresh cycle and verify mount remains accessible")
    set_credential(endpoint, mode, user_mi_client_id)
    creds_before = list_cifs_credentials()
    if not creds_before:
        raise RuntimeError("No credentials present before daemon refresh")

    before_times = get_ticket_times(creds_before, endpoint)
    username = "root" if mode == "system" else user_mi_client_id
    mount_point = os.path.join(mount_base, f"{mode}_daemon")
    os.makedirs(mount_point, exist_ok=True)
    unmount_if_mounted(mount_point)

    ok, result = mount_share(storage_account, file_share, mount_point, username, cruid)
    if not ok:
        raise RuntimeError(f"Mount failed before daemon refresh: {result.stderr}")

    manage_refresh_service("stop")
    try:
        write_and_read_probe(mount_point, f"pre-daemon-{mode}")

        daemon_env = os.environ.copy()
        daemon_env["AZFILES_REFRESH_SLEEP_SECONDS"] = "5"
        daemon_env["AZFILES_REFRESH_BEFORE_EXPIRY_SECONDS"] = "86400"

        daemon = run_cmd(
            ["timeout", "20", "azfilesrefresh"],
            check=False,
            capture=True,
            env=daemon_env,
        )
        if daemon.returncode not in (0, 124):
            raise RuntimeError(
                f"azfilesrefresh run failed ({daemon.returncode})\n"
                f"stdout: {daemon.stdout}\nstderr: {daemon.stderr}"
            )

        creds_after = list_cifs_credentials()
        if not creds_after:
            raise RuntimeError("No credentials present after daemon refresh")
        after_times = get_ticket_times(creds_after, endpoint)
        verify_ticket_refreshed(before_times, after_times)

        write_and_read_probe(mount_point, f"post-daemon-{mode}")
    finally:
        manage_refresh_service("start")
        unmount_if_mounted(mount_point)
        clear_credentials(endpoint)


def run_mode(endpoint, storage_account, file_share, mount_base, mode, user_mi_client_id, cruid):
    scenario_authenticate(endpoint, mode, user_mi_client_id)
    scenario_mount(endpoint, storage_account, file_share, mount_base, mode, user_mi_client_id, cruid)
    scenario_expiry(endpoint, storage_account, file_share, mount_base, mode, user_mi_client_id, cruid)
    scenario_daemon_refresh(endpoint, storage_account, file_share, mount_base, mode, user_mi_client_id, cruid)


def main():
    parser = argparse.ArgumentParser(description="Managed identity lifecycle scenarios")
    parser.add_argument("endpoint", help="File endpoint URI, e.g. https://<storage>.file.core.windows.net")
    parser.add_argument("--storage-account", default=os.environ.get("STORAGE_ACCOUNT"), help="Storage account name")
    parser.add_argument("--file-share", default=os.environ.get("FILE_SHARE", "testshare"), help="File share name")
    parser.add_argument("--mount-base", default=os.environ.get("MOUNT_BASE", "/mnt/azfiles_test"), help="Base mount directory")
    parser.add_argument("--user-mi-client-id", default=os.environ.get("USER_MI_CLIENT_ID"), help="User-assigned MI client ID")
    args = parser.parse_args()

    ensure_root()

    if not args.storage_account:
        print("Missing storage account. Set --storage-account or STORAGE_ACCOUNT.")
        sys.exit(1)

    os.makedirs(args.mount_base, exist_ok=True)
    cruid = get_cruid()

    modes = ["system"]
    if args.user_mi_client_id:
        modes.append("user")
    else:
        print("[!] USER_MI_CLIENT_ID not set; user-assigned MI scenarios will be skipped", flush=True)

    for mode in modes:
        run_mode(
            args.endpoint,
            args.storage_account,
            args.file_share,
            args.mount_base,
            mode,
            args.user_mi_client_id,
            cruid,
        )

    print("\n[+] Managed identity lifecycle scenarios PASSED", flush=True)


if __name__ == "__main__":
    main()
