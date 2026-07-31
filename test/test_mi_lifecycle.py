#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

EPOCH_RE = re.compile(r"\(epoch:\s*(\d+)\)")


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


def get_cruid():
    config_path = Path("/etc/azfilesauth/config.yaml")
    if config_path.exists():
        for line in config_path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("USER_UID:"):
                return line.split(":", 1)[1].strip()
    result = run_cmd(["id", "-u", "azfilesuser"], check=False)
    if result.returncode == 0:
        return result.stdout.strip()
    return str(os.getuid())


def get_ccache_name(cruid):
    config_path = Path("/etc/azfilesauth/config.yaml")
    if config_path.exists():
        for line in config_path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("KRB5_CC_NAME:"):
                value = line.split(":", 1)[1].strip()
                if value:
                    return value
    return f"FILE:/tmp/krb5cc_{cruid}"


def clear_credentials(endpoint):
    run_cmd(["azfilesauthmanager", "clear", endpoint], check=False)


def list_cifs_credentials():
    result = run_cmd(["azfilesauthmanager", "list", "--json"], check=True)
    payload = json.loads(result.stdout or "[]")
    return [c for c in payload if c.get("server", "").startswith("cifs")]


def extract_ticket_epoch(cred):
    if isinstance(cred.get("ticket_renew_till"), int):
        return cred["ticket_renew_till"]

    end_time = cred.get("ticket_end_time", "")
    if end_time:
        m = EPOCH_RE.search(end_time)
        if m:
            return int(m.group(1))

    renew_till = cred.get("ticket_renew_till", "")
    if isinstance(renew_till, str):
        m = EPOCH_RE.search(renew_till)
        if m:
            return int(m.group(1))

    return 0


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
    before_epoch = max(extract_ticket_epoch(c) for c in creds_before)
    if before_epoch == 0:
        raise RuntimeError("Could not parse ticket end_time epoch before daemon run")

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
    run_cmd(["systemctl", "stop", "azfilesrefresh"], check=False)
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
        after_epoch = max(extract_ticket_epoch(c) for c in creds_after)
        if after_epoch == 0:
            raise RuntimeError("Could not parse ticket end_time epoch after daemon run")

        if after_epoch < before_epoch:
            raise RuntimeError(
                f"Ticket end_time regressed after daemon refresh "
                f"(before={before_epoch}, after={after_epoch})"
            )
    finally:
        run_cmd(["systemctl", "start", "azfilesrefresh"], check=False)
        unmount_if_mounted(mount_point)
        clear_credentials(endpoint)


def scenario_daemon_refresh(endpoint, storage_account, file_share, mount_base, mode, user_mi_client_id, cruid):
    print_step(f"Scenario 4 [{mode}] Run daemon refresh cycle and verify mount remains accessible")
    set_credential(endpoint, mode, user_mi_client_id)
    creds_before = list_cifs_credentials()
    if not creds_before:
        raise RuntimeError("No credentials present before daemon refresh")

    before_epoch = max(extract_ticket_epoch(c) for c in creds_before)
    username = "root" if mode == "system" else user_mi_client_id
    mount_point = os.path.join(mount_base, f"{mode}_daemon")
    os.makedirs(mount_point, exist_ok=True)
    unmount_if_mounted(mount_point)

    ok, result = mount_share(storage_account, file_share, mount_point, username, cruid)
    if not ok:
        raise RuntimeError(f"Mount failed before daemon refresh: {result.stderr}")

    run_cmd(["systemctl", "stop", "azfilesrefresh"], check=False)
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
        after_epoch = max(extract_ticket_epoch(c) for c in creds_after)

        if before_epoch > 0 and after_epoch > 0 and after_epoch < before_epoch:
            raise RuntimeError(
                f"Ticket epoch regressed after daemon refresh ({after_epoch} < {before_epoch})"
            )

        write_and_read_probe(mount_point, f"post-daemon-{mode}")
    finally:
        run_cmd(["systemctl", "start", "azfilesrefresh"], check=False)
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
