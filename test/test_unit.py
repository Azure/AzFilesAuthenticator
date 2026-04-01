#!/usr/bin/env python3
"""
Unit tests for azfilesauthmanager.py and azfilesrefresh.py.in.

These tests mock external dependencies (native lib, IMDS, HTTP, subprocess,
filesystem) so they can run anywhere — no Azure endpoint, no root, no
libazfilesauth.so required.

Run:
    python3 test/test_unit.py            # verbose
    python3 -m pytest test/test_unit.py  # if pytest is available

Exit code 0 = all passed, 1 = failures found.
"""

import ast
import importlib
import importlib.util
import json
import os
import re
import signal
import sys
import textwrap
import time
import types
import unittest
from unittest import mock

# ---------------------------------------------------------------------------
# Helpers to import src modules with mocked native dependencies
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(REPO_ROOT, "src")


def _strip_autoconf(source: str) -> str:
    """Replace @VAR@ placeholders used in .py.in files."""
    source = re.sub(r'"@\w+@"', '"/dev/null"', source)
    source = re.sub(r"'@\w+@'", '"/dev/null"', source)
    source = re.sub(r"@\w+@", '"/dev/null"', source)
    return source


def _load_module_from_source(name: str, path: str, pre_patch=None):
    """Load a Python module from *path*, optionally applying *pre_patch*
    (a dict of ``sys.modules`` entries) before exec so that imports inside the
    module resolve to mocks."""
    with open(path) as f:
        source = f.read()
    source = _strip_autoconf(source)

    spec = importlib.util.spec_from_loader(name, loader=None)
    mod = importlib.util.module_from_spec(spec)

    saved = {}
    if pre_patch:
        for k, v in pre_patch.items():
            saved[k] = sys.modules.get(k)
            sys.modules[k] = v

    # Compile and exec inside the module's namespace
    code = compile(source, path, "exec")
    exec(code, mod.__dict__)

    # Restore sys.modules
    for k in saved:
        if saved[k] is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = saved[k]

    return mod


# ---------------------------------------------------------------------------
# Build a fake ctypes lib that the manager module uses at import time
# ---------------------------------------------------------------------------

def _make_fake_lib():
    """Return a mock object that looks enough like ctypes.CDLL(libazfilesauth)."""
    lib = mock.MagicMock()
    lib.extern_smb_set_credential_oauth_token.return_value = 0
    lib.extern_smb_clear_credential.return_value = 0
    lib.extern_smb_list_credential.return_value = 0
    lib.extern_smb_version.return_value = b"1.0-test"
    return lib


_real_os_path_exists = os.path.exists

def _load_manager(fake_lib=None, config_content="KRB5_CC_NAME: /tmp/krb5cc_test\n"):
    """Import azfilesauthmanager.py with all native/OS deps mocked out."""
    if fake_lib is None:
        fake_lib = _make_fake_lib()

    manager_path = os.path.join(SRC_DIR, "azfilesauthmanager.py")
    with open(manager_path) as f:
        source = f.read()

    mod = types.ModuleType("azfilesauthmanager")
    mod.__file__ = manager_path
    mod.__builtins__ = __builtins__

    ns = dict(mod.__dict__)
    ns["__name__"] = "azfilesauthmanager"

    with mock.patch("os.path.exists", side_effect=lambda p: True if p == "/usr/lib/libazfilesauth.so" else _real_os_path_exists(p)):
        with mock.patch("ctypes.CDLL", return_value=fake_lib):
            code = compile(source, manager_path, "exec")
            exec(code, ns)

    # Copy all defined names back onto the module
    for k, v in ns.items():
        if not k.startswith("__"):
            setattr(mod, k, v)

    mod.lib = fake_lib
    return mod


# ---------------------------------------------------------------------------
# Load azfilesrefresh.py.in
# ---------------------------------------------------------------------------

def _load_refresh():
    """Import azfilesrefresh.py.in with deps mocked."""
    refresh_path = os.path.join(SRC_DIR, "azfilesrefresh.py.in")
    with open(refresh_path) as f:
        source = f.read()
    source = _strip_autoconf(source)

    # Build a fake 'azfilesauth' module that provides the names refresh imports
    fake_azfilesauth = types.ModuleType("azfilesauth")
    fake_azfilesauth.azfiles_set_oauth = mock.MagicMock()
    fake_azfilesauth.get_oauth_token = mock.MagicMock(return_value="fake-token-123")
    fake_azfilesauth.init_new_user = mock.MagicMock()

    pre_patch = {"azfilesauth": fake_azfilesauth}

    # Redirect logging to a temp file or NullHandler so tests don't need /var/log access
    import logging as _logging
    _orig_basicConfig = _logging.basicConfig
    def _patched_basicConfig(**kwargs):
        kwargs.pop("filename", None)
        kwargs.pop("filemode", None)
        kwargs["handlers"] = [_logging.NullHandler()]
        _orig_basicConfig(**kwargs)
    with mock.patch("logging.basicConfig", side_effect=_patched_basicConfig):
        mod = _load_module_from_source("azfilesrefresh", refresh_path, pre_patch=pre_patch)
    mod._fake_azfilesauth = fake_azfilesauth
    return mod


# ===================================================================
# Test: azfilesauthmanager.py — token acquisition logic
# ===================================================================

class TestGetOauthToken(unittest.TestCase):
    """Test get_oauth_token() for both system and user-assigned MI."""

    def setUp(self):
        self.mod = _load_manager()

    @mock.patch("requests.get")
    def test_system_assigned_returns_token(self, mock_get):
        mock_get.return_value = mock.MagicMock(
            status_code=200,
            json=lambda: {"access_token": "sys-tok-abc"},
        )
        mock_get.return_value.raise_for_status = mock.MagicMock()

        # Rebind requests inside module
        self.mod.requests = mock.MagicMock()
        self.mod.requests.get = mock_get

        token = self.mod.get_oauth_token()
        self.assertEqual(token, "sys-tok-abc")

        # Verify IMDS was called without client_id
        call_url = mock_get.call_args[0][0]
        self.assertIn("169.254.169.254", call_url)
        self.assertNotIn("client_id", call_url)

    @mock.patch("requests.get")
    def test_user_assigned_passes_client_id(self, mock_get):
        mock_get.return_value = mock.MagicMock(
            status_code=200,
            json=lambda: {"access_token": "user-tok-xyz"},
        )
        mock_get.return_value.raise_for_status = mock.MagicMock()

        self.mod.requests = mock.MagicMock()
        self.mod.requests.get = mock_get

        token = self.mod.get_oauth_token("my-client-id")
        self.assertEqual(token, "user-tok-xyz")

        call_url = mock_get.call_args[0][0]
        self.assertIn("client_id=my-client-id", call_url)

    @mock.patch("requests.get")
    def test_missing_access_token_returns_none(self, mock_get):
        mock_get.return_value = mock.MagicMock(
            status_code=200,
            json=lambda: {"something_else": "oops"},
        )
        mock_get.return_value.raise_for_status = mock.MagicMock()

        self.mod.requests = mock.MagicMock()
        self.mod.requests.get = mock_get

        token = self.mod.get_oauth_token()
        self.assertIsNone(token)

    @mock.patch("requests.get", side_effect=Exception("network down"))
    def test_request_failure_returns_none(self, mock_get):
        self.mod.requests = mock.MagicMock()
        self.mod.requests.get = mock_get

        token = self.mod.get_oauth_token()
        self.assertIsNone(token)


# ===================================================================
# Test: azfilesauthmanager.py — workload identity token
# ===================================================================

class TestGetWorkloadIdentityToken(unittest.TestCase):

    def setUp(self):
        self.mod = _load_manager()

    def test_missing_params_returns_none(self):
        self.assertIsNone(self.mod.get_workload_identity_token(None, "cid", "/tok"))
        self.assertIsNone(self.mod.get_workload_identity_token("tid", None, "/tok"))
        self.assertIsNone(self.mod.get_workload_identity_token("tid", "cid", None))

    @mock.patch("builtins.open", mock.mock_open(read_data="jwt-assertion-data"))
    @mock.patch("requests.post")
    def test_successful_token_fetch(self, mock_post):
        mock_post.return_value = mock.MagicMock(
            status_code=200,
            json=lambda: {"access_token": "wi-token-123"},
        )
        mock_post.return_value.raise_for_status = mock.MagicMock()

        self.mod.requests = mock.MagicMock()
        self.mod.requests.post = mock_post

        token = self.mod.get_workload_identity_token("tenant-1", "client-1", "/tok")
        self.assertEqual(token, "wi-token-123")

        # Verify the AAD URL contains the tenant
        call_url = mock_post.call_args[0][0]
        self.assertIn("tenant-1", call_url)

        # Verify the POST body
        call_data = mock_post.call_args[1].get("data") or mock_post.call_args[0][2] if len(mock_post.call_args[0]) > 2 else mock_post.call_args[1].get("data")
        self.assertEqual(call_data["client_id"], "client-1")
        self.assertEqual(call_data["client_assertion"], "jwt-assertion-data")


# ===================================================================
# Test: azfilesauthmanager.py — native lib wrappers
# ===================================================================

class TestAzfilesSetOauth(unittest.TestCase):
    """Verify azfiles_set_oauth calls the C library correctly."""

    def test_set_calls_lib(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        mod.azfiles_set_oauth("https://myaccount.file.core.windows.net", "tok-123")

        fake_lib.extern_smb_set_credential_oauth_token.assert_called_once()
        args = fake_lib.extern_smb_set_credential_oauth_token.call_args[0]
        self.assertEqual(args[0], b"https://myaccount.file.core.windows.net")
        self.assertEqual(args[1], b"tok-123")

    def test_set_nonzero_rc_exits(self):
        fake_lib = _make_fake_lib()
        fake_lib.extern_smb_set_credential_oauth_token.return_value = -1
        mod = _load_manager(fake_lib)

        with self.assertRaises(SystemExit):
            mod.azfiles_set_oauth("https://myaccount.file.core.windows.net", "tok-123")


class TestAzfilesClear(unittest.TestCase):

    def test_clear_calls_lib(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        mod.azfiles_clear("https://myaccount.file.core.windows.net")

        fake_lib.extern_smb_clear_credential.assert_called_once()

    def test_clear_nonzero_rc_exits(self):
        fake_lib = _make_fake_lib()
        fake_lib.extern_smb_clear_credential.return_value = -1
        mod = _load_manager(fake_lib)

        with self.assertRaises(SystemExit):
            mod.azfiles_clear("https://myaccount.file.core.windows.net")


class TestAzfilesList(unittest.TestCase):

    def test_list_plain(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)
        mod.azfiles_list(False)
        fake_lib.extern_smb_list_credential.assert_called_once_with(False)

    def test_list_json(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)
        mod.azfiles_list(True)
        fake_lib.extern_smb_list_credential.assert_called_once_with(True)

    def test_list_nonzero_rc_exits(self):
        fake_lib = _make_fake_lib()
        fake_lib.extern_smb_list_credential.return_value = 2
        mod = _load_manager(fake_lib)

        with self.assertRaises(SystemExit) as ctx:
            mod.azfiles_list(False)
        self.assertEqual(ctx.exception.code, 2)


# ===================================================================
# Test: azfilesrefresh.py.in — ticket expiry logic
# ===================================================================

class TestIsExpiring(unittest.TestCase):
    """Test the is_expiring() function which decides if a ticket needs refresh."""

    def setUp(self):
        self.mod = _load_refresh()

    def test_ticket_far_from_expiry(self):
        """Ticket that expires 30 min from now should NOT be expiring."""
        future = int(time.time()) + 30 * 60
        ticket = {"ticket_end_time": f"01/15/25 04:28:48 UTC (epoch: {future})"}
        self.assertFalse(self.mod.is_expiring(ticket))

    def test_ticket_about_to_expire(self):
        """Ticket that expires in 2 minutes should be expiring (within REFRESH_BEFORE_EXPIRY + SLEEP_TIME)."""
        soon = int(time.time()) + 2 * 60
        ticket = {"ticket_end_time": f"01/15/25 04:28:48 UTC (epoch: {soon})"}
        self.assertTrue(self.mod.is_expiring(ticket))

    def test_ticket_already_expired(self):
        past = int(time.time()) - 60
        ticket = {"ticket_end_time": f"01/15/25 04:28:48 UTC (epoch: {past})"}
        self.assertTrue(self.mod.is_expiring(ticket))

    def test_missing_end_time_forces_refresh(self):
        ticket = {"ticket_end_time": ""}
        self.assertTrue(self.mod.is_expiring(ticket))

    def test_unparsable_end_time_forces_refresh(self):
        ticket = {"ticket_end_time": "garbage data no epoch"}
        self.assertTrue(self.mod.is_expiring(ticket))

    def test_no_end_time_key_forces_refresh(self):
        ticket = {}
        self.assertTrue(self.mod.is_expiring(ticket))


# ===================================================================
# Test: azfilesrefresh.py.in — endpoint extraction from principal
# ===================================================================

class TestGetEndpointFromPrincipal(unittest.TestCase):

    def setUp(self):
        self.mod = _load_refresh()

    def test_cifs_prefix(self):
        result = self.mod.get_endpoint_from_principal("cifs/myaccount.file.core.windows.net@STORAGE.AZURE.NET")
        self.assertEqual(result, "myaccount.file.core.windows.net")

    def test_https_prefix(self):
        result = self.mod.get_endpoint_from_principal("https://myaccount.file.core.windows.net@STORAGE.AZURE.NET")
        self.assertEqual(result, "myaccount.file.core.windows.net")

    def test_unknown_prefix_returns_empty(self):
        result = self.mod.get_endpoint_from_principal("nfs/myaccount@REALM")
        self.assertEqual(result, "")


# ===================================================================
# Test: azfilesrefresh.py.in — mount option parsing
# ===================================================================

class TestGetMountOptions(unittest.TestCase):

    def setUp(self):
        self.mod = _load_refresh()

    @mock.patch("subprocess.run")
    def test_parses_krb5_mounts(self, mock_run):
        mount_output = (
            "//myaccount.file.core.windows.net/share on /mnt/azure type cifs "
            "(rw,relatime,sec=krb5,username=adb3f02b-6844-1234-8ddd-abcdef123456,uid=0)\n"
            "//other.file.core.windows.net/share2 on /mnt/other type cifs "
            "(rw,relatime,sec=ntlmssp,username=someuser,uid=0)\n"
        )
        mock_run.return_value = mock.MagicMock(
            stdout=mount_output.encode("utf-8"),
            stderr=b"",
        )

        id_map = self.mod.get_mount_options()
        # Only the krb5 mount should be included
        self.assertIn("myaccount.file.core.windows.net", id_map)
        self.assertEqual(id_map["myaccount.file.core.windows.net"], "adb3f02b-6844-1234-8ddd-abcdef123456")
        self.assertNotIn("other.file.core.windows.net", id_map)

    @mock.patch("subprocess.run")
    def test_root_username_detected(self, mock_run):
        mount_output = (
            "//sys.file.core.windows.net/share on /mnt/sys type cifs "
            "(rw,sec=krb5,username=root,uid=0)\n"
        )
        mock_run.return_value = mock.MagicMock(
            stdout=mount_output.encode("utf-8"),
            stderr=b"",
        )

        id_map = self.mod.get_mount_options()
        self.assertEqual(id_map["sys.file.core.windows.net"], "root")

    @mock.patch("subprocess.run")
    def test_no_cifs_mounts_returns_empty(self, mock_run):
        mock_run.return_value = mock.MagicMock(stdout=b"", stderr=b"")
        id_map = self.mod.get_mount_options()
        self.assertEqual(id_map, {})


# ===================================================================
# Test: azfilesrefresh.py.in — refresh_ticket dispatch
# ===================================================================

class TestRefreshTicket(unittest.TestCase):

    def setUp(self):
        self.mod = _load_refresh()

    @mock.patch("subprocess.run")
    def test_refresh_uses_system_mi_for_root_username(self, mock_run):
        mount_output = (
            "//account.file.core.windows.net/share on /mnt type cifs "
            "(rw,sec=krb5,username=root,uid=0)\n"
        )
        mock_run.return_value = mock.MagicMock(
            stdout=mount_output.encode("utf-8"),
            stderr=b"",
        )

        self.mod._fake_azfilesauth.get_oauth_token.return_value = "system-token"
        self.mod._fake_azfilesauth.azfiles_set_oauth.reset_mock()
        self.mod._fake_azfilesauth.get_oauth_token.reset_mock()

        ticket = {"server": "cifs/account.file.core.windows.net@REALM"}
        self.mod.refresh_ticket(ticket)

        # Should call get_oauth_token with no args (system MI)
        self.mod._fake_azfilesauth.get_oauth_token.assert_called_once_with()
        self.mod._fake_azfilesauth.azfiles_set_oauth.assert_called_once_with(
            "https://account.file.core.windows.net", "system-token"
        )

    @mock.patch("subprocess.run")
    def test_refresh_uses_user_mi_for_client_id_username(self, mock_run):
        mount_output = (
            "//account.file.core.windows.net/share on /mnt type cifs "
            "(rw,sec=krb5,username=my-client-id,uid=0)\n"
        )
        mock_run.return_value = mock.MagicMock(
            stdout=mount_output.encode("utf-8"),
            stderr=b"",
        )

        self.mod._fake_azfilesauth.get_oauth_token.return_value = "user-token"
        self.mod._fake_azfilesauth.azfiles_set_oauth.reset_mock()
        self.mod._fake_azfilesauth.get_oauth_token.reset_mock()

        ticket = {"server": "cifs/account.file.core.windows.net@REALM"}
        self.mod.refresh_ticket(ticket)

        # Should call get_oauth_token with the client_id
        self.mod._fake_azfilesauth.get_oauth_token.assert_called_once_with("my-client-id")


# ===================================================================
# Test: azfilesrefresh.py.in — epoch parsing
# ===================================================================

class TestParseEpoch(unittest.TestCase):

    def setUp(self):
        self.mod = _load_refresh()

    def test_standard_format(self):
        self.assertEqual(self.mod._parse_epoch("01/15/25 04:28:48 UTC (epoch: 1736916528)"), 1736916528)

    def test_no_epoch(self):
        self.assertEqual(self.mod._parse_epoch("01/15/25 04:28:48 UTC"), 0)

    def test_empty_string(self):
        self.assertEqual(self.mod._parse_epoch(""), 0)

    def test_none_input(self):
        self.assertEqual(self.mod._parse_epoch(None), 0)


# ===================================================================
# Test: CLI argument parsing (azfilesauthmanager)
# ===================================================================

class TestCLIArgParsing(unittest.TestCase):
    """Verify run_azfilesauthmanager() correctly routes commands."""

    def _make_mod(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)
        mod.fake_lib = fake_lib
        return mod

    def _run_cli(self, argv, fake_lib=None):
        """Load manager module, then patch open/os/subprocess for CLI routing."""
        if fake_lib is None:
            fake_lib = _make_fake_lib()
        # Load module first (needs real filesystem)
        mod = _load_manager(fake_lib)

        config_data = "KRB5_CC_NAME: /tmp/krb5cc_test\nUSER_UID: 1000\n"
        real_open = open
        def _mock_open_fn(path, *a, **kw):
            if isinstance(path, str) and path == "/etc/azfilesauth/config.yaml":
                return mock.mock_open(read_data=config_data)()
            return real_open(path, *a, **kw)

        with mock.patch("builtins.open", side_effect=_mock_open_fn):
            with mock.patch("os.system", return_value=0):
                with mock.patch("subprocess.check_output", return_value=b"1000"):
                    with mock.patch("pwd.getpwuid", return_value=mock.MagicMock()):
                        saved_argv = sys.argv
                        try:
                            sys.argv = argv
                            mod.run_azfilesauthmanager()
                        finally:
                            sys.argv = saved_argv
        return fake_lib

    def test_no_args_prints_usage_and_exits(self):
        with self.assertRaises(SystemExit):
            self._run_cli(["azfilesauthmanager"])

    def test_list_command_calls_lib(self):
        fake_lib = _make_fake_lib()
        try:
            self._run_cli(["azfilesauthmanager", "list"], fake_lib)
        except SystemExit:
            pass
        fake_lib.extern_smb_list_credential.assert_called()

    def test_clear_command_calls_lib(self):
        fake_lib = _make_fake_lib()
        try:
            self._run_cli(["azfilesauthmanager", "clear", "https://account.file.core.windows.net"], fake_lib)
        except SystemExit:
            pass
        fake_lib.extern_smb_clear_credential.assert_called()

    def test_set_direct_token(self):
        fake_lib = _make_fake_lib()
        try:
            self._run_cli(["azfilesauthmanager", "set", "https://account.file.core.windows.net", "my-direct-token"], fake_lib)
        except SystemExit:
            pass
        fake_lib.extern_smb_set_credential_oauth_token.assert_called_once()
        args = fake_lib.extern_smb_set_credential_oauth_token.call_args[0]
        self.assertEqual(args[0], b"https://account.file.core.windows.net")
        self.assertEqual(args[1], b"my-direct-token")


# ===================================================================
# Test: azfilesrefresh.py.in — get_tickets JSON parsing
# ===================================================================

class TestGetTickets(unittest.TestCase):

    def setUp(self):
        self.mod = _load_refresh()

    @mock.patch("subprocess.run")
    def test_parses_json_tickets(self, mock_run):
        tickets_json = json.dumps([
            {
                "server": "cifs/account.file.core.windows.net@REALM",
                "client": "AzureFileClient",
                "realm": "REALM",
                "ticket_flags": 1234,
                "ticket_start_time": "01/15/25 04:28:48 UTC (epoch: 1736916528)",
                "ticket_end_time": "01/15/25 05:12:58 UTC (epoch: 1736919178)",
                "ticket_renew_till": "N/A (epoch: 0)",
            }
        ])
        mock_run.return_value = mock.MagicMock(
            stdout=tickets_json.encode("utf-8"),
            returncode=0,
        )

        tickets = self.mod.get_tickets()
        self.assertEqual(len(tickets), 1)
        self.assertEqual(tickets[0]["server"], "cifs/account.file.core.windows.net@REALM")

    @mock.patch("subprocess.run")
    def test_handles_empty_output(self, mock_run):
        import subprocess as sp
        mock_run.side_effect = sp.CalledProcessError(1, "cmd", stderr=b"error")
        tickets = self.mod.get_tickets()
        self.assertEqual(tickets, [])


# ===================================================================
# Test: azfilesrefresh.py.in — start_daemon orchestration loop
# ===================================================================

class TestStartDaemon(unittest.TestCase):
    """Verify start_daemon() ties get_tickets, is_expiring, and refresh_ticket
    together correctly."""

    def setUp(self):
        self.mod = _load_refresh()

    def _run_one_iteration(self, tickets):
        """Run start_daemon() for exactly one loop iteration, returning
        a mock for refresh_ticket so callers can inspect what was refreshed."""
        # Stop the loop after one iteration by flipping RUNNING on the first sleep
        def _stop_loop(secs):
            self.mod.RUNNING = False

        with mock.patch.object(self.mod, "get_tickets", return_value=tickets), \
             mock.patch.object(self.mod, "refresh_ticket") as mock_refresh, \
             mock.patch.object(self.mod, "init_new_user"), \
             mock.patch("time.sleep", side_effect=_stop_loop):
            self.mod.RUNNING = True
            self.mod.start_daemon()

        return mock_refresh

    def test_only_expiring_tickets_are_refreshed(self):
        """Given 3 tickets where only ticket-B is expiring, only ticket-B
        should be passed to refresh_ticket."""
        far_future = int(time.time()) + 60 * 60   # 1 hour out
        almost_now = int(time.time()) + 60         # 1 min out

        ticket_a = {"server": "cifs/a.file.core.windows.net@REALM",
                     "ticket_end_time": f"(epoch: {far_future})"}
        ticket_b = {"server": "cifs/b.file.core.windows.net@REALM",
                     "ticket_end_time": f"(epoch: {almost_now})"}
        ticket_c = {"server": "cifs/c.file.core.windows.net@REALM",
                     "ticket_end_time": f"(epoch: {far_future})"}

        mock_refresh = self._run_one_iteration([ticket_a, ticket_b, ticket_c])

        mock_refresh.assert_called_once_with(ticket_b)

    def test_no_tickets_means_no_refresh(self):
        """Empty ticket list should not call refresh_ticket at all."""
        mock_refresh = self._run_one_iteration([])
        mock_refresh.assert_not_called()

    def test_all_expiring_tickets_refreshed(self):
        """When all tickets are expiring, every one of them gets refreshed."""
        soon = int(time.time()) + 30

        ticket_x = {"server": "cifs/x.file.core.windows.net@REALM",
                     "ticket_end_time": f"(epoch: {soon})"}
        ticket_y = {"server": "cifs/y.file.core.windows.net@REALM",
                     "ticket_end_time": f"(epoch: {soon})"}

        mock_refresh = self._run_one_iteration([ticket_x, ticket_y])

        self.assertEqual(mock_refresh.call_count, 2)
        mock_refresh.assert_any_call(ticket_x)
        mock_refresh.assert_any_call(ticket_y)

    def test_no_expiring_tickets_skips_refresh(self):
        """When no tickets are near expiry, refresh_ticket is never called."""
        far = int(time.time()) + 60 * 60

        ticket = {"server": "cifs/safe.file.core.windows.net@REALM",
                  "ticket_end_time": f"(epoch: {far})"}

        mock_refresh = self._run_one_iteration([ticket])
        mock_refresh.assert_not_called()


# ===================================================================
# Main
# ===================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
