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
import contextlib
import importlib
import importlib.util
import fcntl
import json
import os
import re
import signal
import stat
import sys
import tempfile
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
    fake_azfilesauth.get_workload_identity_token = mock.MagicMock(return_value="fake-workload-token-123")
    fake_azfilesauth.get_endpoint_auth_metadata = mock.MagicMock(return_value=None)
    fake_azfilesauth.init_new_user = mock.MagicMock()

    class _FakeAuthMetadataConflict(Exception):
        pass

    fake_azfilesauth.AuthMetadataConflict = _FakeAuthMetadataConflict

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


@contextlib.contextmanager
def _temp_auth_state(mod):
    """Point mod's AUTH_STATE_DIR/AUTH_STATE_FILE_PATH at a throwaway temp dir so
    lock-holding code paths (azfiles_set_oauth/azfiles_clear/azfiles_list) don't
    touch the real /run/azfilesauth in tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        state_dir = os.path.join(temp_dir, "run", "azfilesauth")
        state_file = os.path.join(state_dir, "endpoint-auth-state.json")
        with mock.patch.dict(
            mod.get_endpoint_auth_metadata.__globals__,
            {"AUTH_STATE_DIR": state_dir, "AUTH_STATE_FILE_PATH": state_file},
        ):
            yield state_dir, state_file


# ===================================================================
# Test: azfilesauthmanager.py — YAML configuration
# ===================================================================

class TestYamlConfig(unittest.TestCase):

    def setUp(self):
        self.mod = _load_manager()

    def test_config_round_trip_preserves_nested_mappings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as config_file:
                config_file.write(
                    "ENVIRONMENT:\n"
                    "  MSI_ENDPOINT: http://localhost/token\n"
                    "KRB5_CC_NAME: FILE:/tmp/krb5cc_1000\n"
                )
            os.chmod(config_path, 0o666)

            with mock.patch.dict(
                self.mod.load_config.__globals__,
                {"CONFIG_FILE_PATH": config_path},
            ), mock.patch("os.chown") as mock_chown, mock.patch("os.chmod") as mock_chmod:
                config = self.mod.load_config()
                config["USER_UID"] = 1000
                self.mod.save_config(config)
                saved_config = self.mod.load_config()
                saved_mode = stat.S_IMODE(os.stat(config_path).st_mode)

        self.assertEqual(saved_config["ENVIRONMENT"]["MSI_ENDPOINT"], "http://localhost/token")
        self.assertEqual(saved_config["KRB5_CC_NAME"], "FILE:/tmp/krb5cc_1000")
        self.assertEqual(saved_config["USER_UID"], 1000)
        self.assertEqual(saved_mode, 0o666)
        mock_chown.assert_not_called()
        mock_chmod.assert_not_called()

    def test_save_config_secures_new_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.yaml")
            with mock.patch.dict(
                self.mod.save_config.__globals__,
                {"CONFIG_FILE_PATH": config_path},
            ), mock.patch("os.chown") as mock_chown, mock.patch("os.chmod") as mock_chmod:
                self.mod.save_config({"USER_UID": 1000})
                saved_mode = stat.S_IMODE(os.stat(config_path).st_mode)

        self.assertEqual(saved_mode, 0o600)
        mock_chown.assert_not_called()
        mock_chmod.assert_not_called()

    def test_load_config_treats_empty_document_as_empty_mapping(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w"):
                pass

            with mock.patch.dict(
                self.mod.load_config.__globals__,
                {"CONFIG_FILE_PATH": config_path},
            ):
                config = self.mod.load_config()

        self.assertEqual(config, {})

    def test_load_config_rejects_falsy_non_mapping_roots(self):
        for document in ("[]\n", "false\n", "0\n"):
            with self.subTest(document=document), tempfile.TemporaryDirectory() as temp_dir:
                config_path = os.path.join(temp_dir, "config.yaml")
                with open(config_path, "w") as config_file:
                    config_file.write(document)

                with mock.patch.dict(
                    self.mod.load_config.__globals__,
                    {"CONFIG_FILE_PATH": config_path},
                ):
                    with self.assertRaisesRegex(ValueError, "configuration root must be a mapping"):
                        self.mod.load_config()

    def test_init_new_user_preserves_existing_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as config_file:
                config_file.write("ENVIRONMENT:\n  MSI_SECRET: example-secret\n")

            with mock.patch.dict(
                self.mod.init_new_user.__globals__,
                {"CONFIG_FILE_PATH": config_path},
            ), mock.patch("os.system", return_value=0), mock.patch(
                "subprocess.check_output", return_value=b"1001"
            ):
                user_uid = self.mod.init_new_user()
                saved_config = self.mod.load_config()

        self.assertEqual(user_uid, "1001")
        self.assertEqual(saved_config["ENVIRONMENT"]["MSI_SECRET"], "example-secret")
        self.assertEqual(saved_config["USER_UID"], 1001)

    def test_init_new_user_exits_when_config_cannot_be_loaded(self):
        mock_load = mock.MagicMock(side_effect=ValueError("configuration root must be a mapping"))
        mock_save = mock.MagicMock()
        with mock.patch.dict(
            self.mod.init_new_user.__globals__,
            {"load_config": mock_load, "save_config": mock_save},
        ), mock.patch("os.system") as mock_system, mock.patch("builtins.print") as mock_print:
            with self.assertRaises(SystemExit) as raised:
                self.mod.init_new_user()

        self.assertEqual(raised.exception.code, 1)
        mock_system.assert_not_called()
        mock_save.assert_not_called()
        self.assertIn(
            "Error reading the config file from /etc/azfilesauth/config.yaml: configuration root must be a mapping",
            " ".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list),
        )


# ===================================================================
# Test: azfilesauthmanager.py — Azure Identity environment
# ===================================================================

class TestAzureIdentityEnvironment(unittest.TestCase):

    def setUp(self):
        self.mod = _load_manager()

    def test_reload_overwrites_configured_values_without_unsetting_removed_keys(self):
        configs = [
            {"ENVIRONMENT": {"CONFIGURED": "first", "REMOVED": "retained"}},
            {"ENVIRONMENT": {"CURRENT": "second"}},
        ]
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.dict(
            self.mod.load_azure_identity_environment.__globals__,
            {"load_config": mock.MagicMock(side_effect=configs)},
        ):
            self.assertTrue(self.mod.load_azure_identity_environment())
            self.assertEqual(os.environ["CONFIGURED"], "first")
            self.assertEqual(os.environ["REMOVED"], "retained")

            self.assertTrue(self.mod.load_azure_identity_environment())
            self.assertEqual(os.environ["REMOVED"], "retained")
            self.assertEqual(os.environ["CURRENT"], "second")

    def test_invalid_reload_retains_values_applied_before_the_error(self):
        configs = [
            {"ENVIRONMENT": {"VALID": "first"}},
            {"ENVIRONMENT": {"VALID": "second", "INVALID": ["not", "scalar"]}},
        ]
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.dict(
            self.mod.load_azure_identity_environment.__globals__,
            {"load_config": mock.MagicMock(side_effect=configs)},
        ):
            self.assertTrue(self.mod.load_azure_identity_environment())
            self.assertFalse(self.mod.load_azure_identity_environment())
            self.assertEqual(os.environ["VALID"], "second")
            self.assertNotIn("INVALID", os.environ)

    def test_init_new_user_skips_user_creation_for_local_sentinel(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as config_file:
                config_file.write("USER_UID: local\n")

            with mock.patch.dict(
                self.mod.init_new_user.__globals__,
                {"CONFIG_FILE_PATH": config_path},
            ), mock.patch("os.system") as mock_system, mock.patch(
                "subprocess.check_output"
            ) as mock_check_output:
                user_uid = self.mod.init_new_user()
                saved_config = self.mod.load_config()

        self.assertEqual(user_uid, "local")
        # No shared user should be looked up or created.
        mock_system.assert_not_called()
        mock_check_output.assert_not_called()
        # The sentinel must be left untouched in the config file.
        self.assertEqual(saved_config["USER_UID"], "local")

    def test_init_new_user_local_sentinel_is_case_insensitive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as config_file:
                config_file.write("USER_UID: Local\n")

            with mock.patch.dict(
                self.mod.init_new_user.__globals__,
                {"CONFIG_FILE_PATH": config_path},
            ), mock.patch("os.system") as mock_system:
                user_uid = self.mod.init_new_user()

        self.assertEqual(user_uid, "local")
        mock_system.assert_not_called()


# ===================================================================
# Test: azfilesauthmanager.py — token acquisition logic
# ===================================================================

class TestGetOauthToken(unittest.TestCase):
    """Test get_oauth_token() for both system and user-assigned MI."""

    def setUp(self):
        self.mod = _load_manager()

    def test_system_assigned_returns_token(self):
        token_response = mock.MagicMock()
        token_response.token = "sys-tok-abc"
        credential = mock.MagicMock()
        credential.get_token.return_value = token_response

        mock_cred = mock.MagicMock(return_value=credential)
        with mock.patch.dict(self.mod.get_oauth_token.__globals__, {"ManagedIdentityCredential": mock_cred}):
            token = self.mod.get_oauth_token()

        self.assertEqual(token, "sys-tok-abc")
        mock_cred.assert_called_once_with()
        credential.get_token.assert_called_once_with("https://storage.azure.com/.default")

    def test_user_assigned_passes_client_id(self):
        token_response = mock.MagicMock()
        token_response.token = "user-tok-xyz"
        credential = mock.MagicMock()
        credential.get_token.return_value = token_response

        mock_cred = mock.MagicMock(return_value=credential)
        with mock.patch.dict(self.mod.get_oauth_token.__globals__, {"ManagedIdentityCredential": mock_cred}):
            token = self.mod.get_oauth_token("my-client-id")

        self.assertEqual(token, "user-tok-xyz")
        mock_cred.assert_called_once_with(client_id="my-client-id")
        credential.get_token.assert_called_once_with("https://storage.azure.com/.default")

    def test_loads_environment_before_managed_identity_credential(self):
        token_response = mock.MagicMock(token="env-token")
        credential = mock.MagicMock()
        credential.get_token.return_value = token_response

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as config_file:
                config_file.write(
                    "ENVIRONMENT:\n"
                    "  MSI_ENDPOINT: http://localhost:40342/msi/token\n"
                    "  LITERAL_DOLLAR: $HOME\n"
                    "  RETRY_ENABLED: true\n"
                )

            def create_credential():
                self.assertEqual(os.environ["MSI_ENDPOINT"], "http://localhost:40342/msi/token")
                self.assertEqual(os.environ["LITERAL_DOLLAR"], "$HOME")
                self.assertEqual(os.environ["RETRY_ENABLED"], "True")
                return credential

            with mock.patch.dict(os.environ, {"MSI_ENDPOINT": "old-value"}):
                with mock.patch.dict(
                    self.mod.get_oauth_token.__globals__,
                    {
                        "CONFIG_FILE_PATH": config_path,
                        "ManagedIdentityCredential": mock.MagicMock(side_effect=create_credential),
                    },
                ):
                    token = self.mod.get_oauth_token()

        self.assertEqual(token, "env-token")

    def test_empty_client_id_uses_system_assigned_identity(self):
        token_response = mock.MagicMock()
        token_response.token = "sys-tok-empty"
        credential = mock.MagicMock()
        credential.get_token.return_value = token_response

        mock_cred = mock.MagicMock(return_value=credential)
        with mock.patch.dict(self.mod.get_oauth_token.__globals__, {"ManagedIdentityCredential": mock_cred}):
            token = self.mod.get_oauth_token("")

        self.assertEqual(token, "sys-tok-empty")
        mock_cred.assert_called_once_with()

    def test_missing_access_token_returns_none(self):
        token_response = mock.MagicMock()
        token_response.token = None
        credential = mock.MagicMock()
        credential.get_token.return_value = token_response

        with mock.patch.dict(self.mod.get_oauth_token.__globals__, {"ManagedIdentityCredential": mock.MagicMock(return_value=credential)}):
            token = self.mod.get_oauth_token()

        self.assertIsNone(token)

    def test_request_failure_returns_none(self):
        credential = mock.MagicMock()
        credential.get_token.side_effect = Exception("credential unavailable")

        with mock.patch.dict(self.mod.get_oauth_token.__globals__, {"ManagedIdentityCredential": mock.MagicMock(return_value=credential)}):
            token = self.mod.get_oauth_token()

        self.assertIsNone(token)

    def test_missing_sdk_dependency_returns_none(self):
        with mock.patch.dict(
            self.mod.get_oauth_token.__globals__,
            {"ManagedIdentityCredential": None, "ClientAssertionCredential": None}
        ):
            with mock.patch("builtins.print") as mock_print:
                token = self.mod.get_oauth_token()

        self.assertIsNone(token)
        printed = " ".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list)
        self.assertIn("Missing Python dependencies: azure-identity and azure-core", printed)


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
    def test_successful_token_fetch(self):
        token_response = mock.MagicMock()
        token_response.token = "wi-token-123"
        credential = mock.MagicMock()
        credential.get_token.return_value = token_response

        mock_cred = mock.MagicMock(return_value=credential)
        with mock.patch.dict(
            self.mod.get_workload_identity_token.__globals__,
            {
                "ClientAssertionCredential": mock_cred,
                "load_azure_identity_environment": mock.MagicMock(return_value=True),
            },
        ):
            token = self.mod.get_workload_identity_token("tenant-1", "client-1", "/tok")

        self.assertEqual(token, "wi-token-123")
        kwargs = mock_cred.call_args.kwargs
        self.assertEqual(kwargs["tenant_id"], "tenant-1")
        self.assertEqual(kwargs["client_id"], "client-1")
        self.assertEqual(kwargs["authority"], "https://login.microsoftonline.com")
        self.assertEqual(kwargs["func"](), "jwt-assertion-data")
        credential.get_token.assert_called_once_with("https://storage.azure.com/.default")

    def test_loads_environment_before_client_assertion_credential(self):
        token_response = mock.MagicMock(token="env-token")
        credential = mock.MagicMock()
        credential.get_token.return_value = token_response

        with tempfile.TemporaryDirectory() as temp_dir:
            token_path = os.path.join(temp_dir, "federated-token")
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(token_path, "w") as token_file:
                token_file.write("jwt-assertion-data")
            with open(config_path, "w") as config_file:
                config_file.write("ENVIRONMENT:\n  AZURE_AUTHORITY_HOST: https://login.example.test\n")

            def create_credential(**kwargs):
                self.assertEqual(os.environ["AZURE_AUTHORITY_HOST"], "https://login.example.test")
                self.assertEqual(kwargs["authority"], "https://login.example.test")
                return credential

            with mock.patch.dict(os.environ, {}, clear=True):
                with mock.patch.dict(
                    self.mod.get_workload_identity_token.__globals__,
                    {
                        "CONFIG_FILE_PATH": config_path,
                        "ClientAssertionCredential": mock.MagicMock(side_effect=create_credential),
                    },
                ):
                    token = self.mod.get_workload_identity_token("tenant-1", "client-1", token_path)

        self.assertEqual(token, "env-token")

    @mock.patch("builtins.open", mock.mock_open(read_data="jwt-assertion-data"))
    def test_default_authority_is_public(self):
        token_response = mock.MagicMock()
        token_response.token = "wi-token-123"
        credential = mock.MagicMock()
        credential.get_token.return_value = token_response

        mock_cred = mock.MagicMock(return_value=credential)
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.dict(
                self.mod.get_workload_identity_token.__globals__,
                {
                    "ClientAssertionCredential": mock_cred,
                    "load_azure_identity_environment": mock.MagicMock(return_value=True),
                },
            ):
                self.mod.get_workload_identity_token("tenant-1", "client-1", "/tok")

        kwargs = mock_cred.call_args.kwargs
        self.assertEqual(kwargs["authority"], "https://login.microsoftonline.com")
        credential.get_token.assert_called_once_with("https://storage.azure.com/.default")

    @mock.patch("builtins.open", mock.mock_open(read_data="jwt-assertion-data"))
    def test_resource_is_used_as_base_uri(self):
        token_response = mock.MagicMock()
        token_response.token = "wi-token-123"
        credential = mock.MagicMock()
        credential.get_token.return_value = token_response

        mock_cred = mock.MagicMock(return_value=credential)
        with mock.patch.dict(
            self.mod.get_workload_identity_token.__globals__,
            {
                "ClientAssertionCredential": mock_cred,
                "load_azure_identity_environment": mock.MagicMock(return_value=True),
            },
        ):
            self.mod.get_workload_identity_token(
                "tenant-1", "client-1", "/tok",
                resource="https://storage.azure.com/",
            )

        credential.get_token.assert_called_once_with("https://storage.azure.com/.default")

    @mock.patch("builtins.open", mock.mock_open(read_data="jwt-assertion-data"))
    def test_sovereign_authority_and_resource_override(self):
        token_response = mock.MagicMock()
        token_response.token = "wi-token-123"
        credential = mock.MagicMock()
        credential.get_token.return_value = token_response

        mock_cred = mock.MagicMock(return_value=credential)
        with mock.patch.dict(os.environ, {"AZURE_AUTHORITY_HOST": "https://ignored.example"}, clear=True):
            with mock.patch.dict(
                self.mod.get_workload_identity_token.__globals__,
                {
                    "ClientAssertionCredential": mock_cred,
                    "load_azure_identity_environment": mock.MagicMock(return_value=True),
                },
            ):
                # Mooncake (Azure China) authority host; trailing slash must be normalized.
                self.mod.get_workload_identity_token(
                    "tenant-1", "client-1", "/tok",
                    authority_host="https://login.chinacloudapi.cn/",
                    resource="https://storage.sovereign.example/",
                )

        kwargs = mock_cred.call_args.kwargs
        self.assertEqual(kwargs["authority"], "https://login.chinacloudapi.cn")
        credential.get_token.assert_called_once_with("https://storage.sovereign.example/.default")


# ===================================================================
# Test: azfilesauthmanager.py — runtime endpoint auth metadata
# ===================================================================

class TestEndpointAuthMetadata(unittest.TestCase):

    def setUp(self):
        self.mod = _load_manager()

    def test_metadata_uses_runtime_state_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = os.path.join(temp_dir, "run", "azfilesauth")
            state_file = os.path.join(state_dir, "endpoint-auth-state.json")
            with mock.patch.dict(
                self.mod.get_endpoint_auth_metadata.__globals__,
                {
                    "AUTH_STATE_DIR": state_dir,
                    "AUTH_STATE_FILE_PATH": state_file,
                },
            ):
                self.mod.azfiles_set_oauth(
                    "https://account.file.core.windows.net",
                    "seed-token",
                    auth_mode="workload-identity",
                    tenant_id="tenant-1",
                    client_id="client-1",
                    token_file="/tmp/token",
                )

                metadata = self.mod.get_endpoint_auth_metadata(
                    "https://account.file.core.windows.net"
                )

            self.assertEqual(metadata["auth_mode"], "workload-identity")
            self.assertTrue(os.path.exists(state_file))

    def test_metadata_rejects_different_client_id_for_same_endpoint(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = os.path.join(temp_dir, "run", "azfilesauth")
            state_file = os.path.join(state_dir, "endpoint-auth-state.json")
            with mock.patch.dict(
                self.mod.get_endpoint_auth_metadata.__globals__,
                {
                    "AUTH_STATE_DIR": state_dir,
                    "AUTH_STATE_FILE_PATH": state_file,
                },
            ):
                self.mod.azfiles_set_oauth(
                    "https://account.file.core.windows.net",
                    "tok-alice",
                    auth_mode="user-assigned",
                    client_id="alice-client-id",
                )
                with self.assertRaises(self.mod.AuthMetadataConflict):
                    self.mod.azfiles_set_oauth(
                        "https://account.file.core.windows.net",
                        "tok-bob",
                        auth_mode="user-assigned",
                        client_id="bob-client-id",
                    )
                metadata = self.mod.get_endpoint_auth_metadata(
                    "https://account.file.core.windows.net"
                )

            self.assertEqual(metadata["client_id"], "alice-client-id")
            self.assertEqual(metadata["auth_mode"], "user-assigned")

    def test_metadata_write_takes_exclusive_lock(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = os.path.join(temp_dir, "run", "azfilesauth")
            state_file = os.path.join(state_dir, "endpoint-auth-state.json")
            with mock.patch.dict(
                self.mod.get_endpoint_auth_metadata.__globals__,
                {
                    "AUTH_STATE_DIR": state_dir,
                    "AUTH_STATE_FILE_PATH": state_file,
                },
            ):
                self.mod.azfiles_set_oauth(
                    "https://account.file.core.windows.net",
                    "seed-token",
                    auth_mode="system",
                )

                # A second exclusive lock attempt on the same file must block
                # (non-blocking probe should fail with EWOULDBLOCK/EAGAIN)
                # while the first holder is still writing.
                with self.mod._locked_state_file(exclusive=True) as held_file:
                    probe_fd = os.open(state_file, os.O_RDWR)
                    try:
                        with self.assertRaises(OSError):
                            fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(probe_fd)



# ===================================================================
# Test: azfilesauthmanager.py — native lib wrappers
# ===================================================================

class TestAzfilesSetOauth(unittest.TestCase):
    """Verify azfiles_set_oauth calls the C library correctly."""

    def test_set_calls_lib(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        with _temp_auth_state(mod):
            mod.azfiles_set_oauth("https://myaccount.file.core.windows.net", "tok-123")

        fake_lib.extern_smb_set_credential_oauth_token.assert_called_once()
        args = fake_lib.extern_smb_set_credential_oauth_token.call_args[0]
        self.assertEqual(args[0], b"https://myaccount.file.core.windows.net")
        self.assertEqual(args[1], b"tok-123")

    def test_set_nonzero_rc_exits(self):
        fake_lib = _make_fake_lib()
        fake_lib.extern_smb_set_credential_oauth_token.return_value = -1
        mod = _load_manager(fake_lib)

        with _temp_auth_state(mod):
            with self.assertRaises(SystemExit):
                mod.azfiles_set_oauth("https://myaccount.file.core.windows.net", "tok-123")

    def test_set_persists_metadata_after_successful_lib_call(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        with _temp_auth_state(mod):
            mod.azfiles_set_oauth(
                "https://myaccount.file.core.windows.net",
                "tok-123",
                auth_mode="system",
            )
            metadata = mod.get_endpoint_auth_metadata("https://myaccount.file.core.windows.net")

        self.assertEqual(metadata["auth_mode"], "system")

    def test_set_direct_token_persists_token_auth_mode(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        with _temp_auth_state(mod):
            mod.azfiles_set_oauth(
                "https://myaccount.file.core.windows.net",
                "tok-123",
                auth_mode="token",
            )
            metadata = mod.get_endpoint_auth_metadata("https://myaccount.file.core.windows.net")

        self.assertEqual(metadata["auth_mode"], "token")

    def test_set_conflict_raised_before_lib_call(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        with _temp_auth_state(mod):
            mod.azfiles_set_oauth(
                "https://myaccount.file.core.windows.net",
                "tok-1",
                auth_mode="user-assigned",
                client_id="alice-client-id",
            )
            fake_lib.extern_smb_set_credential_oauth_token.reset_mock()

            with self.assertRaises(mod.AuthMetadataConflict):
                mod.azfiles_set_oauth(
                    "https://myaccount.file.core.windows.net",
                    "tok-2",
                    auth_mode="user-assigned",
                    client_id="bob-client-id",
                )

        fake_lib.extern_smb_set_credential_oauth_token.assert_not_called()

    def test_set_force_bypasses_conflict_and_overwrites_metadata(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        with _temp_auth_state(mod):
            mod.azfiles_set_oauth(
                "https://myaccount.file.core.windows.net",
                "tok-1",
                auth_mode="user-assigned",
                client_id="alice-client-id",
            )
            fake_lib.extern_smb_set_credential_oauth_token.reset_mock()

            mod.azfiles_set_oauth(
                "https://myaccount.file.core.windows.net",
                "tok-2",
                auth_mode="user-assigned",
                client_id="bob-client-id",
                force=True,
            )

            metadata = mod.get_endpoint_auth_metadata("https://myaccount.file.core.windows.net")

        fake_lib.extern_smb_set_credential_oauth_token.assert_called_once()
        args = fake_lib.extern_smb_set_credential_oauth_token.call_args[0]
        self.assertEqual(args[1], b"tok-2")
        self.assertEqual(metadata["client_id"], "bob-client-id")


class TestAzfilesClear(unittest.TestCase):

    def test_clear_calls_lib(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        with _temp_auth_state(mod):
            mod.azfiles_clear("https://myaccount.file.core.windows.net")

        fake_lib.extern_smb_clear_credential.assert_called_once()

    def test_clear_nonzero_rc_exits(self):
        fake_lib = _make_fake_lib()
        fake_lib.extern_smb_clear_credential.return_value = -1
        mod = _load_manager(fake_lib)

        with _temp_auth_state(mod):
            with self.assertRaises(SystemExit):
                mod.azfiles_clear("https://myaccount.file.core.windows.net")

    def test_clear_removes_metadata(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        with _temp_auth_state(mod):
            mod.azfiles_set_oauth(
                "https://myaccount.file.core.windows.net",
                "tok-123",
                auth_mode="system",
            )
            mod.azfiles_clear("https://myaccount.file.core.windows.net")
            metadata = mod.get_endpoint_auth_metadata("https://myaccount.file.core.windows.net")

        self.assertIsNone(metadata)


class TestAzfilesList(unittest.TestCase):

    def test_list_plain(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)
        with _temp_auth_state(mod):
            mod.azfiles_list(False)
        fake_lib.extern_smb_list_credential.assert_called_once_with(False)

    def test_list_json(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)
        with _temp_auth_state(mod):
            mod.azfiles_list(True)
        fake_lib.extern_smb_list_credential.assert_called_once_with(True)

    def test_list_nonzero_rc_exits(self):
        fake_lib = _make_fake_lib()
        fake_lib.extern_smb_list_credential.return_value = 2
        mod = _load_manager(fake_lib)

        with _temp_auth_state(mod):
            with self.assertRaises(SystemExit) as ctx:
                mod.azfiles_list(False)
        self.assertEqual(ctx.exception.code, 2)



# ===================================================================
# Test: azfilesrefresh.py.in — environment configuration
# ===================================================================

class TestRefreshEnvironment(unittest.TestCase):

    def test_valid_sleep_overrides_at_or_above_minimum(self):
        for value in ("5", "30"):
            with self.subTest(value=value), mock.patch.dict(
                os.environ,
                {"AZFILES_REFRESH_SLEEP_SECONDS": value},
            ), mock.patch("logging.error") as mock_log:
                mod = _load_refresh()

            self.assertEqual(mod.SLEEP_TIME, int(value))
            mock_log.assert_not_called()

    def test_sleep_overrides_below_minimum_use_default(self):
        for value in ("-1", "0", "1", "4"):
            with self.subTest(value=value), mock.patch.dict(
                os.environ,
                {"AZFILES_REFRESH_SLEEP_SECONDS": value},
            ), mock.patch("logging.error") as mock_log:
                mod = _load_refresh()

            self.assertEqual(mod.SLEEP_TIME, 60)
            mock_log.assert_any_call(
                "Invalid AZFILES_REFRESH_SLEEP_SECONDS: value must be at least 5 seconds; using default 60"
            )

    def test_invalid_timing_overrides_log_and_use_defaults(self):
        with mock.patch.dict(
            os.environ,
            {
                "AZFILES_REFRESH_SLEEP_SECONDS": "not-an-integer",
                "AZFILES_REFRESH_BEFORE_EXPIRY_SECONDS": "",
            },
        ), mock.patch("logging.error") as mock_log:
            mod = _load_refresh()

        self.assertEqual(mod.SLEEP_TIME, 60)
        self.assertEqual(mod.REFRESH_BEFORE_EXPIRY, 300)
        mock_log.assert_any_call(
            "Invalid AZFILES_REFRESH_SLEEP_SECONDS: invalid literal for int() with base 10: 'not-an-integer'; using default 60"
        )
        mock_log.assert_any_call(
            "Invalid AZFILES_REFRESH_BEFORE_EXPIRY_SECONDS: invalid literal for int() with base 10: ''; using default 300"
        )


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
            "https://account.file.core.windows.net", "system-token", auth_mode="system"
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

    @mock.patch("subprocess.run")
    def test_refresh_skips_if_metadata_client_id_differs_from_mount_user(self, mock_run):
        mount_output = (
            "//account.file.core.windows.net/share on /mnt type cifs "
            "(rw,sec=krb5,username=other-client-id,uid=0)\n"
        )
        mock_run.return_value = mock.MagicMock(
            stdout=mount_output.encode("utf-8"),
            stderr=b"",
        )

        self.mod._fake_azfilesauth.get_endpoint_auth_metadata.return_value = {
            "auth_mode": "user-assigned",
            "client_id": "saved-client-id",
        }
        self.mod._fake_azfilesauth.get_oauth_token.reset_mock()
        self.mod._fake_azfilesauth.azfiles_set_oauth.reset_mock()

        ticket = {"server": "cifs/account.file.core.windows.net@REALM"}
        self.mod.refresh_ticket(ticket)

        self.mod._fake_azfilesauth.get_oauth_token.assert_not_called()
        self.mod._fake_azfilesauth.azfiles_set_oauth.assert_not_called()

    @mock.patch("subprocess.run")
    def test_refresh_skips_workload_identity_metadata_when_present(self, mock_run):
        mount_output = (
            "//account.file.core.windows.net/share on /mnt type cifs "
            "(rw,sec=krb5,username=workload-client-id,uid=0)\n"
        )
        mock_run.return_value = mock.MagicMock(
            stdout=mount_output.encode("utf-8"),
            stderr=b"",
        )

        self.mod._fake_azfilesauth.get_endpoint_auth_metadata.return_value = {
            "auth_mode": "workload-identity",
            "tenant_id": "tenant-1",
            "client_id": "workload-client-id",
            "token_file": "/tmp/token",
            "authority_host": "https://login.microsoftonline.com",
            "resource": "https://storage.azure.com",
        }
        self.mod._fake_azfilesauth.get_oauth_token.reset_mock()
        self.mod._fake_azfilesauth.get_workload_identity_token.reset_mock()
        self.mod._fake_azfilesauth.azfiles_set_oauth.reset_mock()

        ticket = {"server": "cifs/account.file.core.windows.net@REALM"}
        self.mod.refresh_ticket(ticket)

        self.mod._fake_azfilesauth.get_workload_identity_token.assert_not_called()
        self.mod._fake_azfilesauth.get_oauth_token.assert_not_called()
        self.mod._fake_azfilesauth.azfiles_set_oauth.assert_not_called()

    @mock.patch("subprocess.run")
    def test_refresh_skips_token_auth_mode(self, mock_run):
        mount_output = (
            "//account.file.core.windows.net/share on /mnt type cifs "
            "(rw,sec=krb5,username=root,uid=0)\n"
        )
        mock_run.return_value = mock.MagicMock(
            stdout=mount_output.encode("utf-8"),
            stderr=b"",
        )

        self.mod._fake_azfilesauth.get_endpoint_auth_metadata.return_value = {
            "auth_mode": "token",
        }
        self.mod._fake_azfilesauth.get_oauth_token.reset_mock()
        self.mod._fake_azfilesauth.azfiles_set_oauth.reset_mock()

        ticket = {"server": "cifs/account.file.core.windows.net@REALM"}
        self.mod.refresh_ticket(ticket)

        self.mod._fake_azfilesauth.get_oauth_token.assert_not_called()
        self.mod._fake_azfilesauth.azfiles_set_oauth.assert_not_called()

    @mock.patch("subprocess.run")
    def test_refresh_skips_when_identity_changes_during_token_fetch(self, mock_run):
        mount_output = (
            "//account.file.core.windows.net/share on /mnt type cifs "
            "(rw,sec=krb5,username=root,uid=0)\n"
        )
        mock_run.return_value = mock.MagicMock(
            stdout=mount_output.encode("utf-8"),
            stderr=b"",
        )

        self.mod._fake_azfilesauth.get_endpoint_auth_metadata.return_value = {
            "auth_mode": "system",
        }
        self.mod._fake_azfilesauth.get_oauth_token.return_value = "system-token"
        # Simulate another process re-assigning this endpoint's identity while
        # the (possibly slow) token fetch above was in flight: azfiles_set_oauth
        # re-checks metadata under its own lock and raises on the stale caller.
        self.mod._fake_azfilesauth.azfiles_set_oauth.side_effect = self.mod._fake_azfilesauth.AuthMetadataConflict(
            "Endpoint https://account.file.core.windows.net: existing auth_mode='user-assigned' does not match requested auth_mode='system'"
        )

        ticket = {"server": "cifs/account.file.core.windows.net@REALM"}
        # Should not raise: the conflict must be caught and treated as a skip.
        self.mod.refresh_ticket(ticket)

        self.mod._fake_azfilesauth.azfiles_set_oauth.assert_called_once_with(
            "https://account.file.core.windows.net", "system-token", auth_mode="system"
        )

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

        with _temp_auth_state(mod):
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

    def test_set_direct_token_conflict_exits_before_touching_krb5_cache(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = os.path.join(temp_dir, "run", "azfilesauth")
            state_file = os.path.join(state_dir, "endpoint-auth-state.json")

            with mock.patch.dict(
                mod.get_endpoint_auth_metadata.__globals__,
                {
                    "AUTH_STATE_DIR": state_dir,
                    "AUTH_STATE_FILE_PATH": state_file,
                },
            ):
                # Endpoint is already owned by a user-assigned identity.
                mod.azfiles_set_oauth(
                    "https://account.file.core.windows.net",
                    "seed-token",
                    auth_mode="user-assigned",
                    client_id="alice-client-id",
                )
                fake_lib.extern_smb_set_credential_oauth_token.reset_mock()

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
                                    sys.argv = ["azfilesauthmanager", "set", "https://account.file.core.windows.net", "my-direct-token"]
                                    with self.assertRaises(SystemExit) as ctx:
                                        mod.run_azfilesauthmanager()
                                finally:
                                    sys.argv = saved_argv

                self.assertEqual(ctx.exception.code, 3)
                fake_lib.extern_smb_set_credential_oauth_token.assert_not_called()

                # Original owner's metadata must remain untouched.
                metadata = mod.get_endpoint_auth_metadata("https://account.file.core.windows.net")
                self.assertEqual(metadata["client_id"], "alice-client-id")

    def test_set_system_mi_conflict_exits_before_touching_krb5_cache(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = os.path.join(temp_dir, "run", "azfilesauth")
            state_file = os.path.join(state_dir, "endpoint-auth-state.json")

            with mock.patch.dict(
                mod.get_endpoint_auth_metadata.__globals__,
                {
                    "AUTH_STATE_DIR": state_dir,
                    "AUTH_STATE_FILE_PATH": state_file,
                },
            ):
                # Endpoint is already owned by a user-assigned identity.
                mod.azfiles_set_oauth(
                    "https://account.file.core.windows.net",
                    "seed-token",
                    auth_mode="user-assigned",
                    client_id="alice-client-id",
                )
                fake_lib.extern_smb_set_credential_oauth_token.reset_mock()

                token_response = mock.MagicMock()
                token_response.token = "sys-tok"
                credential = mock.MagicMock()
                credential.get_token.return_value = token_response

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
                                with mock.patch.dict(
                                    mod.get_oauth_token.__globals__,
                                    {"ManagedIdentityCredential": mock.MagicMock(return_value=credential)},
                                ):
                                    saved_argv = sys.argv
                                    try:
                                        sys.argv = ["azfilesauthmanager", "set", "https://account.file.core.windows.net", "--system"]
                                        with self.assertRaises(SystemExit) as ctx:
                                            mod.run_azfilesauthmanager()
                                    finally:
                                        sys.argv = saved_argv

                self.assertEqual(ctx.exception.code, 3)
                fake_lib.extern_smb_set_credential_oauth_token.assert_not_called()

                # Original owner's metadata must remain untouched.
                metadata = mod.get_endpoint_auth_metadata("https://account.file.core.windows.net")
                self.assertEqual(metadata["client_id"], "alice-client-id")

    def test_set_system_mi_force_overwrites_conflicting_metadata(self):
        fake_lib = _make_fake_lib()
        mod = _load_manager(fake_lib)

        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = os.path.join(temp_dir, "run", "azfilesauth")
            state_file = os.path.join(state_dir, "endpoint-auth-state.json")

            with mock.patch.dict(
                mod.get_endpoint_auth_metadata.__globals__,
                {
                    "AUTH_STATE_DIR": state_dir,
                    "AUTH_STATE_FILE_PATH": state_file,
                },
            ):
                # Endpoint is already owned by a user-assigned identity.
                mod.azfiles_set_oauth(
                    "https://account.file.core.windows.net",
                    "seed-token",
                    auth_mode="user-assigned",
                    client_id="alice-client-id",
                )
                fake_lib.extern_smb_set_credential_oauth_token.reset_mock()

                token_response = mock.MagicMock()
                token_response.token = "sys-tok"
                credential = mock.MagicMock()
                credential.get_token.return_value = token_response

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
                                with mock.patch.dict(
                                    mod.get_oauth_token.__globals__,
                                    {"ManagedIdentityCredential": mock.MagicMock(return_value=credential)},
                                ):
                                    saved_argv = sys.argv
                                    try:
                                        sys.argv = ["azfilesauthmanager", "set", "https://account.file.core.windows.net", "--system", "--force"]
                                        mod.run_azfilesauthmanager()
                                    finally:
                                        sys.argv = saved_argv

                fake_lib.extern_smb_set_credential_oauth_token.assert_called_once()

                # Metadata now reflects the forced overwrite, not the original owner.
                metadata = mod.get_endpoint_auth_metadata("https://account.file.core.windows.net")
                self.assertEqual(metadata["auth_mode"], "system")
                self.assertNotIn("client_id", metadata)


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
