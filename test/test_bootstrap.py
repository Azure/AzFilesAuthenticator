#!/usr/bin/env python3
"""Runtime setup tests; no root, network access, or installed native library required."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bootstrap", ROOT / "src" / "azfilesauthbootstrap.py")
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


def result(code=0, error=""):
    return subprocess.CompletedProcess([], code, "", error)


class TestEnvironmentSetup(unittest.TestCase):
    def setUp(self):
        self.run_patcher = mock.patch.object(bootstrap, "_run")
        self.run = self.run_patcher.start()
        self.addCleanup(mock.patch.stopall)
        self.run.return_value = result()
        self.prefix = mock.patch.object(bootstrap.sys, "prefix", bootstrap.sys.base_prefix).start()

    def test_system_satisfied_does_not_install(self):
        self.assertEqual(bootstrap._prepare_environment(""), sys.executable)
        self.run.assert_called_once_with(
            sys.executable, "-c", bootstrap.DEPENDENCY_CHECK, str(bootstrap.REQUIREMENTS_PATH)
        )

    def test_system_missing_dependencies_and_pip_aborts(self):
        self.run.side_effect = [result(1, "No module named yaml"), result(1, "No module named pip")]
        with self.assertRaisesRegex(RuntimeError, "pip is required for system Python"):
            bootstrap._prepare_environment("")
        self.assertEqual(self.run.call_count, 2)
        self.assertEqual(self.run.call_args.args, (sys.executable, "-m", "pip", "--version"))

    def test_system_installs_missing_dependencies_and_verifies(self):
        self.run.side_effect = [result(1), result(), result(), result()]
        with mock.patch("builtins.print") as message:
            bootstrap._prepare_environment("")
        message.assert_called_once_with(
            f"azfilesauth: installing Python requirements using {sys.executable}",
            file=sys.stderr, flush=True,
        )
        install = self.run.call_args_list[2].args
        self.assertEqual(install[:5], (sys.executable, "-m", "pip", "--disable-pip-version-check", "install"))
        self.assertIn(str(bootstrap.REQUIREMENTS_PATH), install)
        self.assertNotIn("--break-system-packages", install)
        self.assertEqual(self.run.call_args_list[3].args[2], bootstrap.DEPENDENCY_CHECK)

    def test_install_failure_aborts_without_successful_verification(self):
        self.run.side_effect = [result(1), result(), result(1, "externally-managed-environment")]
        with self.assertRaisesRegex(RuntimeError, "externally-managed-environment"):
            bootstrap._prepare_environment("")
        self.assertEqual(self.run.call_count, 3)

    def test_failed_post_install_verification_aborts(self):
        self.run.side_effect = [result(1), result(), result(), result(1, "cannot import yaml")]
        with self.assertRaisesRegex(RuntimeError, "dependency verification"):
            bootstrap._prepare_environment("")

    def test_venv_created_and_pip_bootstrapped(self):
        with tempfile.TemporaryDirectory(prefix="azfiles venv ") as directory:
            path = Path(directory) / "new venv"

            def run(python, *arguments):
                if arguments[:3] == ("-m", "venv", "--without-pip"):
                    (path / "bin").mkdir(parents=True)
                    (path / "pyvenv.cfg").touch()
                    (path / "bin" / "python").touch()
                if arguments == ("-m", "pip", "--version") and not hasattr(run, "pip_ready"):
                    run.pip_ready = True
                    return result(1)
                if arguments[:2] == ("-c", bootstrap.DEPENDENCY_CHECK) and not hasattr(run, "deps_ready"):
                    run.deps_ready = True
                    return result(1)
                return result()

            self.run.side_effect = run
            with mock.patch.object(bootstrap, "_validate_secure_path"):
                selected = bootstrap._prepare_environment(str(path))
            self.assertEqual(selected, str(path / "bin" / "python"))
            calls = [call.args for call in self.run.call_args_list]
            self.assertIn((sys.executable, "-m", "venv", "--without-pip", str(path)), calls)
            self.assertIn((selected, "-m", "ensurepip", "--upgrade"), calls)
            self.assertTrue(any(call[0] == selected and "install" in call for call in calls))

    def test_existing_non_venv_is_not_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(bootstrap, "_validate_secure_path"):
                with self.assertRaisesRegex(RuntimeError, "not a Python venv"):
                    bootstrap._prepare_environment(directory)
        self.run.assert_not_called()

    def test_venv_with_system_site_packages_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "pyvenv.cfg").write_text("include-system-site-packages = true\n")
            with mock.patch.object(bootstrap, "_validate_secure_path"):
                with self.assertRaisesRegex(RuntimeError, "must not include system site packages"):
                    bootstrap._prepare_environment(directory)
        self.run.assert_not_called()

    def test_venv_creation_failure_is_explicit(self):
        self.run.return_value = result(1, "No module named venv")
        with mock.patch.object(bootstrap, "_validate_secure_path"), mock.patch.object(Path, "exists", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "Venv creation"):
                bootstrap._prepare_environment("/opt/azfilesauth/venv")

    def test_existing_venv_missing_ensurepip_aborts_without_system_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "bin").mkdir()
            (path / "bin" / "python").touch()
            (path / "pyvenv.cfg").touch()
            self.run.side_effect = [result(), result(1), result(1), result(1, "No module named ensurepip")]
            with mock.patch.object(bootstrap, "_validate_secure_path"):
                with self.assertRaisesRegex(RuntimeError, "Bootstrapping pip in the venv"):
                    bootstrap._prepare_environment(directory)
            self.assertTrue(all(call.args[0] == str(path / "bin" / "python") for call in self.run.call_args_list))

    def test_ready_venv_does_not_check_or_bootstrap_pip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "bin").mkdir()
            (path / "bin" / "python").touch()
            (path / "pyvenv.cfg").touch()
            with mock.patch.object(bootstrap, "_validate_secure_path"):
                self.assertEqual(bootstrap._prepare_environment(directory), str(path / "bin" / "python"))
            self.assertEqual(self.run.call_count, 2)
            self.assertEqual(self.run.call_args.args[1:], (
                "-c", bootstrap.DEPENDENCY_CHECK, str(bootstrap.REQUIREMENTS_PATH)
            ))

    def test_run_uses_isolated_interpreter_and_captures_output(self):
        self.run_patcher.stop()
        with mock.patch.object(bootstrap.subprocess, "run", return_value=result()) as run:
            bootstrap._run(sys.executable, "-m", "pip", "--version")
        self.assertEqual(
            run.call_args.args[0],
            [sys.executable, "-I", "-c", bootstrap.RUN_COMMAND,
             str(ROOT / "src" / "azfilesauthbootstrap.py"), "-m", "pip", "--version"],
        )
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.PIPE)


class TestSecurePaths(unittest.TestCase):
    def test_relative_root_and_parent_traversal_rejected(self):
        for value in ("relative", "/", "/opt/../tmp/venv"):
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "absolute, non-root"):
                bootstrap._validate_secure_path(Path(value))

    def test_symlinks_rejected(self):
        info = mock.Mock(st_mode=stat.S_IFLNK | 0o755, st_uid=0)
        with mock.patch.object(Path, "lstat", return_value=info):
            with self.assertRaisesRegex(RuntimeError, "Symlinks"):
                bootstrap._validate_secure_path(Path("/opt/venv"))

    def test_nonroot_owned_and_writable_paths_rejected(self):
        for owner, mode in ((1000, 0o755), (0, 0o775), (0, 0o777)):
            info = mock.Mock(st_mode=stat.S_IFDIR | mode, st_uid=owner)
            with self.subTest(owner=owner, mode=mode), mock.patch.object(Path, "lstat", return_value=info):
                with self.assertRaisesRegex(RuntimeError, "root-owned"):
                    bootstrap._validate_secure_path(Path("/opt/venv"))

    def test_secure_and_missing_components_allowed(self):
        info = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        with mock.patch.object(Path, "lstat", side_effect=[info, info, FileNotFoundError()]):
            bootstrap._validate_secure_path(Path("/opt/venv"))


class TestNativeConfig(unittest.TestCase):
    def test_native_error_propagated(self):
        library = mock.Mock()

        def read(value, value_size, error, error_size):
            error.value = b"configuration root must be a mapping"
            return 1

        library.extern_azfilesauth_venv_path.side_effect = read
        with mock.patch.object(bootstrap, "_validate_secure_path"), \
                mock.patch.object(bootstrap.os.path, "exists", return_value=True), \
                mock.patch.object(bootstrap.ctypes, "CDLL", return_value=library):
            with self.assertRaisesRegex(RuntimeError, "configuration root must be a mapping"):
                bootstrap._configured_venv()

    def test_native_path_read_without_pyyaml(self):
        library = mock.Mock()

        def read(value, value_size, error, error_size):
            value.value = b"/opt/azfilesauth/venv"
            return 0

        library.extern_azfilesauth_venv_path.side_effect = read
        with mock.patch.object(bootstrap, "_validate_secure_path"), \
                mock.patch.object(bootstrap.os.path, "exists", return_value=True), \
                mock.patch.object(bootstrap.ctypes, "CDLL", return_value=library):
            self.assertEqual(bootstrap._configured_venv(), "/opt/azfilesauth/venv")


class TestSystemSitePackages(unittest.TestCase):
    def test_existing_interpreter_sites_are_not_revalidated(self):
        directory = "/usr/local/lib/python3.8/dist-packages"
        with mock.patch.object(bootstrap.sys, "prefix", "/usr"), \
                mock.patch.object(bootstrap.sys, "base_prefix", "/usr"), \
                mock.patch.object(bootstrap.sys, "path", [directory]), \
                mock.patch.object(bootstrap.site, "getsitepackages", return_value=[directory]), \
                mock.patch.object(bootstrap, "_validate_secure_path") as validate, \
                mock.patch.object(bootstrap.site, "addsitedir") as add:
            bootstrap._add_system_site_packages()
        validate.assert_not_called()
        add.assert_not_called()

    def test_local_system_sites_validated_before_adding(self):
        directory = "/usr/local/lib/python3.9/site-packages"
        events = []
        with mock.patch.object(bootstrap.sys, "prefix", "/usr"), \
                mock.patch.object(bootstrap.sys, "base_prefix", "/usr"), \
                mock.patch.object(bootstrap.site, "getsitepackages", return_value=[directory]) as paths, \
                mock.patch.object(Path, "is_dir", return_value=True), \
                mock.patch.object(bootstrap, "_validate_secure_path",
                                  side_effect=lambda path: events.append(("validate", str(path)))), \
                mock.patch.object(bootstrap.site, "addsitedir",
                                  side_effect=lambda path: events.append(("add", path))):
            bootstrap._add_system_site_packages()
        paths.assert_called_once_with(["/usr/local"])
        self.assertEqual(events, [("validate", directory), ("add", directory)])

    def test_venv_never_inherits_system_local_packages(self):
        with mock.patch.object(bootstrap.sys, "prefix", "/opt/venv"), \
                mock.patch.object(bootstrap.sys, "base_prefix", "/usr"), \
                mock.patch.object(bootstrap.site, "addsitedir") as add:
            bootstrap._add_system_site_packages()
        add.assert_not_called()

    def test_unsafe_system_site_is_rejected(self):
        with mock.patch.object(bootstrap.sys, "prefix", "/usr"), \
                mock.patch.object(bootstrap.sys, "base_prefix", "/usr"), \
                mock.patch.object(bootstrap.site, "getsitepackages", return_value=["/usr/local/lib/site-packages"]), \
                mock.patch.object(Path, "is_dir", return_value=True), \
                mock.patch.object(bootstrap, "_validate_secure_path", side_effect=RuntimeError("unsafe")), \
                mock.patch.object(bootstrap.site, "addsitedir") as add:
            with self.assertRaisesRegex(RuntimeError, "unsafe"):
                bootstrap._add_system_site_packages()
        add.assert_not_called()


class TestStartup(unittest.TestCase):
    def test_nonroot_fails_before_loading_config(self):
        with mock.patch.object(bootstrap.os, "geteuid", return_value=1000), \
                mock.patch.object(bootstrap, "_configured_venv") as config, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(SystemExit) as exit_result:
                bootstrap.bootstrap()
        self.assertEqual(exit_result.exception.code, 1)
        config.assert_not_called()
        self.assertIn("as root", errors.getvalue())

    def test_setup_locked_and_reexec_preserves_arguments(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(bootstrap.os, "geteuid", return_value=0), \
                mock.patch.object(bootstrap, "_configured_venv", return_value="/opt/venv"), \
                mock.patch.object(bootstrap, "LOCK_PATH", str(Path(directory) / "lock")), \
                mock.patch.object(bootstrap.os, "fstat", return_value=mock.Mock(st_mode=stat.S_IFREG | 0o600, st_uid=0)), \
                mock.patch.object(bootstrap.fcntl, "flock") as flock, \
                mock.patch.object(bootstrap, "_prepare_environment", return_value="/opt/venv/bin/python") as prepare, \
                mock.patch.object(bootstrap.os, "execv") as execute:
            bootstrap.bootstrap()
            flock.assert_called_once()
            self.assertEqual(flock.call_args.args[1], bootstrap.fcntl.LOCK_EX)
            prepare.assert_called_once_with("/opt/venv")
            execute.assert_called_once_with("/opt/venv/bin/python", ["/opt/venv/bin/python", "-I", *sys.argv])

    def test_setup_failure_goes_to_stderr_and_exits(self):
        with mock.patch.object(bootstrap.os, "geteuid", return_value=0), \
                mock.patch.object(bootstrap, "_configured_venv", side_effect=RuntimeError("invalid config")), \
                contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(SystemExit):
                bootstrap.bootstrap()
        self.assertEqual(output.getvalue(), "")
        self.assertIn("invalid config", errors.getvalue())


class TestPackaging(unittest.TestCase):
    def test_debian_supplies_venv_support_as_a_package_prerequisite(self):
        control = (ROOT / "debian/control").read_text()
        dependencies = next(line for line in control.splitlines() if line.startswith("Depends:"))
        self.assertIn("python3-venv", dependencies)

    def test_no_package_time_python_installs_or_pip_dependencies(self):
        for filename in ("debian/postinst", "rpm.spec"):
            source = (ROOT / filename).read_text()
            self.assertNotIn("-m pip install", source)
            self.assertNotIn("SKIP_PIP_INSTALL", source)
        for filename in ("debian/control", "rpm.spec"):
            source = (ROOT / filename).read_text()
            self.assertNotIn("python3-pip", source)
            self.assertNotIn("python311-pip", source)


@unittest.skipUnless(importlib.util.find_spec("packaging"), "Requires the packaging runtime dependency")
class TestRequirementVersions(unittest.TestCase):
    def test_minimum_versions_and_imports_checked_in_selected_interpreter(self):
        setup = """
import importlib.metadata
import json
import sys
import types
class RejectPip:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "pip" or fullname.startswith("pip."):
            raise ModuleNotFoundError("pip is deliberately unavailable")
sys.meta_path.insert(0, RejectPip())
versions = json.loads(sys.argv[2])
importlib.metadata.version = lambda name: versions[name]
for name in ("azure", "azure.identity", "azure.core", "azure.core.exceptions", "yaml"):
    sys.modules[name] = types.ModuleType(name)
sys.modules["azure.identity"].ManagedIdentityCredential = object
sys.modules["azure.identity"].ClientAssertionCredential = object
sys.modules["azure.core.exceptions"].ClientAuthenticationError = Exception
"""
        minimums = {"azure-identity": "1.14.0", "azure-core": "1.26.0", "PyYAML": "5.4", "packaging": "20.0"}
        variants = [
            (minimums, True),
            ({**minimums, "azure-identity": "1.13.9"}, False),
            ({**minimums, "azure-core": "1.25.9"}, False),
            ({**minimums, "PyYAML": "5.3.9"}, False),
            ({**minimums, "packaging": "19.2"}, False),
            ({**minimums, "azure-identity": "1.14.0rc1"}, False),
            ({**minimums, "azure-identity": "1.15.0", "PyYAML": "6.0.3"}, True),
        ]
        for versions, expected in variants:
            with self.subTest(versions=versions):
                check = subprocess.run(
                    [sys.executable, "-I", "-c", setup + bootstrap.DEPENDENCY_CHECK,
                     str(ROOT / "requirements.txt"), json.dumps(versions)],
                    capture_output=True, text=True,
                )
                self.assertEqual(check.returncode == 0, expected, check.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
