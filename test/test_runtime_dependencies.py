#!/usr/bin/env python3
"""Installed-package tests. Run only in an explicitly opted-in disposable container."""

import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


CONFIG = Path("/etc/azfilesauth/config.yaml")
MANAGER = shutil.which("azfilesauthmanager")
DAEMON = shutil.which("azfilesrefresh")


@unittest.skipUnless(
    os.environ.get("RUN_RUNTIME_DEPENDENCY_TESTS") == "1"
    and Path("/.dockerenv").exists()
    and os.geteuid() == 0,
    "Requires an opted-in disposable root Docker container",
)
class TestInstalledRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not MANAGER or not DAEMON:
            raise RuntimeError("Install the package before running runtime tests")
        cls.original_config = CONFIG.read_bytes()
        cls.workspace = Path(tempfile.mkdtemp(prefix="runtime-e2e-", dir="/opt"))
        cls.system_python = Path(MANAGER).read_text().splitlines()[0][2:]
        spec = importlib.util.spec_from_file_location(
            "installed_bootstrap", "/usr/share/azfilesauth/azfilesauthbootstrap.py"
        )
        cls.bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.bootstrap)

    @classmethod
    def tearDownClass(cls):
        CONFIG.write_bytes(cls.original_config)
        shutil.rmtree(cls.workspace)

    def tearDown(self):
        CONFIG.write_bytes(self.original_config)

    def configure(self, path):
        CONFIG.write_text("PYTHON_VENV_PATH: " + json.dumps(str(path)) + "\n")

    def run_command(self, arguments, success=True, offline=False):
        environment = os.environ.copy()
        if offline:
            environment["PIP_NO_INDEX"] = "1"
            environment["PIP_FIND_LINKS"] = ""
        result = subprocess.run(
            arguments, text=True, capture_output=True, env=environment, timeout=180
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def assert_startup_failure(self, message, offline=False):
        for arguments in ([MANAGER, "--version"], [DAEMON]):
            with self.subTest(command=arguments[0]):
                result = self.run_command(arguments, success=False, offline=offline)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("runtime setup failed", result.stderr)
                self.assertIn(message, result.stderr)

    def test_concurrent_creation_offline_start_and_pip_recovery(self):
        path = self.workspace / "venv with spaces"
        self.configure(path)
        processes = [
            subprocess.Popen([MANAGER, "--version"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
            for _ in range(2)
        ]
        outputs = []
        try:
            for process in processes:
                stdout, stderr = process.communicate(timeout=180)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                outputs.append(stderr)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        combined = "".join(outputs)
        self.assertEqual(combined.count("creating Python venv"), 1, combined)
        self.assertEqual(combined.count("installing Python requirements"), 1, combined)
        python = str(path / "bin" / "python")
        self.run_command([python, "-I", "-c", self.bootstrap.DEPENDENCY_CHECK,
                          str(self.bootstrap.REQUIREMENTS_PATH)])
        ready = self.run_command([MANAGER, "--version"], offline=True)
        self.assertNotIn("azfilesauth:", ready.stderr)
        self.run_command([python, "-m", "pip", "uninstall", "-y", "pip"])
        self.run_command([MANAGER, "--version"], offline=True)
        self.run_command([python, "-I", "-m", "pip", "--version"], success=False)
        yaml_file = self.run_command(
            [python, "-I", "-c", "import yaml; print(yaml.__file__)"]
        ).stdout.strip()
        yaml_package = Path(yaml_file).parent
        metadata = next(
            entry for entry in yaml_package.parent.glob("*.dist-info")
            if entry.name.lower().startswith("pyyaml-")
        )
        shutil.move(str(yaml_package), str(self.workspace / "removed-yaml"))
        shutil.move(str(metadata), str(self.workspace / "removed-yaml-metadata"))
        self.run_command([MANAGER, "--version"])
        self.run_command([python, "-I", "-m", "pip", "--version"])

        self.run_command([MANAGER, "list"])
        tickets = self.run_command([MANAGER, "list", "--json"], offline=True)
        self.assertIsInstance(json.loads(tickets.stdout), list)

    def test_daemon_installs_missing_dependencies_before_starting(self):
        path = self.workspace / "daemon-venv"
        self.configure(path)
        self.assert_daemon_ready(str(path / "bin" / "python"))

    def assert_daemon_ready(self, python):
        log_path = Path("/var/log/azfilesrefresh.log")
        offset = log_path.stat().st_size if log_path.exists() else 0
        with tempfile.TemporaryFile(mode="w+") as errors:
            process = subprocess.Popen([DAEMON], stdout=subprocess.DEVNULL, stderr=errors)
            try:
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        errors.seek(0)
                        self.fail("Daemon exited during runtime setup: " + errors.read())
                    if log_path.exists():
                        with log_path.open() as log:
                            log.seek(offset)
                            if "AZ Files Refresh Daemon started." in log.read():
                                break
                    time.sleep(1)
                else:
                    self.fail("Daemon did not become ready")
                check = self.bootstrap._run(
                    python, "-c", self.bootstrap.DEPENDENCY_CHECK,
                    str(self.bootstrap.REQUIREMENTS_PATH),
                )
                self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def test_install_failure_is_fatal_for_cli_and_daemon(self):
        self.configure(self.workspace / "offline-empty-venv")
        self.assert_startup_failure("Python dependency installation", offline=True)

    def test_invalid_and_unsafe_venvs_fail_without_system_fallback(self):
        for value, message in (
            ("relative-venv", "absolute, non-root"),
            (str(self.workspace), "not a Python venv"),
        ):
            self.configure(value)
            self.assert_startup_failure(message)
        unsafe = self.workspace / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        self.configure(unsafe)
        self.assert_startup_failure("not group/world writable")
        CONFIG.write_text("PYTHON_VENV_PATH: []\n")
        self.assert_startup_failure("must be a scalar")

    def test_system_dependencies_work_without_pip_and_missing_dependencies_fail(self):
        CONFIG.write_text("\n")
        target = self.prepare_system_dependencies()
        self.run_command([MANAGER, "--version"])
        probe = self.run_command(
            [self.system_python, "-I", "-c", "import pip; print(pip.__path__[0])"],
        )
        package = Path(probe.stdout.strip())
        hidden = package.with_name(package.name + ".azfilesauth-e2e-hidden")
        self.assertFalse(hidden.exists())
        shutil.move(str(package), str(hidden))
        try:
            ready = self.run_command([MANAGER, "--version"], offline=True)
            self.assertNotIn("azfilesauth:", ready.stderr)
            self.assert_daemon_ready(self.system_python)
            azure = target / "azure"
            hidden_azure = self.workspace / "removed-system-azure"
            shutil.move(str(azure), str(hidden_azure))
            try:
                self.assert_startup_failure("pip is required for system Python")
            finally:
                shutil.move(str(hidden_azure), str(azure))
        finally:
            shutil.move(str(hidden), str(package))

    def test_system_install_or_explicit_pep668_failure(self):
        CONFIG.write_text("\n")
        target = self.prepare_system_dependencies()
        entries = [target / "azure"] + [
            entry for entry in target.glob("*.dist-info")
            if entry.name.lower().replace("-", "_").startswith(("azure_identity_", "azure_core_"))
        ]
        for entry in entries:
            shutil.move(str(entry), str(self.workspace / ("original-" + entry.name)))
        try:
            self.check_system_install()
        finally:
            for entry in entries:
                if entry.exists():
                    shutil.move(str(entry), str(self.workspace / ("installed-" + entry.name)))
                shutil.move(str(self.workspace / ("original-" + entry.name)), str(entry))

    def prepare_system_dependencies(self):
        target = Path(self.run_command(
            [self.system_python, "-I", "-c",
             "import os,site,sys; print(site.getsitepackages([os.path.join(sys.prefix, 'local')])[-1])"]
        ).stdout.strip())
        source = Path(importlib.metadata.distribution("azure-identity").locate_file(""))
        target.mkdir(parents=True, exist_ok=True)
        for entry in source.iterdir():
            if entry.name == "pip" or entry.name.startswith("pip-"):
                continue
            if entry.is_dir():
                shutil.copytree(str(entry), str(target / entry.name), dirs_exist_ok=True)
            else:
                shutil.copy2(str(entry), str(target / entry.name))
        return target

    def check_system_install(self):
        self.run_command([self.system_python, "-I", "-m", "pip", "--version"])
        marker = self.run_command(
            [self.system_python, "-I", "-c",
             "import pathlib,sysconfig; print(int((pathlib.Path(sysconfig.get_path('stdlib'))"
             " / 'EXTERNALLY-MANAGED').exists()))"]
        )
        if marker.stdout.strip() == "1":
            self.assert_startup_failure("externally-managed-environment")
        else:
            self.run_command([MANAGER, "--version"])
            ready = self.run_command([MANAGER, "--version"], offline=True)
            self.assertNotIn("azfilesauth:", ready.stderr)
            check = self.bootstrap._run(
                self.system_python, "-c", self.bootstrap.DEPENDENCY_CHECK,
                str(self.bootstrap.REQUIREMENTS_PATH),
            )
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_package_metadata_has_no_pip_dependency_or_install_hook(self):
        if shutil.which("dpkg-query"):
            dependencies = self.run_command(
                ["dpkg-query", "-W", "-f=${Depends}", "azfilesauth"]
            ).stdout
            hooks = Path("/var/lib/dpkg/info/azfilesauth.postinst").read_text()
        else:
            dependencies = self.run_command(["rpm", "-q", "--requires", "azfilesauth"]).stdout
            hooks = self.run_command(["rpm", "-q", "--scripts", "azfilesauth"]).stdout
        self.assertNotIn("pip", dependencies.lower())
        self.assertNotIn("-m pip", hooks)
        self.assertNotIn("azure.identity", hooks)


if __name__ == "__main__":
    unittest.main(verbosity=2)
