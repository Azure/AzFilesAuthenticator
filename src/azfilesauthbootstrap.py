"""Standard-library-only dependency setup shared by the CLI and refresh daemon."""

import ctypes
import fcntl
import os
from pathlib import Path
import site
import stat
import subprocess
import sys


CONFIG_PATH = Path("/etc/azfilesauth/config.yaml")
LOCK_PATH = "/run/azfilesauth-bootstrap.lock"
LIBRARY_PATHS = (
    "/usr/lib/libazfilesauth.so",
    "/usr/lib64/libazfilesauth.so",
    "/usr/local/lib/libazfilesauth.so",
)
REQUIREMENTS_PATH = Path(__file__).with_name("requirements.txt")

RUN_COMMAND = """
import runpy
import sys
runtime = runpy.run_path(sys.argv.pop(1))
runtime["_add_system_site_packages"]()
mode = sys.argv.pop(1)
if mode == "-m":
    module = sys.argv.pop(1)
    sys.argv[0] = module
    runpy.run_module(module, run_name="__main__", alter_sys=True)
elif mode == "-c":
    exec(sys.argv.pop(1), {"__name__": "__main__"})
else:
    raise RuntimeError("Unsupported runtime command: " + mode)
"""

DEPENDENCY_CHECK = """
import importlib.metadata
import sys
from packaging.requirements import Requirement
for line in open(sys.argv[1]):
    line = line.strip()
    if line and not line.startswith("#"):
        requirement = Requirement(line)
        version = importlib.metadata.version(requirement.name)
        if not requirement.specifier.contains(version):
            raise RuntimeError(str(requirement) + "; installed version is " + version)
from azure.identity import ManagedIdentityCredential, ClientAssertionCredential
from azure.core.exceptions import ClientAuthenticationError
import yaml
"""


def _validate_secure_path(path: Path) -> None:
    if not path.is_absolute() or str(path) == "/" or ".." in path.parts:
        raise RuntimeError(f"Expected an absolute, non-root path without '..': {path}")
    for component in reversed((path,) + tuple(path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"Symlinks are not allowed in the runtime environment path: {component}")
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f"Runtime path must be root-owned and not group/world writable: {component}")


def _configured_venv() -> str:
    _validate_secure_path(CONFIG_PATH)
    for path in LIBRARY_PATHS:
        if os.path.exists(path):
            library = ctypes.CDLL(path)
            break
    else:
        raise RuntimeError("Cannot find libazfilesauth.so")
    read_path = library.extern_azfilesauth_venv_path
    read_path.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
    read_path.restype = ctypes.c_int
    value = ctypes.create_string_buffer(4096)
    error = ctypes.create_string_buffer(4096)
    if read_path(value, len(value), error, len(error)) != 0:
        raise RuntimeError(f"Cannot read {CONFIG_PATH}: {error.value.decode(errors='replace')}")
    return os.fsdecode(value.value)


def _add_system_site_packages() -> None:
    if sys.prefix != sys.base_prefix:
        return
    # RHEL omits root-owned /usr/local pip destinations when Python uses -I.
    for directory in site.getsitepackages([os.path.join(sys.prefix, "local")]):
        if directory in sys.path:
            continue
        path = Path(directory)
        if path.is_dir():
            _validate_secure_path(path)
            site.addsitedir(directory)


def _run(python: str, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [python, "-I", "-c", RUN_COMMAND, os.path.abspath(__file__), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def _require_success(result: subprocess.CompletedProcess, action: str) -> None:
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{action} failed (exit {result.returncode}): {detail}")


def _prepare_environment(venv_path: str) -> str:
    python = sys.executable
    if venv_path:
        path = Path(venv_path)
        _validate_secure_path(path)
        if not path.exists():
            print(f"azfilesauth: creating Python venv at {path}", file=sys.stderr, flush=True)
            _require_success(
                _run(python, "-m", "venv", "--without-pip", str(path)),
                "Venv creation; install your distribution's Python venv support if unavailable",
            )
        if not (path / "pyvenv.cfg").is_file():
            raise RuntimeError(f"Configured path is not a Python venv: {path}")
        python = str(path / "bin" / "python")
        _validate_secure_path(path / "pyvenv.cfg")
        for line in (path / "pyvenv.cfg").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip().lower() == "include-system-site-packages" and value.strip().lower() == "true":
                raise RuntimeError(f"Venv must not include system site packages: {path}")
        _validate_secure_path(path / "bin")
        # Interpreter symlinks are normal in venvs; validate their final target.
        _validate_secure_path(Path(python).resolve(strict=True))
        _require_success(
            _run(python, "-c", "import os, sys; assert sys.prefix != sys.base_prefix; "
                 "assert os.path.samefile(sys.prefix, sys.argv[1])", str(path)),
            "Venv interpreter validation",
        )
    elif sys.prefix != sys.base_prefix:
        python = sys._base_executable

    check = _run(python, "-c", DEPENDENCY_CHECK, str(REQUIREMENTS_PATH))
    if not check.returncode:
        return python

    pip_check = _run(python, "-m", "pip", "--version")
    if pip_check.returncode:
        if not venv_path:
            raise RuntimeError(
                f"pip is required for system Python ({python}). Install pip for that interpreter "
                "or configure PYTHON_VENV_PATH. " + pip_check.stderr.strip()
            )
        _require_success(
            _run(python, "-m", "ensurepip", "--upgrade"),
            "Bootstrapping pip in the venv; install your distribution's ensurepip/venv support if unavailable",
        )
        _require_success(_run(python, "-m", "pip", "--version"), "Verifying pip")

    print(f"azfilesauth: installing Python requirements using {python}", file=sys.stderr, flush=True)
    _require_success(
        _run(python, "-m", "pip", "--disable-pip-version-check", "install",
             "--no-input", "--no-cache-dir", "--retries", "2", "--timeout", "15",
             "-r", str(REQUIREMENTS_PATH)),
        "Python dependency installation; if system Python is externally managed, configure PYTHON_VENV_PATH",
    )
    _require_success(
        _run(python, "-c", DEPENDENCY_CHECK, str(REQUIREMENTS_PATH)),
        "Python dependency verification",
    )
    return python


def bootstrap() -> None:
    try:
        if os.geteuid() != 0:
            raise RuntimeError("Run this command as root")
        venv_path = _configured_venv()
        descriptor = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "r+") as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError(f"Unsafe runtime lock file: {LOCK_PATH}")
            fcntl.flock(lock, fcntl.LOCK_EX)
            python = _prepare_environment(venv_path)
        if python != sys.executable or not sys.flags.isolated:
            os.execv(python, [python, "-I", *sys.argv])
        _add_system_site_packages()
    except (OSError, RuntimeError, AttributeError, UnicodeError) as error:
        print(f"azfilesauth: runtime setup failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
