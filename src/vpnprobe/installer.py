"""Interactive installation of external runtime dependencies for `vpnprobe setup`."""

from __future__ import annotations

import hashlib
import io
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from vpnprobe import __version__
from vpnprobe.diagnostics import check_dependencies, print_dependency_check
from vpnprobe.errors import ConfigurationError, ProbeError, SetupError
from vpnprobe.tdlib import TdJson

PINNED_XRAY_KNIFE = "10.1.1"
PINNED_HYSTERIA = "2.12.1"
TDLIB_PACKAGE = "libtdjson1.8.38"
SYSTEM_BIN = Path("/usr/local/bin")
DOWNLOAD_TIMEOUT = 120.0
# download.hysteria.network answers HTTP 403 to the default Python-urllib agent.
USER_AGENT = f"vpnprobe/{__version__}"

XRAY_KNIFE_RELEASES = "https://github.com/lilendian0x00/xray-knife/releases"
HYSTERIA_DOWNLOADS = "https://download.hysteria.network/app"

_VERSION = re.compile(r"\d+\.\d+\.\d+")
_ARCHITECTURES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
_XRAY_KNIFE_ASSETS = {"amd64": "Xray-knife-linux-64.zip", "arm64": "Xray-knife-linux-arm64-v8a.zip"}

Ask = Callable[[str], str]


@dataclass(frozen=True, slots=True)
class _Tool:
    name: str
    pinned: str
    version_arguments: tuple[str, ...]
    latest_version: Callable[[str], str]
    download: Callable[[str, str], bytes]


@dataclass(frozen=True, slots=True)
class _Prompter:
    yes: bool
    interactive: bool
    ask: Ask

    def confirm(self, question: str) -> bool:
        if self.yes:
            print(f"{question} [Y/n] yes")
            return True
        if not self.interactive:
            print(f"SKIP {question} No terminal; rerun with --yes.")
            return False
        return self.ask(f"{question} [Y/n] ").strip().lower() in {"", "y", "yes"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def _is_root() -> bool:
    return os.geteuid() == 0


def _target_directory() -> Path:
    return SYSTEM_BIN if _is_root() else Path.home() / ".local" / "bin"


def _architecture() -> str:
    architecture = _ARCHITECTURES.get(platform.machine().lower())
    if architecture is None:
        raise SetupError(f"Unsupported architecture: {platform.machine()}")
    return architecture


def _request(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": USER_AGENT})


def _fetch(url: str) -> bytes:
    try:
        with urllib.request.urlopen(_request(url), timeout=DOWNLOAD_TIMEOUT) as response:
            return bytes(response.read())
    except urllib.error.URLError as exc:
        raise SetupError(f"Download failed: {url}: {exc.reason}") from None


def _redirect_location(url: str) -> str:
    """Return where url redirects without downloading the target."""
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(_request(url), timeout=DOWNLOAD_TIMEOUT) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location")
        if exc.code in {301, 302, 303, 307, 308} and location:
            return str(location)
        raise SetupError(f"Cannot resolve the latest release from {url}: HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise SetupError(f"Cannot resolve the latest release from {url}: {exc.reason}") from None
    raise SetupError(f"Expected a redirect from {url}, got HTTP {status}")


def _version_in(text: str) -> str:
    match = _VERSION.search(text)
    if match is None:
        raise SetupError(f"No version number in {text}")
    return match.group(0)


def _verify(data: bytes, expected: str, label: str) -> None:
    if hashlib.sha256(data).hexdigest() != expected.strip().lower():
        raise SetupError(f"Checksum mismatch for {label}")


def _digest_from_dgst(text: str) -> str:
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "SHA2-256" and value.strip():
            return value.strip()
    raise SetupError("xray-knife digest file has no SHA2-256 entry")


def _digest_from_hashes(text: str, name: str) -> str:
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].rsplit("/", 1)[-1] == name:
            return parts[0]
    raise SetupError(f"Hysteria hashes.txt has no entry for {name}")


def _latest_xray_knife(_architecture: str) -> str:
    return _version_in(_redirect_location(f"{XRAY_KNIFE_RELEASES}/latest"))


def _download_xray_knife(version: str, architecture: str) -> bytes:
    url = f"{XRAY_KNIFE_RELEASES}/download/v{version}/{_XRAY_KNIFE_ASSETS[architecture]}"
    archive = _fetch(url)
    _verify(archive, _digest_from_dgst(_fetch(f"{url}.dgst").decode()), url)
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        try:
            return bundle.read("xray-knife")
        except KeyError:
            raise SetupError(f"{url} does not contain xray-knife") from None


def _latest_hysteria(architecture: str) -> str:
    return _version_in(
        _redirect_location(f"{HYSTERIA_DOWNLOADS}/latest/hysteria-linux-{architecture}")
    )


def _download_hysteria(version: str, architecture: str) -> bytes:
    name = f"hysteria-linux-{architecture}"
    base = f"{HYSTERIA_DOWNLOADS}/v{version}"
    binary = _fetch(f"{base}/{name}")
    _verify(binary, _digest_from_hashes(_fetch(f"{base}/hashes.txt").decode(), name), name)
    return binary


def _tools() -> tuple[_Tool, ...]:
    return (
        _Tool(
            "xray-knife",
            PINNED_XRAY_KNIFE,
            ("--version",),
            _latest_xray_knife,
            _download_xray_knife,
        ),
        _Tool("hysteria", PINNED_HYSTERIA, ("version",), _latest_hysteria, _download_hysteria),
    )


def installed_version(executable: str, arguments: tuple[str, ...]) -> str | None:
    """Return the version reported by an executable on PATH, or None if it is unusable."""
    path = shutil.which(executable)
    if path is None:
        return None
    try:
        completed = subprocess.run(
            (path, *arguments),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = _VERSION.search(completed.stdout)
    return match.group(0) if completed.returncode == 0 and match else None


def _install_executable(data: bytes, directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    with tempfile.NamedTemporaryFile(dir=directory, prefix=f".{name}.", delete=False) as handle:
        handle.write(data)
        temporary = Path(handle.name)
    try:
        temporary.chmod(0o755)
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return target


def _setup_tool(tool: _Tool, *, pin: bool, prompter: _Prompter) -> None:
    installed = installed_version(tool.name, tool.version_arguments)
    if installed is not None and (not pin or installed == tool.pinned):
        print(f"OK {tool.name} {installed}")
        return
    architecture = _architecture()
    version = tool.pinned if pin else tool.latest_version(architecture)
    directory = _target_directory()
    state = "not found" if installed is None else f"{installed} differs from pinned {tool.pinned}"
    if not prompter.confirm(f"{tool.name} {state}. Install {version} into {directory}?"):
        return
    target = _install_executable(tool.download(version, architecture), directory, tool.name)
    print(f"INSTALLED {tool.name} {version} -> {target}")
    resolved = shutil.which(tool.name)
    if resolved is not None and Path(resolved) != target:
        print(f"WARNING {tool.name} on PATH is {resolved}, not {target}")


def _setup_tdlib(prompter: _Prompter) -> None:
    try:
        library = TdJson("").library_name
    except (ConfigurationError, OSError):
        pass
    else:
        print(f"OK TDLib {library}")
        return
    if not _is_root():
        print(f"SKIP TDLib not found. Install it with: sudo apt install {TDLIB_PACKAGE}")
        return
    if not prompter.confirm(f"TDLib not found. Install the Debian package {TDLIB_PACKAGE}?"):
        return
    for command in (("apt-get", "update"), ("apt-get", "install", "--yes", TDLIB_PACKAGE)):
        completed = subprocess.run(command, check=False)
        if completed.returncode != 0:
            raise SetupError(f"{' '.join(command)} exited {completed.returncode}")
    print(f"INSTALLED TDLib {TDLIB_PACKAGE}")


def run_setup(
    *,
    yes: bool = False,
    pin: bool = False,
    ask: Ask = input,
    interactive: bool | None = None,
) -> int:
    """Offer to install each missing dependency, then print the `check` report.

    Latest releases are installed unless pin is set. Root installs executables into
    /usr/local/bin and TDLib with apt; other users get ~/.local/bin and a sudo hint.
    Returns 0 only when every dependency is available afterwards.
    """
    prompter = _Prompter(yes, sys.stdin.isatty() if interactive is None else interactive, ask)
    directory = str(_target_directory())
    search_path = os.environ.get("PATH", "")
    if directory not in search_path.split(os.pathsep):
        print(f"WARNING {directory} is not on PATH; run: pipx ensurepath")
        # Let this process find what it installs there, including the final check.
        os.environ["PATH"] = os.pathsep.join(filter(None, (search_path, directory)))
    steps: list[tuple[str, Callable[[], None]]] = [
        (tool.name, partial(_setup_tool, tool, pin=pin, prompter=prompter)) for tool in _tools()
    ]
    steps.append(("TDLib", partial(_setup_tdlib, prompter)))
    for name, step in steps:
        try:
            step()
        except (ProbeError, OSError) as exc:
            print(f"ERR {name}: {str(exc).strip() or type(exc).__name__}")
    print()
    return print_dependency_check(check_dependencies())
