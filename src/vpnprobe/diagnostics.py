"""Local runtime dependency diagnostics for the vpnprobe CLI."""

from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import dataclass

from vpnprobe.errors import ConfigurationError
from vpnprobe.tdlib import TdJson

XRAY_KNIFE_INSTALL = (
    "Download the latest archive: https://github.com/lilendian0x00/xray-knife/releases/latest"
)
TDLIB_INSTALL = "Install the Debian 13 package: sudo apt install libtdjson1.8.38"


@dataclass(frozen=True, slots=True)
class DependencyResult:
    name: str
    available: bool
    detail: str
    install: str


def _hysteria_install() -> str:
    architectures = {
        "aarch64": "arm64",
        "amd64": "amd64",
        "arm64": "arm64",
        "armv7l": "arm",
        "i386": "386",
        "i686": "386",
        "riscv64": "riscv64",
        "x86_64": "amd64",
    }
    architecture = architectures.get(platform.machine().lower())
    if architecture is None:
        return "Download the latest executable for this architecture: https://github.com/apernet/hysteria/releases/latest"
    return (
        "Download the latest executable: "
        f"https://download.hysteria.network/app/latest/hysteria-linux-{architecture}; "
        "install it as /usr/local/bin/hysteria with mode 0755"
    )


def _version_line(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in lines:
        if line.lower().startswith(("version", "xray-knife")):
            return line.replace("\t", " ")
    return lines[0] if lines else "version command produced no output"


def _executable(
    name: str,
    configured_path: str,
    version_arguments: tuple[str, ...],
    install: str,
) -> DependencyResult:
    executable = shutil.which(configured_path)
    if executable is None:
        return DependencyResult(name, False, f"executable not found: {configured_path}", install)
    try:
        completed = subprocess.run(
            (executable, *version_arguments),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DependencyResult(name, False, str(exc) or type(exc).__name__, install)
    detail = _version_line(completed.stdout)
    if completed.returncode != 0:
        return DependencyResult(
            name,
            False,
            f"version command exited {completed.returncode}: {detail}",
            install,
        )
    return DependencyResult(name, True, f"{executable} ({detail})", install)


def check_dependencies(
    *,
    xray_knife_path: str = "xray-knife",
    hysteria_path: str = "hysteria",
    tdjson_library: str = "",
) -> tuple[DependencyResult, ...]:
    """Inspect every external runtime dependency without network access."""
    results = [
        _executable(
            "xray-knife",
            xray_knife_path,
            ("--version",),
            XRAY_KNIFE_INSTALL,
        ),
        _executable(
            "hysteria",
            hysteria_path,
            ("version",),
            _hysteria_install(),
        ),
    ]
    try:
        library_name = TdJson(tdjson_library).library_name
    except (ConfigurationError, OSError) as exc:
        results.append(
            DependencyResult("TDLib", False, str(exc) or type(exc).__name__, TDLIB_INSTALL)
        )
    else:
        results.append(DependencyResult("TDLib", True, library_name, TDLIB_INSTALL))
    return tuple(results)


def print_dependency_check(results: tuple[DependencyResult, ...]) -> int:
    """Print concise diagnostics and return a conventional process status."""
    for result in results:
        marker = "OK" if result.available else "ERR"
        print(f"{marker} {result.name}: {result.detail}")
        if not result.available:
            print(f"  {result.install}")
    available = sum(result.available for result in results)
    print(f"Dependencies: {available}/{len(results)} available")
    return 0 if available == len(results) else 1
