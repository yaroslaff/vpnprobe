from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import urllib.error
import zipfile
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from vpnprobe import cli, installer
from vpnprobe.errors import ConfigurationError, SetupError

XRAY_URL = f"{installer.XRAY_KNIFE_RELEASES}/download/v10.1.1/Xray-knife-linux-64.zip"
HYSTERIA_BASE = f"{installer.HYSTERIA_DOWNLOADS}/v2.12.1"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def zipped(member: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr(member, data)
    return buffer.getvalue()


def test_parsing_and_checksums() -> None:
    assert installer._version_in(f"{installer.XRAY_KNIFE_RELEASES}/tag/v11.2.0") == "11.2.0"
    with pytest.raises(SetupError, match="No version"):
        installer._version_in("latest")
    assert installer._digest_from_dgst("MD5= aa\nSHA2-256= ABCDEF\n") == "ABCDEF"
    with pytest.raises(SetupError, match="SHA2-256"):
        installer._digest_from_dgst("MD5= aa\n")
    hashes = "111  build/hysteria-linux-amd64-avx\n222  build/hysteria-linux-amd64\n"
    assert installer._digest_from_hashes(hashes, "hysteria-linux-amd64") == "222"
    with pytest.raises(SetupError, match="no entry"):
        installer._digest_from_hashes(hashes, "hysteria-linux-arm64")
    installer._verify(b"x", sha256(b"x").upper(), "x")
    with pytest.raises(SetupError, match="Checksum mismatch"):
        installer._verify(b"x", "00", "x")


def test_architecture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
    assert installer._architecture() == "amd64"
    monkeypatch.setattr(installer.platform, "machine", lambda: "aarch64")
    assert installer._architecture() == "arm64"
    monkeypatch.setattr(installer.platform, "machine", lambda: "riscv64")
    with pytest.raises(SetupError, match="Unsupported architecture"):
        installer._architecture()


def test_target_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(installer.os, "geteuid", lambda: 1000)
    assert installer._target_directory() == tmp_path / ".local" / "bin"
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0)
    assert installer._target_directory() == installer.SYSTEM_BIN


def test_downloads_verify_published_checksums(monkeypatch: pytest.MonkeyPatch) -> None:
    archive = zipped("xray-knife", b"xray binary")
    files = {
        XRAY_URL: archive,
        f"{XRAY_URL}.dgst": f"MD5= aa\nSHA2-256= {sha256(archive)}\n".encode(),
        f"{HYSTERIA_BASE}/hysteria-linux-amd64": b"hysteria binary",
        f"{HYSTERIA_BASE}/hashes.txt": (
            f"{sha256(b'hysteria binary')}  build/hysteria-linux-amd64\n".encode()
        ),
    }
    monkeypatch.setattr(installer, "_fetch", files.__getitem__)
    assert installer._download_xray_knife("10.1.1", "amd64") == b"xray binary"
    assert installer._download_hysteria("2.12.1", "amd64") == b"hysteria binary"

    files[f"{HYSTERIA_BASE}/hysteria-linux-amd64"] = b"tampered"
    with pytest.raises(SetupError, match="Checksum mismatch"):
        installer._download_hysteria("2.12.1", "amd64")

    archive = zipped("README.md", b"no binary")
    files[XRAY_URL] = archive
    files[f"{XRAY_URL}.dgst"] = f"SHA2-256= {sha256(archive)}\n".encode()
    with pytest.raises(SetupError, match="does not contain"):
        installer._download_xray_knife("10.1.1", "amd64")


def test_latest_versions_come_from_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    locations = {
        f"{installer.XRAY_KNIFE_RELEASES}/latest": (f"{installer.XRAY_KNIFE_RELEASES}/tag/v11.2.0"),
        f"{installer.HYSTERIA_DOWNLOADS}/latest/hysteria-linux-amd64": (
            f"{installer.HYSTERIA_DOWNLOADS}/v2.12.2/hysteria-linux-amd64"
        ),
    }
    monkeypatch.setattr(installer, "_redirect_location", locations.__getitem__)
    assert installer._latest_xray_knife("amd64") == "11.2.0"
    assert installer._latest_hysteria("amd64") == "2.12.2"


class FakeResponse:
    status = 200

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return b"payload"


def test_fetch_and_redirect_location(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[Any] = []

    def urlopen(request: Any, timeout: float) -> FakeResponse:
        requests.append(request)
        return FakeResponse()

    monkeypatch.setattr(installer.urllib.request, "urlopen", urlopen)
    assert installer._fetch("https://example.com/file") == b"payload"
    assert requests[0].get_header("User-agent") == installer.USER_AGENT

    def unreachable(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(installer.urllib.request, "urlopen", unreachable)
    with pytest.raises(SetupError, match="Download failed"):
        installer._fetch("https://example.com/file")

    outcomes: list[Any] = []

    class Opener:
        def open(self, request: Any, timeout: float) -> FakeResponse:
            assert request.get_header("User-agent") == installer.USER_AGENT
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return FakeResponse()

    monkeypatch.setattr(installer.urllib.request, "build_opener", lambda *_handlers: Opener())

    def http_error(code: int, headers: dict[str, str]) -> urllib.error.HTTPError:
        return urllib.error.HTTPError("https://example.com", code, "status", headers, None)  # type: ignore[arg-type]

    outcomes.append(http_error(302, {"Location": "https://example.com/v1.2.3"}))
    assert installer._redirect_location("https://example.com") == "https://example.com/v1.2.3"
    outcomes.append(http_error(404, {}))
    with pytest.raises(SetupError, match="HTTP 404"):
        installer._redirect_location("https://example.com")
    outcomes.append(urllib.error.URLError("offline"))
    with pytest.raises(SetupError, match="offline"):
        installer._redirect_location("https://example.com")
    outcomes.append(None)
    with pytest.raises(SetupError, match="Expected a redirect"):
        installer._redirect_location("https://example.com")
    assert installer._NoRedirect().redirect_request() is None


def test_installed_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(installer.shutil, "which", lambda _name: None)
    assert installer.installed_version("xray-knife", ("--version",)) is None

    monkeypatch.setattr(installer.shutil, "which", lambda name: f"/usr/local/bin/{name}")
    completed = SimpleNamespace(returncode=0, stdout="xray-knife 11.2.0\n")
    monkeypatch.setattr(installer.subprocess, "run", lambda *_a, **_k: completed)
    assert installer.installed_version("xray-knife", ("--version",)) == "11.2.0"
    completed.returncode = 1
    assert installer.installed_version("xray-knife", ("--version",)) is None

    def timed_out(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired("xray-knife", 10)

    monkeypatch.setattr(installer.subprocess, "run", timed_out)
    assert installer.installed_version("xray-knife", ("--version",)) is None


def test_install_executable_replaces_atomically(tmp_path: Path) -> None:
    directory = tmp_path / "bin"
    target = installer._install_executable(b"old", directory, "tool")
    assert installer._install_executable(b"new", directory, "tool") == target
    assert target.read_bytes() == b"new"
    assert target.stat().st_mode & 0o777 == 0o755
    assert [path.name for path in directory.iterdir()] == ["tool"]


@pytest.fixture
def fake_system(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """Patch every external effect of run_setup and record what it did."""
    state: dict[str, Any] = {
        "installed": {"xray-knife": None, "hysteria": None},
        "downloads": [],
        "commands": [],
        "tdlib": True,
        "apt_status": 0,
    }
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setattr(installer, "_is_root", lambda: False)
    monkeypatch.setattr(installer, "_architecture", lambda: "amd64")
    monkeypatch.setattr(
        installer, "installed_version", lambda name, _args: state["installed"][name]
    )
    monkeypatch.setattr(installer, "_latest_xray_knife", lambda _arch: "11.2.0")
    monkeypatch.setattr(installer, "_latest_hysteria", lambda _arch: "2.12.2")

    def download(name: str) -> Any:
        def fetch(version: str, _architecture: str) -> bytes:
            state["downloads"].append((name, version))
            return f"{name} {version}".encode()

        return fetch

    monkeypatch.setattr(installer, "_download_xray_knife", download("xray-knife"))
    monkeypatch.setattr(installer, "_download_hysteria", download("hysteria"))

    def tdjson(_configured: str) -> SimpleNamespace:
        if not state["tdlib"]:
            raise ConfigurationError("TDLib JSON library was not found")
        return SimpleNamespace(library_name="libtdjson.so.1.8.38")

    monkeypatch.setattr(installer, "TdJson", tdjson)

    def run(command: tuple[str, ...], check: bool) -> SimpleNamespace:
        state["commands"].append(command)
        return SimpleNamespace(returncode=state["apt_status"])

    monkeypatch.setattr(installer.subprocess, "run", run)
    monkeypatch.setattr(installer, "check_dependencies", lambda: ())
    return state


def answers(*replies: str) -> Iterator[str]:
    return iter(replies)


def test_setup_installs_latest_into_user_bin(
    fake_system: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    replies = answers("", "n")
    assert installer.run_setup(ask=lambda _question: next(replies), interactive=True) == 0
    user_bin = tmp_path / ".local" / "bin"
    assert (user_bin / "xray-knife").read_bytes() == b"xray-knife 11.2.0"
    assert not (user_bin / "hysteria").exists()
    assert fake_system["downloads"] == [("xray-knife", "11.2.0")]
    output = capsys.readouterr().out
    assert f"INSTALLED xray-knife 11.2.0 -> {user_bin / 'xray-knife'}" in output
    assert f"WARNING {user_bin} is not on PATH" in output
    assert "on PATH is" not in output
    assert os.environ["PATH"] == f"/nonexistent{os.pathsep}{user_bin}"
    assert "OK TDLib libtdjson.so.1.8.38" in output


def test_setup_pin_replaces_only_mismatched_versions(
    fake_system: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_system["installed"] = {"xray-knife": "10.1.1", "hysteria": "2.12.2"}
    assert installer.run_setup(pin=True, yes=True, interactive=False) == 0
    assert fake_system["downloads"] == [("hysteria", "2.12.1")]
    output = capsys.readouterr().out
    assert "OK xray-knife 10.1.1" in output
    assert "hysteria 2.12.2 differs from pinned 2.12.1" in output

    fake_system["downloads"].clear()
    assert installer.run_setup(yes=True, interactive=False) == 0
    assert fake_system["downloads"] == []
    assert "OK hysteria 2.12.2" in capsys.readouterr().out

    elsewhere = str(Path("/usr/bin/hysteria"))
    monkeypatch.setattr(installer.shutil, "which", lambda _name: elsewhere)
    assert installer.run_setup(pin=True, yes=True, interactive=False) == 0
    assert f"hysteria on PATH is {elsewhere}" in capsys.readouterr().out


def test_setup_without_terminal_installs_nothing(
    fake_system: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    installer.run_setup(interactive=False)
    assert fake_system["downloads"] == []
    assert capsys.readouterr().out.count("No terminal; rerun with --yes.") == 2


def test_setup_reports_step_errors_and_continues(
    fake_system: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(_version: str, _architecture: str) -> bytes:
        raise SetupError("Checksum mismatch for xray-knife")

    monkeypatch.setattr(installer, "_download_xray_knife", broken)
    installer.run_setup(yes=True, interactive=False)
    output = capsys.readouterr().out
    assert "ERR xray-knife: Checksum mismatch for xray-knife" in output
    assert "INSTALLED hysteria 2.12.2" in output


def test_setup_tdlib_as_user_and_root(
    fake_system: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_system["installed"] = {"xray-knife": "11.2.0", "hysteria": "2.12.2"}
    fake_system["tdlib"] = False
    installer.run_setup(yes=True, interactive=False)
    assert "sudo apt install libtdjson1.8.38" in capsys.readouterr().out
    assert fake_system["commands"] == []

    monkeypatch.setattr(installer, "_is_root", lambda: True)
    installer.run_setup(yes=True, interactive=False)
    assert fake_system["commands"] == [
        ("apt-get", "update"),
        ("apt-get", "install", "--yes", "libtdjson1.8.38"),
    ]
    assert "INSTALLED TDLib libtdjson1.8.38" in capsys.readouterr().out

    fake_system["apt_status"] = 100
    installer.run_setup(yes=True, interactive=False)
    assert "ERR TDLib: apt-get update exited 100" in capsys.readouterr().out

    replies = answers("no")
    installer.run_setup(ask=lambda _question: next(replies), interactive=True)
    assert "INSTALLED TDLib" not in capsys.readouterr().out


def test_cli_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, bool]] = []

    def run_setup(*, yes: bool, pin: bool) -> int:
        calls.append({"yes": yes, "pin": pin})
        return 1

    monkeypatch.setattr(cli, "run_setup", run_setup)
    monkeypatch.setattr(sys, "argv", ["vpnprobe", "setup", "-y", "--pin"])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == 1
    assert calls == [{"yes": True, "pin": True}]
