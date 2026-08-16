from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from vpnprobe import diagnostics
from vpnprobe.diagnostics import DependencyResult, check_dependencies, print_dependency_check
from vpnprobe.errors import ConfigurationError


def test_executable_found_missing_and_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(diagnostics.shutil, "which", lambda _path: "/usr/bin/tool")
    monkeypatch.setattr(
        diagnostics.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout="banner\nVersion:\tv1.2.3\n"
        ),
    )
    result = diagnostics._executable("tool", "tool", ("version",), "install it")
    assert result.available
    assert "Version: v1.2.3" in result.detail

    monkeypatch.setattr(diagnostics.shutil, "which", lambda _path: None)
    result = diagnostics._executable("tool", "tool", ("version",), "install it")
    assert not result.available
    assert "not found" in result.detail

    monkeypatch.setattr(diagnostics.shutil, "which", lambda _path: "/usr/bin/tool")
    monkeypatch.setattr(
        diagnostics.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=2, stdout="broken"),
    )
    result = diagnostics._executable("tool", "tool", ("version",), "install it")
    assert not result.available
    assert "exited 2" in result.detail

    def timed_out(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired("tool", 10)

    monkeypatch.setattr(diagnostics.subprocess, "run", timed_out)
    result = diagnostics._executable("tool", "tool", ("version",), "install it")
    assert not result.available
    assert result.detail


def test_dependency_check_with_tdlib(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def executable(
        name: str, _path: str, _arguments: tuple[str, ...], install: str
    ) -> DependencyResult:
        seen.append(name)
        return DependencyResult(name, True, "version", install)

    monkeypatch.setattr(diagnostics, "_executable", executable)
    monkeypatch.setattr(
        diagnostics,
        "TdJson",
        lambda configured: SimpleNamespace(library_name=configured or "libtdjson.so"),
    )
    results = check_dependencies(tdjson_library="custom.so")
    assert seen == ["xray-knife", "sing-box", "hysteria"]
    assert results[-1] == DependencyResult("TDLib", True, "custom.so", diagnostics.TDLIB_INSTALL)

    def unavailable(_configured: str) -> object:
        raise ConfigurationError("missing TDLib")

    monkeypatch.setattr(diagnostics, "TdJson", unavailable)
    assert not check_dependencies()[-1].available


def test_hysteria_install_matches_architecture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(diagnostics.platform, "machine", lambda: "aarch64")
    assert "hysteria-linux-arm64" in diagnostics._hysteria_install()
    monkeypatch.setattr(diagnostics.platform, "machine", lambda: "unknown")
    assert "releases/latest" in diagnostics._hysteria_install()


def test_dependency_output(capsys: pytest.CaptureFixture[str]) -> None:
    results = (
        DependencyResult("one", True, "v1", "unused"),
        DependencyResult("two", False, "missing", "install two"),
    )
    assert print_dependency_check(results) == 1
    output = capsys.readouterr().out
    assert "OK one: v1" in output
    assert "ERR two: missing" in output
    assert "install two" in output
    assert "Dependencies: 1/2 available" in output
    assert print_dependency_check((results[0],)) == 0
