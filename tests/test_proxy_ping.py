from __future__ import annotations

import asyncio
import sys
from dataclasses import replace
from typing import Any

import pytest

from vpnprobe.errors import ConfigurationError
from vpnprobe.proxy_ping_cli import run_proxy_ping
from vpnprobe.proxy_ping_worker import main, ping_once
from vpnprobe.tdlib import ProxyDcTest, ProxyTestResult

PROXY_URL = "tg://proxy?server=proxy.example&port=443&secret=00112233445566778899aabbccddeeff"


class Process:
    def __init__(
        self,
        returncode: int,
        stdout: bytes = b"",
        stderr: bytes = b"",
        *,
        hangs: bool = False,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.hangs = hangs
        self.calls = 0
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        self.calls += 1
        if self.hangs and self.calls == 1:
            await asyncio.Event().wait()
        return self.stdout, self.stderr

    def kill(self) -> None:
        self.killed = True


@pytest.mark.asyncio
async def test_isolated_ping_process_results(
    settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    processes = [
        Process(0, stdout=b"OK 42.0 ms\n"),
        Process(1, stderr=b"ERR 10.0 ms refused\n"),
        Process(-6),
    ]

    async def create(*_args: object, **_kwargs: object) -> Process:
        return processes.pop(0)

    monkeypatch.setattr("vpnprobe.proxy_ping_cli.asyncio.create_subprocess_exec", create)
    assert await run_proxy_ping(PROXY_URL, settings, 1, "ALL") == 0
    assert capsys.readouterr().out == "OK 42.0 ms\n"
    assert await run_proxy_ping(PROXY_URL, settings, 1, "2") == 1
    assert capsys.readouterr().err == "ERR 10.0 ms refused\n"
    assert await run_proxy_ping(PROXY_URL, settings, 1, "1") == 1
    assert "exited with code -6" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_isolated_ping_process_timeout(
    settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    process = Process(0, hangs=True)

    async def create(*_args: object, **_kwargs: object) -> Process:
        return process

    monkeypatch.setattr("vpnprobe.proxy_ping_cli.asyncio.create_subprocess_exec", create)
    quick = replace(settings, process_stop_timeout=0.001)
    assert await run_proxy_ping(PROXY_URL, quick, 0.001, "ALL") == 1
    assert process.killed
    assert "helper did not stop" in capsys.readouterr().err


def test_ping_worker_result_and_main(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Client:
        def __init__(self, _library: str) -> None:
            pass

        def ping(self, *_args: object) -> ProxyTestResult:
            return ProxyTestResult(
                (
                    ProxyDcTest(1, 0.042),
                    ProxyDcTest(2, None, "timeout"),
                )
            )

    monkeypatch.setattr("vpnprobe.proxy_ping_worker.TdJson", Client)
    assert ping_once(PROXY_URL, "", 1, "ALL") == (
        0,
        "OK 42.0 ms dc_ok=1 dc_failed=2",
    )

    def invalid(_value: str) -> Any:
        raise ConfigurationError("invalid proxy")

    monkeypatch.setattr("vpnprobe.proxy_ping_worker.telegram_proxy", invalid)
    code, message = ping_once(PROXY_URL, "", 1, "1")
    assert code == 1
    assert message.endswith(" ms invalid proxy")

    monkeypatch.setattr("vpnprobe.proxy_ping_worker.telegram_proxy", lambda _value: object())
    monkeypatch.setattr("vpnprobe.proxy_ping_worker.ping_once", lambda *_args: (0, "OK 1.0 ms"))
    monkeypatch.setattr("vpnprobe.proxy_ping_worker.resource.setrlimit", lambda *_args: None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["worker", "--timeout", "1", "--dc", "ALL", PROXY_URL],
    )

    def exit_process(code: int) -> None:
        raise SystemExit(code)

    monkeypatch.setattr("vpnprobe.proxy_ping_worker.os._exit", exit_process)
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 0
    assert capsys.readouterr().out == "OK 1.0 ms\n"
