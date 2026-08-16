from __future__ import annotations

import sys
from importlib import import_module

import pytest

from vpnprobe import cli
from vpnprobe.errors import ConfigurationError
from vpnprobe.ping import PingOptions, ping

PROXY = "tg://proxy?server=proxy.example&port=443&secret=00112233445566778899aabbccddeeff"
VLESS = "vless://id@example.com:443?security=reality"
ping_module = import_module("vpnprobe.ping")


@pytest.mark.asyncio
async def test_ping_dispatches_direct(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, float | None, bool]] = []

    async def direct(
        url: str,
        _settings: object,
        timeout_seconds: float | None,
        *,
        speedtest: bool,
    ) -> int:
        calls.append((url, timeout_seconds, speedtest))
        return 7

    monkeypatch.setattr(ping_module, "run_vpn_ping", direct)
    assert await ping(VLESS, PingOptions(timeout=2.5, speedtest=True)) == 7
    assert calls == [(VLESS, 2.5, True)]
    with pytest.raises(ConfigurationError, match="--dc"):
        await ping(VLESS, PingOptions(dc="1"))


@pytest.mark.asyncio
async def test_ping_dispatches_mtproto(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, float, str]] = []

    async def proxy(url: str, _settings: object, timeout_seconds: float, dc: str) -> int:
        calls.append((url, timeout_seconds, dc))
        return 0

    monkeypatch.setattr(ping_module, "run_proxy_ping", proxy)
    assert await ping(PROXY, PingOptions(timeout=3, dc="2")) == 0
    assert calls == [(PROXY, 3, "2")]
    with pytest.raises(ConfigurationError, match="speedtest"):
        await ping(PROXY, PingOptions(speedtest=True))
    with pytest.raises(ConfigurationError, match="positive"):
        await ping(PROXY, PingOptions(timeout=0))


def test_cli_success(monkeypatch: pytest.MonkeyPatch) -> None:
    async def success(_url: str, _options: object) -> int:
        return 0

    monkeypatch.setattr(cli, "ping", success)
    monkeypatch.setattr(sys, "argv", ["vpnprobe", "ping", VLESS, "--timeout", "1"])
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 0


def test_cli_concise_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def failure(_url: str, _options: object) -> int:
        raise ConfigurationError("bad input")

    monkeypatch.setattr(cli, "ping", failure)
    monkeypatch.setattr(sys, "argv", ["vpnprobe", "ping", VLESS])
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 2
    assert capsys.readouterr().err == "ERROR_COMMAND bad input\n"
