from __future__ import annotations

from typing import ClassVar

import pytest

from vpnprobe.vpn_ping_cli import _run_hysteria_ping, run_vpn_ping
from vpnprobe.xray import TunnelError

VLESS_URL = "vless://id@example.com:443?security=reality"
HYSTERIA2_URL = "hysteria2://password@example.com:9443?security=tls&sni=example.com"


class Process:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode

    async def wait(self) -> int:
        return self.returncode


@pytest.mark.asyncio
async def test_vpn_ping_inherits_xray_output(settings, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[str, ...]] = []

    async def create(*arguments: str) -> Process:
        calls.append(arguments)
        return Process(7)

    monkeypatch.setattr(
        "vpnprobe.vpn_ping_cli.asyncio.create_subprocess_exec",
        create,
    )
    assert await run_vpn_ping(VLESS_URL, settings, None, speedtest=False) == 7
    assert calls == [
        (
            settings.xray_knife_path,
            "http",
            "--config",
            VLESS_URL,
            "--out",
            "/dev/null",
        )
    ]

    assert await run_vpn_ping(VLESS_URL, settings, 2.5, speedtest=True) == 7
    assert "--speedtest" in calls[-1]
    assert calls[-1][-4:] == ("--timeout", "2500", "--mdelay", "2500")


class Response:
    def __init__(self, status: int, chunks: tuple[bytes, ...] = ()) -> None:
        self.status = status
        self.content = self
        self.chunks = chunks

    async def __aenter__(self):  # type: ignore[no-untyped-def]
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def read(self) -> bytes:
        return b""

    async def iter_chunked(self, _size: int):  # type: ignore[no-untyped-def]
        for chunk in self.chunks:
            yield chunk


class Session:
    responses: ClassVar[list[Response]] = []

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.items = self.responses.copy()

    async def __aenter__(self):  # type: ignore[no-untyped-def]
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def get(self, _url: str) -> Response:
        return self.items.pop(0)


class HysteriaTunnel:
    proxy_url = "socks5://127.0.0.1:23456"

    def __init__(self) -> None:
        self.stopped = False

    async def stop(self) -> None:
        self.stopped = True


@pytest.mark.asyncio
async def test_hysteria_ping_uses_native_tunnel(
    settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:  # type: ignore[no-untyped-def]
    tunnel = HysteriaTunnel()

    async def start(_url: str, configured: object) -> HysteriaTunnel:
        assert configured.hysteria_path == settings.hysteria_path
        return tunnel

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.start_tunnel", start)
    monkeypatch.setattr("vpnprobe.vpn_ping_cli.ProxyConnector.from_url", lambda *_a, **_k: object())
    monkeypatch.setattr("vpnprobe.vpn_ping_cli.aiohttp.ClientSession", Session)
    Session.responses = [Response(204)]
    assert await run_vpn_ping(HYSTERIA2_URL, settings, 1, speedtest=False) == 0
    assert capsys.readouterr().out == "OK Hysteria2 connectivity HTTP 204\n"
    assert tunnel.stopped

    Session.responses = [Response(204), Response(200, (b"x" * 1000,))]
    assert await _run_hysteria_ping(HYSTERIA2_URL, settings, 1, speedtest=True) == 0
    assert "Download:" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_hysteria_ping_reports_failures(
    settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:  # type: ignore[no-untyped-def]
    async def failed(_url: str, _configured: object) -> HysteriaTunnel:
        raise TunnelError("bad config")

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.start_tunnel", failed)
    assert await _run_hysteria_ping(HYSTERIA2_URL, settings, 1, speedtest=False) == 1
    assert capsys.readouterr().err == "ERR Hysteria2 bad config\n"

    tunnel = HysteriaTunnel()

    async def started(_url: str, _configured: object) -> HysteriaTunnel:
        return tunnel

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.start_tunnel", started)
    monkeypatch.setattr(
        "vpnprobe.vpn_ping_cli.ProxyConnector.from_url", lambda *_args, **_kwargs: object()
    )
    monkeypatch.setattr("vpnprobe.vpn_ping_cli.aiohttp.ClientSession", Session)
    Session.responses = [Response(200)]
    assert await _run_hysteria_ping(HYSTERIA2_URL, settings, 1, speedtest=False) == 1
    assert "expected 204" in capsys.readouterr().err
    assert tunnel.stopped
