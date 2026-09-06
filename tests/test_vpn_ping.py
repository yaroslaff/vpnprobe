from __future__ import annotations

import asyncio
from typing import ClassVar

import aiohttp
import pytest

from vpnprobe.vpn_ping_cli import run_vpn_ping
from vpnprobe.xray import TunnelError

VLESS_URL = "vless://id@example.com:443?security=reality"
HYSTERIA2_URL = "hysteria2://password@example.com:9443?security=tls&sni=example.com"


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
    responses: ClassVar[list[Response | Exception]] = []

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.items: list[Response | Exception] = self.responses.copy()

    async def __aenter__(self):  # type: ignore[no-untyped-def]
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def get(self, _url: str) -> Response:
        # The connectivity check retries, so the last scripted answer repeats.
        item = self.items.pop(0) if len(self.items) > 1 else self.items[0]
        if isinstance(item, Exception):
            raise item
        return item


class FakeProcess:
    def __init__(self, returncode: int | None = None) -> None:
        self.returncode = returncode


class FakeTunnel:
    proxy_url = "socks5://127.0.0.1:23456"

    def __init__(self, returncode: int | None = None) -> None:
        self.stopped = False
        self.process = FakeProcess(returncode)

    async def error_output(self) -> str:
        return "xray-knife: invalid configuration"

    async def stop(self) -> None:
        self.stopped = True


@pytest.fixture(autouse=True)
def _offline_details(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the decoded-configuration helper from running the real xray-knife."""

    async def unavailable(*_arguments: str, **_options: object) -> object:
        raise OSError("xray-knife is not available in tests")

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.asyncio.create_subprocess_exec", unavailable)


@pytest.fixture
def tunnel(monkeypatch: pytest.MonkeyPatch) -> FakeTunnel:
    started = FakeTunnel()

    async def start(_url: str, _configured: object) -> FakeTunnel:
        return started

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.start_tunnel", start)
    monkeypatch.setattr("vpnprobe.vpn_ping_cli.ProxyConnector.from_url", lambda *_a, **_k: object())
    monkeypatch.setattr("vpnprobe.vpn_ping_cli.aiohttp.ClientSession", Session)
    return started


@pytest.mark.parametrize("url", [VLESS_URL, HYSTERIA2_URL])
@pytest.mark.asyncio
async def test_vpn_ping_succeeds_on_204(
    url: str,
    settings,  # type: ignore[no-untyped-def]
    tunnel: FakeTunnel,
    capsys: pytest.CaptureFixture[str],
) -> None:
    Session.responses = [Response(204)]
    assert await run_vpn_ping(url, settings, 1, speedtest=False) == 0
    label = url.split("://", 1)[0]
    assert capsys.readouterr().out == f"OK {label} connectivity HTTP 204\n"
    assert tunnel.stopped


@pytest.mark.asyncio
async def test_vpn_ping_measures_download(
    settings,  # type: ignore[no-untyped-def]
    tunnel: FakeTunnel,
    capsys: pytest.CaptureFixture[str],
) -> None:
    Session.responses = [Response(204), Response(200, (b"x" * 1000,))]
    assert await run_vpn_ping(VLESS_URL, settings, 1, speedtest=True) == 0
    assert "Download:" in capsys.readouterr().out
    assert tunnel.stopped


@pytest.mark.asyncio
async def test_vpn_ping_fails_when_endpoint_is_not_204(
    settings,  # type: ignore[no-untyped-def]
    tunnel: FakeTunnel,
    capsys: pytest.CaptureFixture[str],
) -> None:
    Session.responses = [Response(403)]
    assert await run_vpn_ping(VLESS_URL, settings, 0.05, speedtest=False) == 1
    assert "HTTP 403, expected 204" in capsys.readouterr().err
    assert tunnel.stopped


@pytest.mark.asyncio
async def test_vpn_ping_retries_until_connectivity_answers(
    settings,  # type: ignore[no-untyped-def]
    tunnel: FakeTunnel,
    capsys: pytest.CaptureFixture[str],
) -> None:
    Session.responses = [aiohttp.ClientConnectionError("tunnel warming up"), Response(204)]
    assert await run_vpn_ping(VLESS_URL, settings, 1, speedtest=False) == 0
    assert capsys.readouterr().out == "OK vless connectivity HTTP 204\n"


@pytest.mark.asyncio
async def test_vpn_ping_reports_last_connectivity_error(
    settings,  # type: ignore[no-untyped-def]
    tunnel: FakeTunnel,
    capsys: pytest.CaptureFixture[str],
) -> None:
    Session.responses = [aiohttp.ClientConnectionError("connection refused")]
    assert await run_vpn_ping(VLESS_URL, settings, 0.05, speedtest=False) == 1
    assert "connection refused" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_vpn_ping_fails_on_empty_speed_response(
    settings,  # type: ignore[no-untyped-def]
    tunnel: FakeTunnel,
    capsys: pytest.CaptureFixture[str],
) -> None:
    Session.responses = [Response(204), Response(200)]
    assert await run_vpn_ping(VLESS_URL, settings, 1, speedtest=True) == 1
    assert "empty response" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_vpn_ping_fails_on_speed_endpoint_status(
    settings,  # type: ignore[no-untyped-def]
    tunnel: FakeTunnel,
    capsys: pytest.CaptureFixture[str],
) -> None:
    Session.responses = [Response(204), Response(503)]
    assert await run_vpn_ping(VLESS_URL, settings, 1, speedtest=True) == 1
    assert "Speed endpoint returned HTTP 503" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_vpn_ping_reports_tunnel_failure(
    settings,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def failed(_url: str, _configured: object) -> FakeTunnel:
        raise TunnelError("bad config")

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.start_tunnel", failed)
    assert await run_vpn_ping(HYSTERIA2_URL, settings, 1, speedtest=False) == 1
    assert capsys.readouterr().err == "ERR hysteria2 bad config\n"


@pytest.mark.asyncio
async def test_vpn_ping_reports_slow_tunnel_startup(
    settings,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def hanging(_url: str, _configured: object) -> FakeTunnel:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.start_tunnel", hanging)
    assert await run_vpn_ping(VLESS_URL, settings, 0.05, speedtest=False) == 1
    assert "Tunnel was not ready after 0.05s" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_vpn_ping_stops_tunnel_when_cancelled(
    settings,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
    tunnel: FakeTunnel,
) -> None:
    waiting = asyncio.Event()

    class HangingSession(Session):
        def get(self, _url: str) -> Response:
            waiting.set()
            raise aiohttp.ClientConnectionError("still waiting")

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.aiohttp.ClientSession", HangingSession)
    HangingSession.responses = []
    task = asyncio.create_task(run_vpn_ping(VLESS_URL, settings, 5, speedtest=False))
    await waiting.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert tunnel.stopped


@pytest.mark.asyncio
async def test_vpn_ping_reports_tunnel_that_exited_early(
    settings,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dead = FakeTunnel(returncode=1)

    async def start(_url: str, _configured: object) -> FakeTunnel:
        return dead

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.start_tunnel", start)
    monkeypatch.setattr("vpnprobe.vpn_ping_cli.ProxyConnector.from_url", lambda *_a, **_k: object())
    monkeypatch.setattr("vpnprobe.vpn_ping_cli.aiohttp.ClientSession", Session)
    Session.responses = [Response(204)]
    assert await run_vpn_ping(VLESS_URL, settings, 1, speedtest=False) == 1
    assert "Tunnel exited early: xray-knife: invalid configuration" in capsys.readouterr().err
    assert dead.stopped


class ParseProcess:
    def __init__(self, returncode: int, stdout: bytes) -> None:
        self.returncode = returncode
        self.stdout = stdout

    async def communicate(self) -> tuple[bytes, bytes]:
        return self.stdout, b""


@pytest.fixture
def parse_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []

    async def stop(_process: object, _timeout: float) -> None:
        return None

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.stop_process_group", stop)
    return calls


@pytest.mark.asyncio
async def test_ping_prints_decoded_configuration(
    settings,  # type: ignore[no-untyped-def]
    tunnel: FakeTunnel,
    monkeypatch: pytest.MonkeyPatch,
    parse_calls: list[tuple[str, ...]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def create(*arguments: str, **_options: object) -> ParseProcess:
        parse_calls.append(arguments)
        return ParseProcess(0, b"Protocol: vless\nAddress: example.com\n")

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.asyncio.create_subprocess_exec", create)
    Session.responses = [Response(204)]
    assert await run_vpn_ping(VLESS_URL, settings, 1, speedtest=False) == 0
    assert parse_calls == [(settings.xray_knife_path, "parse", "--config", VLESS_URL)]
    assert capsys.readouterr().out == (
        "Protocol: vless\nAddress: example.com\n\nOK vless connectivity HTTP 204\n"
    )


@pytest.mark.parametrize("failure", [ParseProcess(1, b"unusable"), OSError("no xray-knife")])
@pytest.mark.asyncio
async def test_ping_stays_silent_when_details_are_unavailable(
    failure: ParseProcess | OSError,
    settings,  # type: ignore[no-untyped-def]
    tunnel: FakeTunnel,
    monkeypatch: pytest.MonkeyPatch,
    parse_calls: list[tuple[str, ...]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def create(*_arguments: str, **_options: object) -> ParseProcess:
        if isinstance(failure, OSError):
            raise failure
        return failure

    monkeypatch.setattr("vpnprobe.vpn_ping_cli.asyncio.create_subprocess_exec", create)
    Session.responses = [Response(204)]
    assert await run_vpn_ping(VLESS_URL, settings, 1, speedtest=False) == 0
    assert capsys.readouterr().out == "OK vless connectivity HTTP 204\n"
