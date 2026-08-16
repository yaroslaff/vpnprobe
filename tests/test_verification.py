from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any, ClassVar

import pytest
from aiohttp_socks import ProxyTimeoutError

from vpnprobe.config import Settings
from vpnprobe.events import NullEventSink
from vpnprobe.models import Outcome
from vpnprobe.verification import (
    GeoData,
    NetworkProbe,
    ServiceUnavailable,
    VerificationFailure,
    _service_status,
    verify_key,
)


class FakeProcess:
    returncode: int | None = None


class FakeTunnel:
    def __init__(self) -> None:
        self.process = FakeProcess()
        self.port = 34567
        self.stopped = False

    @property
    def proxy_url(self) -> str:
        return "socks5://127.0.0.1:34567"

    async def error_output(self) -> str:
        return "bad config"

    async def entry_ip(self, _url: str) -> str:
        return "9.8.7.6"

    async def stop(self) -> None:
        self.stopped = True


class FakeContent:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    async def iter_chunked(self, _size: int) -> Any:
        for chunk in self.chunks:
            yield chunk


class FakeResponse:
    def __init__(self, status: int, *, text: str = "", chunks: list[bytes] | None = None) -> None:
        self.status = status
        self._text = text
        self.content = FakeContent(chunks or [])

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def text(self) -> str:
        return self._text


class FakeSession:
    def __init__(self, responses: list[FakeResponse | Exception]) -> None:
        self.responses = responses

    def get(self, _url: str) -> FakeResponse:
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class RunSession(FakeSession):
    items: ClassVar[list[FakeResponse | Exception]] = []

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        super().__init__(self.items.copy())

    async def __aenter__(self) -> RunSession:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None


def test_service_status_classification() -> None:
    _service_status(200, "test")
    with pytest.raises(ServiceUnavailable, match="429"):
        _service_status(429, "test")
    with pytest.raises(ServiceUnavailable, match="503"):
        _service_status(503, "test")
    with pytest.raises(VerificationFailure, match="404"):
        _service_status(404, "test")


@pytest.mark.asyncio
async def test_network_probe_steps(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    live_probe = NetworkProbe("socks5://127.0.0.1:34567", settings)
    assert live_probe.connector.force_close
    await live_probe.connector.close()

    probe = object.__new__(NetworkProbe)
    probe.settings = settings
    connectivity = FakeSession([FakeResponse(500), FakeResponse(204)])
    await probe._wait_for_connectivity(connectivity)  # type: ignore[arg-type]

    geo_session = FakeSession(
        [
            FakeResponse(
                200,
                text=(
                    '{"success": true, "ip": "1.2.3.4", "country": "X", "city": "Y", '
                    '"country_code": "se", "connection": {"asn": "24940"}}'
                ),
            )
        ]
    )
    assert await probe._fetch_geo(geo_session) == GeoData(  # type: ignore[arg-type]
        "1.2.3.4", "X", "Y", "SE", 24940
    )
    optional_invalid = FakeSession(
        [
            FakeResponse(
                200,
                text=(
                    '{"success": true, "ip": "1.2.3.4", "country": "X", "city": "Y", '
                    '"country_code": "Sweden", "connection": {"asn": "unknown"}}'
                ),
            )
        ]
    )
    assert await probe._fetch_geo(optional_invalid) == GeoData(  # type: ignore[arg-type]
        "1.2.3.4", "X", "Y"
    )

    speed_session = FakeSession([FakeResponse(200, chunks=[b"a" * 1000, b"b" * 1000])])
    assert await probe._measure_speed(speed_session) > 0  # type: ignore[arg-type]

    latency_session = FakeSession([FakeResponse(204) for _ in range(4)])
    monotonic_values = iter((0.0, 0.1, 1.0, 1.03, 2.0, 2.01, 3.0, 3.02))
    monkeypatch.setattr(probe, "_now", lambda: next(monotonic_values))
    assert await probe._measure_latency(latency_session) == 20.0  # type: ignore[arg-type]

    malformed = FakeSession([FakeResponse(200, text="not-json")])
    with pytest.raises(VerificationFailure, match="malformed"):
        await probe._fetch_geo(malformed)  # type: ignore[arg-type]
    missing = FakeSession([FakeResponse(200, text='{"success": false}')])
    with pytest.raises(VerificationFailure, match="unsuccessful"):
        await probe._fetch_geo(missing)  # type: ignore[arg-type]
    empty_speed = FakeSession([FakeResponse(200, chunks=[])])
    with pytest.raises(VerificationFailure, match="empty"):
        await probe._measure_speed(empty_speed)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_network_probe_run(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    RunSession.items = [
        FakeResponse(204),
        FakeResponse(
            200,
            text='{"success": true, "ip": "1.2.3.4", "country": "X", "city": "Y"}',
        ),
        FakeResponse(204),
        FakeResponse(204),
        FakeResponse(204),
        FakeResponse(204),
        FakeResponse(200, chunks=[b"data"]),
    ]
    monkeypatch.setattr("vpnprobe.verification.aiohttp.ClientSession", RunSession)
    probe = object.__new__(NetworkProbe)
    probe.settings = settings
    probe.connector = object()  # type: ignore[assignment]
    geo, latency, speed = await probe.run()
    assert geo.ip == "1.2.3.4"
    assert latency >= 0
    assert speed > 0


@pytest.mark.asyncio
async def test_connectivity_timeout(settings: Settings) -> None:
    probe = object.__new__(NetworkProbe)
    probe.settings = replace(
        settings, connectivity_check_timeout=0.001, connectivity_retry_interval=0.001
    )
    responses = [FakeResponse(500) for _ in range(10)]
    with pytest.raises(VerificationFailure, match="Connectivity"):
        await probe._wait_for_connectivity(FakeSession(responses))  # type: ignore[arg-type]

    class SlowResponse(FakeResponse):
        async def __aenter__(self) -> FakeResponse:
            await asyncio.sleep(0.05)
            return self

    probe.settings = replace(settings, connectivity_check_timeout=0.001)
    with pytest.raises(VerificationFailure, match="timed out after"):
        await probe._wait_for_connectivity(  # type: ignore[arg-type]
            FakeSession([SlowResponse(204)])
        )


@pytest.mark.asyncio
async def test_verify_key_success(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    tunnel = FakeTunnel()

    async def start(_url: str, _settings: Settings) -> Any:
        return tunnel

    async def run(_self: NetworkProbe) -> tuple[GeoData, float, float]:
        return GeoData("1.2.3.4", "Country", "City"), 45.6, 12.3

    monkeypatch.setattr("vpnprobe.verification.start_tunnel", start)
    monkeypatch.setattr(NetworkProbe, "run", run)
    result = await verify_key("vless://id@example.com:443", settings, NullEventSink())
    assert result.outcome is Outcome.SUCCESS
    assert result.speed_mbps == 12.3
    assert result.latency_ms == 45.6
    assert result.geo == GeoData("1.2.3.4", "Country", "City")
    assert result.entry_ip == "9.8.7.6"
    assert tunnel.stopped


@pytest.mark.asyncio
async def test_verify_key_observes_entry_while_probe_runs(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    class DelayedEntryTunnel(FakeTunnel):
        def __init__(self) -> None:
            super().__init__()
            self.observations = 0

        async def entry_ip(self, _url: str) -> str | None:
            self.observations += 1
            return "9.8.7.6" if self.observations >= 2 else None

    tunnel = DelayedEntryTunnel()

    async def start(_url: str, _settings: Settings) -> DelayedEntryTunnel:
        return tunnel

    async def run(_self: NetworkProbe) -> tuple[GeoData, float, float]:
        await asyncio.sleep(0.01)
        return GeoData("1.2.3.4", "Country", "City"), 45.6, 12.3

    monkeypatch.setattr("vpnprobe.verification.start_tunnel", start)
    monkeypatch.setattr(NetworkProbe, "run", run)
    result = await verify_key("vless://id@example.com:443", settings, NullEventSink())
    assert result.entry_ip == "9.8.7.6"
    assert tunnel.observations >= 2


@pytest.mark.asyncio
async def test_verify_key_inconclusive_failed_and_timeout(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    tunnels: list[FakeTunnel] = []

    async def start(_url: str, _settings: Settings) -> Any:
        tunnel = FakeTunnel()
        tunnels.append(tunnel)
        return tunnel

    async def unavailable(_self: NetworkProbe) -> tuple[GeoData, float, float]:
        raise ServiceUnavailable("HTTP 503")

    monkeypatch.setattr("vpnprobe.verification.start_tunnel", start)
    monkeypatch.setattr(NetworkProbe, "run", unavailable)
    result = await verify_key("vless://id@example.com:443", settings, NullEventSink())
    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.entry_ip == "9.8.7.6"

    async def failed(_self: NetworkProbe) -> tuple[GeoData, float, float]:
        raise VerificationFailure("no connectivity")

    monkeypatch.setattr(NetworkProbe, "run", failed)
    result = await verify_key("vless://id@example.com:443", settings, NullEventSink())
    assert result.outcome is Outcome.FAILED

    async def proxy_timeout(_self: NetworkProbe) -> tuple[GeoData, float, float]:
        raise ProxyTimeoutError("Proxy connection timed out: 60")

    monkeypatch.setattr(NetworkProbe, "run", proxy_timeout)
    result = await verify_key("vless://id@example.com:443", settings, NullEventSink())
    assert result.outcome is Outcome.FAILED
    assert "Proxy connection timed out" in result.detail

    async def slow_start(_url: str, _settings: Settings) -> Any:
        await asyncio.sleep(0.05)
        return FakeTunnel()

    monkeypatch.setattr("vpnprobe.verification.start_tunnel", slow_start)
    result = await verify_key(
        "vless://id@example.com:443",
        replace(settings, key_check_timeout=0.001),
        NullEventSink(),
    )
    assert result.outcome is Outcome.FAILED
    assert "exceeded" in result.detail
    assert all(tunnel.stopped for tunnel in tunnels)
