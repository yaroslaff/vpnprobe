from __future__ import annotations

import base64
import socket
from dataclasses import replace
from typing import ClassVar

import pytest

from vpnprobe.config import Settings
from vpnprobe.errors import SubscriptionError
from vpnprobe.events import EventSink, NullEventSink
from vpnprobe.models import Outcome
from vpnprobe.subscription import (
    PinnedResolver,
    _download_once,
    _public_addresses,
    fetch_subscription,
    parse_subscription,
    verify_subscription,
)
from vpnprobe.verification import GeoData, SpeedResult, VerificationResult

LEGACY_SS = "ss://" + (
    base64.urlsafe_b64encode(b"aes-256-gcm:password@legacy.example:9443").decode().rstrip("=")
)


def test_parse_plain_and_base64_subscription() -> None:
    lines = [
        "vless://id@example.com:443?security=tls",
        LEGACY_SS,
        "hysteria2://password@example.net:9443?sni=example.net",
    ]
    plain = "\n".join(lines).encode()
    assert parse_subscription(plain) == lines
    assert parse_subscription(base64.b64encode(plain)) == lines
    assert parse_subscription(base64.urlsafe_b64encode(plain).rstrip(b"=")) == lines
    with pytest.raises(SubscriptionError, match="empty"):
        parse_subscription(b"")
    with pytest.raises(SubscriptionError, match="recursive"):
        parse_subscription(b"https://recursive.example/sub")
    with pytest.raises(SubscriptionError, match="no supported entries"):
        parse_subscription(b"vless://id@example.com:not-a-port")
    with pytest.raises(SubscriptionError, match="UTF-8"):
        parse_subscription(b"\xff\xfe")


def test_parse_subscription_keeps_usable_entries() -> None:
    body = (
        "#support-url: https://t.me/example\n"
        "# \u041e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u043e: 2026-09-21 00:58:21\n"
        "\n"
        "vless://id@example.com:443?security=tls\n"
        "vless://id@example.com:not-a-port\n"
        "vless://501a9f81-d8e3-410b-afdc-e9bb55fae944#advertisement\n"
        "hysteria2://password@example.net:20000-50000?sni=example.net\n"
        "tuic://id@example.com:443\n"
        f"{LEGACY_SS}\n"
    ).encode()
    assert parse_subscription(body) == [
        "vless://id@example.com:443?security=tls",
        LEGACY_SS,
    ]


def test_parse_subscription_rejects_non_ascii_without_entries() -> None:
    """A non-ASCII body must fail as a subscription error, never as a raw ValueError."""
    for body in (
        "<html><body>\u041e\u0448\u0438\u0431\u043a\u0430</body></html>",
        "no keys here \u2014 subscription expired",
    ):
        with pytest.raises(SubscriptionError):
            parse_subscription(body.encode())


def test_parse_subscription_rejects_recursion_inside_a_list() -> None:
    body = b"vless://id@example.com:443\nhttps://recursive.example/sub\n"
    with pytest.raises(SubscriptionError, match="recursive"):
        parse_subscription(body)


@pytest.mark.asyncio
async def test_public_address_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    loop = __import__("asyncio").get_running_loop()

    async def public_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(loop, "getaddrinfo", public_getaddrinfo)
    assert await _public_addresses("example.com", 443) == ("93.184.216.34",)
    with pytest.raises(SubscriptionError, match="non-public"):
        await _public_addresses("127.0.0.1", 80)

    resolver = PinnedResolver("example.com", ("93.184.216.34",))
    result = await resolver.resolve("example.com", 443, socket.AF_UNSPEC)
    assert result[0]["host"] == "93.184.216.34"
    assert await resolver.close() is None
    with pytest.raises(OSError, match="unexpected"):
        await resolver.resolve("other.example", 443)

    async def dns_error(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        raise OSError("dns down")

    monkeypatch.setattr(loop, "getaddrinfo", dns_error)
    with pytest.raises(SubscriptionError, match="DNS lookup"):
        await _public_addresses("example.com", 443)


@pytest.mark.asyncio
async def test_download_once_is_bounded_and_pinned(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Content:
        async def iter_chunked(self, _size: int):  # type: ignore[no-untyped-def]
            yield b"vless://id@example.com:443"

    class Response:
        status = 200
        content_length = None
        headers: ClassVar[dict[str, str]] = {}
        content = Content()

        async def __aenter__(self):  # type: ignore[no-untyped-def]
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

    class Session:
        request_headers: ClassVar[list[dict[str, str]]] = []

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return None

        async def __aenter__(self):  # type: ignore[no-untyped-def]
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        def get(self, _url: str, **kwargs: object) -> Response:
            headers = kwargs.get("headers")
            assert isinstance(headers, dict)
            self.request_headers.append(headers)
            return Response()

    async def addresses(_host: str, _port: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr("vpnprobe.subscription._public_addresses", addresses)
    monkeypatch.setattr("vpnprobe.subscription.aiohttp.TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr("vpnprobe.subscription.aiohttp.ClientSession", Session)
    status, payload, location = await _download_once("https://example.com/sub", settings)
    assert status == 200
    assert payload.startswith(b"vless://")
    assert location is None
    assert Session.request_headers == [{"X-Hwid": settings.subscription_hwid}]

    with pytest.raises(SubscriptionError, match="credentials"):
        await _download_once("https://user:pass@example.com/sub", settings)


@pytest.mark.asyncio
async def test_fetch_redirects_and_limits(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    async def download(url: str, _settings: Settings) -> tuple[int, bytes, str | None]:
        calls.append(url)
        if len(calls) == 1:
            return 302, b"", "/next"
        return 200, b"vless://id@example.com:443", None

    monkeypatch.setattr("vpnprobe.subscription._download_once", download)
    assert await fetch_subscription("https://example.com/sub", settings) == [
        "vless://id@example.com:443"
    ]
    assert calls == ["https://example.com/sub", "https://example.com/next"]

    async def error_status(_url: str, _settings: Settings) -> tuple[int, bytes, str | None]:
        return 500, b"", None

    monkeypatch.setattr("vpnprobe.subscription._download_once", error_status)
    with pytest.raises(SubscriptionError, match="HTTP 500"):
        await fetch_subscription("https://example.com/sub", settings)

    async def redirect_forever(_url: str, _settings: Settings) -> tuple[int, bytes, str | None]:
        return 301, b"", "/again"

    monkeypatch.setattr("vpnprobe.subscription._download_once", redirect_forever)
    with pytest.raises(SubscriptionError, match="redirect limit"):
        await fetch_subscription(
            "https://example.com/sub", replace(settings, subscription_max_redirects=1)
        )


@pytest.mark.asyncio
async def test_verify_subscription_selects_fastest_and_bounds_attempts(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    configs = [
        "vless://one@example.com:443",
        "vless://two@example.com:443",
        "vless://three@example.com:443",
    ]

    async def fetch(_url: str, _settings: Settings) -> list[str]:
        return configs.copy()

    speeds = iter((10.0, None, 20.0))
    latencies = iter((50.0, 40.0, 30.0))

    async def verify(
        url: str, _settings: Settings, _logger: EventSink, *, identity: object
    ) -> VerificationResult:
        return VerificationResult(
            Outcome.SUCCESS,
            "ok",
            __import__("vpnprobe.identity", fromlist=["identify"]).identify(url),
            geo=GeoData("1.2.3.4", "Country", "City"),
            latency_ms=next(latencies),
        )

    async def measure(
        _url: str, _settings: Settings, _logger: EventSink, *, identity: object
    ) -> SpeedResult:
        speed = next(speeds)
        return SpeedResult(speed, "ok" if speed is not None else "failed")

    finished: list[float | None] = []

    async def on_finished(_attempt_id: int | None, result: VerificationResult) -> None:
        finished.append(result.speed_mbps)

    monkeypatch.setattr("vpnprobe.subscription.fetch_subscription", fetch)
    monkeypatch.setattr("vpnprobe.subscription.verify_key", verify)
    monkeypatch.setattr("vpnprobe.subscription.measure_speed", measure)
    monkeypatch.setattr("vpnprobe.subscription.random.SystemRandom.shuffle", lambda _s, _x: None)
    logger = NullEventSink()
    result = await verify_subscription(
        "https://example.com/sub",
        settings,
        logger,
        on_attempt_finished=on_finished,
        speed_test=True,
    )
    assert result.outcome is Outcome.SUCCESS
    assert result.attempts == 3
    assert result.successes == 3
    assert finished == [10.0, None, 20.0]
    assert result.speed_mbps == 20.0
    assert result.latency_ms == 30.0

    latencies = iter((50.0, 40.0, 30.0))
    result = await verify_subscription("https://example.com/sub", settings, logger)
    assert result.outcome is Outcome.SUCCESS
    assert result.speed_mbps is None


@pytest.mark.asyncio
async def test_verify_subscription_inconclusive_and_error(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fetch(_url: str, _settings: Settings) -> list[str]:
        return ["vless://one@example.com:443"]

    async def verify(
        url: str, _settings: Settings, _logger: EventSink, *, identity: object
    ) -> VerificationResult:
        return VerificationResult(
            Outcome.INCONCLUSIVE,
            "service down",
            __import__("vpnprobe.identity", fromlist=["identify"]).identify(url),
        )

    monkeypatch.setattr("vpnprobe.subscription.fetch_subscription", fetch)
    monkeypatch.setattr("vpnprobe.subscription.verify_key", verify)
    result = await verify_subscription("https://example.com/sub", settings, NullEventSink())
    assert result.outcome is Outcome.INCONCLUSIVE

    async def broken(_url: str, _settings: Settings) -> list[str]:
        raise SubscriptionError("broken")

    monkeypatch.setattr("vpnprobe.subscription.fetch_subscription", broken)
    result = await verify_subscription("https://example.com/sub", settings, NullEventSink())
    assert result.outcome is Outcome.FAILED
    assert result.detail == "broken"
