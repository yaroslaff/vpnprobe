"""SSRF-resistant subscription retrieval and bounded verification."""

from __future__ import annotations

import asyncio
import base64
import binascii
import ipaddress
import random
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult

from vpnprobe.config import ProbeConfig
from vpnprobe.errors import ConfigurationError, SubscriptionError
from vpnprobe.events import EventSink
from vpnprobe.identity import Identity, identify
from vpnprobe.models import Outcome
from vpnprobe.verification import GeoData, VerificationResult, verify_key


class PinnedResolver(AbstractResolver):
    """Resolve one validated hostname to its already inspected public addresses."""

    def __init__(self, hostname: str, addresses: tuple[str, ...]) -> None:
        self.hostname = hostname
        self.addresses = addresses

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[ResolveResult]:
        if host.lower() != self.hostname.lower():
            raise OSError("resolver received an unexpected hostname")
        results: list[ResolveResult] = []
        for address in self.addresses:
            ip = ipaddress.ip_address(address)
            address_family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
            if family not in {socket.AF_UNSPEC, address_family}:
                continue
            results.append(
                ResolveResult(
                    hostname=host,
                    host=address,
                    port=port,
                    family=address_family,
                    proto=0,
                    flags=socket.AI_NUMERICHOST,
                )
            )
        return results

    async def close(self) -> None:
        return None


async def _public_addresses(hostname: str, port: int) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            records = await asyncio.get_running_loop().getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM
            )
        except OSError as exc:
            raise SubscriptionError(f"Subscription DNS lookup failed: {exc}") from exc
        addresses = tuple(dict.fromkeys(str(record[4][0]) for record in records))
    else:
        addresses = (str(literal),)
    if not addresses:
        raise SubscriptionError("Subscription hostname resolved to no addresses")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise SubscriptionError("Subscription URL resolves to a non-public address")
    return addresses


def _validate_subscription_url(url: str) -> tuple[str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise SubscriptionError("Subscription URL must use HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise SubscriptionError("Subscription URL must not contain HTTP credentials")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise SubscriptionError("Subscription URL contains an invalid port") from exc
    return parsed.hostname, port


async def _download_once(url: str, settings: ProbeConfig) -> tuple[int, bytes, str | None]:
    hostname, port = _validate_subscription_url(url)
    addresses = await _public_addresses(hostname, port)
    resolver = PinnedResolver(hostname, addresses)
    connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
    timeout = aiohttp.ClientTimeout(total=settings.key_check_timeout)
    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, trust_env=False, cookie_jar=aiohttp.DummyCookieJar()
    ) as session:
        try:
            async with session.get(
                url,
                allow_redirects=False,
                headers={"X-Hwid": settings.subscription_hwid},
            ) as response:
                location = response.headers.get("Location")
                length = response.content_length
                if length is not None and length > settings.subscription_max_bytes:
                    raise SubscriptionError("Subscription response exceeds the byte limit")
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.content.iter_chunked(64 * 1024):
                    size += len(chunk)
                    if size > settings.subscription_max_bytes:
                        raise SubscriptionError("Subscription response exceeds the byte limit")
                    chunks.append(chunk)
                return response.status, b"".join(chunks), location
        except aiohttp.ClientError as exc:
            raise SubscriptionError(f"Subscription download failed: {exc}") from exc


def _parse_lines(text: str) -> list[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise SubscriptionError("Subscription is empty")
    if any(not line.lower().startswith(("ss://", "vless://", "hysteria2://")) for line in lines):
        raise SubscriptionError("Subscription contains an unsupported or recursive entry")
    try:
        for line in lines:
            identify(line)
    except ConfigurationError as exc:
        raise SubscriptionError(f"Subscription contains an invalid entry: {exc}") from exc
    return lines


def parse_subscription(payload: bytes) -> list[str]:
    """Parse a UTF-8 list, or a whole-list Base64-wrapped UTF-8 list."""
    try:
        text = payload.decode("utf-8-sig").strip()
    except UnicodeDecodeError as exc:
        raise SubscriptionError("Subscription is not UTF-8 text") from exc
    try:
        return _parse_lines(text)
    except SubscriptionError as plain_error:
        compact = "".join(text.split())
        padding = "=" * (-len(compact) % 4)
        try:
            decoded = base64.b64decode(
                compact + padding,
                altchars=b"-_",
                validate=True,
            ).decode("utf-8-sig")
            return _parse_lines(decoded)
        except (binascii.Error, UnicodeDecodeError, SubscriptionError) as exc:
            raise plain_error from exc


async def fetch_subscription(url: str, settings: ProbeConfig) -> list[str]:
    current_url = url
    for redirect_count in range(settings.subscription_max_redirects + 1):
        status, payload, location = await _download_once(current_url, settings)
        if status in {301, 302, 303, 307, 308}:
            if redirect_count >= settings.subscription_max_redirects:
                raise SubscriptionError("Subscription exceeded the redirect limit")
            if not location:
                raise SubscriptionError("Subscription redirect is missing Location")
            current_url = urljoin(current_url, location)
            _validate_subscription_url(current_url)
            continue
        if status == 429 or status >= 500:
            raise SubscriptionError(f"Subscription service returned HTTP {status}")
        if status < 200 or status >= 300:
            raise SubscriptionError(f"Subscription returned HTTP {status}")
        return parse_subscription(payload)
    raise SubscriptionError("Subscription redirect loop")


@dataclass(frozen=True, slots=True)
class SubscriptionResult:
    outcome: Outcome
    detail: str
    identity: Identity
    attempts: int
    successes: int
    speed_mbps: float | None = None
    geo: GeoData | None = None
    latency_ms: float | None = None


AttemptStarted = Callable[[Identity], Awaitable[int | None]]
AttemptFinished = Callable[[int | None, VerificationResult], Awaitable[None]]


async def _noop_started(_identity: Identity) -> int | None:
    return None


async def _noop_finished(_attempt_id: int | None, _result: VerificationResult) -> None:
    return None


async def verify_subscription(
    url: str,
    settings: ProbeConfig,
    logger: EventSink,
    *,
    on_attempt_started: AttemptStarted = _noop_started,
    on_attempt_finished: AttemptFinished = _noop_finished,
) -> SubscriptionResult:
    subscription_identity = identify(url)
    attempts = 0
    successful: list[VerificationResult] = []
    inconclusive = False
    try:
        async with asyncio.timeout(settings.subscription_check_timeout):
            configs = await fetch_subscription(url, settings)
            random.SystemRandom().shuffle(configs)
            for config in configs:
                if attempts >= settings.subscription_max_attempts:
                    break
                if len(successful) >= settings.subscription_success_target:
                    break
                key_identity = identify(config)
                attempt_id = await on_attempt_started(key_identity)
                attempts += 1
                result = await verify_key(config, settings, logger, identity=key_identity)
                await on_attempt_finished(attempt_id, result)
                if result.outcome is Outcome.SUCCESS:
                    successful.append(result)
                elif result.outcome is Outcome.INCONCLUSIVE:
                    inconclusive = True
    except TimeoutError:
        detail = f"subscription exceeded {settings.subscription_check_timeout:g}s"
    except SubscriptionError as exc:
        detail = str(exc)
    else:
        detail = "subscription verification completed"

    if successful:
        best = max(successful, key=lambda item: item.speed_mbps or 0.0)
        measured_latencies = [item.latency_ms for item in successful if item.latency_ms is not None]
        return SubscriptionResult(
            Outcome.SUCCESS,
            detail,
            subscription_identity,
            attempts,
            len(successful),
            best.speed_mbps,
            None,
            min(measured_latencies) if measured_latencies else None,
        )
    if inconclusive:
        return SubscriptionResult(Outcome.INCONCLUSIVE, detail, subscription_identity, attempts, 0)
    return SubscriptionResult(Outcome.FAILED, detail, subscription_identity, attempts, 0)
