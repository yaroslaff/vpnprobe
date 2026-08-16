"""One-key end-to-end verification pipeline."""

from __future__ import annotations

import asyncio
import contextlib
import json
import statistics
import time
from dataclasses import dataclass
from typing import Any

import aiohttp
from aiohttp_socks import ProxyConnectionError, ProxyConnector, ProxyError, ProxyTimeoutError

from vpnprobe.config import ProbeConfig
from vpnprobe.events import EventSink
from vpnprobe.identity import Identity, identify
from vpnprobe.models import Outcome
from vpnprobe.xray import Tunnel, TunnelError, start_tunnel


class VerificationFailure(Exception):
    pass


class ServiceUnavailable(Exception):
    pass


@dataclass(frozen=True, slots=True)
class GeoData:
    ip: str
    country: str
    city: str
    country_code: str | None = None
    asn: int | None = None


@dataclass(frozen=True, slots=True)
class VerificationResult:
    outcome: Outcome
    detail: str
    identity: Identity
    speed_mbps: float | None = None
    geo: GeoData | None = None
    latency_ms: float | None = None
    entry_ip: str | None = None


def _service_status(status: int, service: str) -> None:
    if status == 429 or status >= 500:
        raise ServiceUnavailable(f"{service} returned HTTP {status}")
    if status < 200 or status >= 300:
        raise VerificationFailure(f"{service} returned HTTP {status}")


class NetworkProbe:
    """Perform every network request through one SOCKS tunnel."""

    def __init__(self, proxy_url: str, settings: ProbeConfig) -> None:
        self.settings = settings
        self.connector = ProxyConnector.from_url(proxy_url, rdns=True, force_close=True)

    async def run(self) -> tuple[GeoData, float, float]:
        timeout = aiohttp.ClientTimeout(total=self.settings.key_check_timeout)
        async with aiohttp.ClientSession(
            connector=self.connector, timeout=timeout, trust_env=False
        ) as session:
            await self._wait_for_connectivity(session)
            geo = await self._fetch_geo(session)
            latency = await self._measure_latency(session)
            speed = await self._measure_speed(session)
            return geo, latency, speed

    async def _wait_for_connectivity(self, session: aiohttp.ClientSession) -> None:
        deadline = asyncio.get_running_loop().time() + self.settings.connectivity_check_timeout
        last_detail = "no response"
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise VerificationFailure(f"Connectivity check failed: {last_detail}")
            try:
                async with asyncio.timeout(remaining):
                    async with session.get(self.settings.connectivity_check_url) as response:
                        if response.status == 204:
                            return
                        last_detail = f"HTTP {response.status}"
            except TimeoutError:
                last_detail = f"timed out after {self.settings.connectivity_check_timeout:g}s"
            except (
                aiohttp.ClientError,
                ProxyConnectionError,
                ProxyError,
                ProxyTimeoutError,
                OSError,
            ) as exc:
                last_detail = str(exc)
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise VerificationFailure(f"Connectivity check failed: {last_detail}")
            await asyncio.sleep(min(self.settings.connectivity_retry_interval, remaining))

    async def _fetch_geo(self, session: aiohttp.ClientSession) -> GeoData:
        async with session.get(self.settings.geoip_url) as response:
            _service_status(response.status, "GeoIP service")
            try:
                payload: Any = json.loads(await response.text())
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise VerificationFailure("GeoIP service returned malformed JSON") from exc
        if not isinstance(payload, dict) or payload.get("success") is False:
            raise VerificationFailure("GeoIP service returned an unsuccessful response")
        ip = payload.get("ip")
        country = payload.get("country")
        city = payload.get("city")
        country_code_value = payload.get("country_code")
        connection = payload.get("connection")
        if not isinstance(ip, str) or not ip:
            raise VerificationFailure("GeoIP response is missing ip/country/city")
        if not isinstance(country, str) or not country:
            raise VerificationFailure("GeoIP response is missing ip/country/city")
        if not isinstance(city, str) or not city:
            raise VerificationFailure("GeoIP response is missing ip/country/city")
        country_code = (
            country_code_value.upper()
            if isinstance(country_code_value, str)
            and len(country_code_value) == 2
            and country_code_value.isalpha()
            else None
        )
        asn_value = connection.get("asn") if isinstance(connection, dict) else None
        if isinstance(asn_value, str) and asn_value.isdecimal():
            asn_value = int(asn_value)
        asn = asn_value if isinstance(asn_value, int) and asn_value > 0 else None
        return GeoData(
            ip=ip,
            country=country,
            city=city,
            country_code=country_code,
            asn=asn,
        )

    async def _measure_speed(self, session: aiohttp.ClientSession) -> float:
        byte_count = 0
        started = time.monotonic()
        async with session.get(self.settings.speed_test_url) as response:
            _service_status(response.status, "Speed service")
            async for chunk in response.content.iter_chunked(64 * 1024):
                byte_count += len(chunk)
        elapsed = time.monotonic() - started
        if byte_count <= 0 or elapsed <= 0:
            raise VerificationFailure("Speed service returned an empty response")
        return round(byte_count * 8 / elapsed / 1_000_000, 1)

    async def _latency_request(self, session: aiohttp.ClientSession) -> float:
        started = self._now()
        async with session.get(self.settings.latency_test_url) as response:
            _service_status(response.status, "Latency service")
            async for _chunk in response.content.iter_chunked(64 * 1024):
                pass
        return (self._now() - started) * 1000

    @staticmethod
    def _now() -> float:
        return time.monotonic()

    async def _measure_latency(self, session: aiohttp.ClientSession) -> float:
        # The untimed request warms DNS and the route. force_close=True keeps each
        # measured request on a new HTTP connection instead of reusing Keep-Alive.
        await self._latency_request(session)
        samples = [await self._latency_request(session) for _ in range(3)]
        return round(statistics.median(samples), 1)


async def verify_key(
    config_url: str,
    settings: ProbeConfig,
    logger: EventSink,
    *,
    identity: Identity | None = None,
) -> VerificationResult:
    """Verify one direct VPN configuration and always tear down its tunnel."""
    key_identity = identity or identify(config_url)
    logger.event("VERIFICATION_START", f"key_id={key_identity.short_id}")
    tunnel: Tunnel | None = None
    entry_ip: str | None = None
    entry_observer: asyncio.Task[None] | None = None

    async def observe_entry_ip() -> None:
        nonlocal entry_ip
        if tunnel is not None and entry_ip is None:
            with contextlib.suppress(Exception):
                entry_ip = await tunnel.entry_ip(config_url)

    async def observe_entry_until_found() -> None:
        while entry_ip is None:
            await observe_entry_ip()
            if entry_ip is None:
                await asyncio.sleep(0.1)

    try:
        async with asyncio.timeout(settings.key_check_timeout):
            tunnel = await start_tunnel(config_url, settings)
            await asyncio.sleep(settings.tunnel_settle_delay)
            if tunnel.process.returncode is not None:
                detail = await tunnel.error_output()
                raise TunnelError(f"xray-knife exited early: {detail or tunnel.process.returncode}")
            logger.event("TUNNEL_READY", f"key_id={key_identity.short_id} port={tunnel.port}")
            await observe_entry_ip()
            if entry_ip is None:
                entry_observer = asyncio.create_task(observe_entry_until_found())
            geo, latency, speed = await NetworkProbe(tunnel.proxy_url, settings).run()
            await observe_entry_ip()
        logger.event(
            "VERIFICATION_OK",
            f"key_id={key_identity.short_id} entry_ip={entry_ip or '-'} "
            f"exit_ip={geo.ip} country={geo.country} "
            f"city={geo.city} latency_ms={latency:.1f} speed_mbps={speed:.1f}",
        )
        return VerificationResult(
            Outcome.SUCCESS,
            "verification succeeded",
            key_identity,
            speed,
            geo,
            latency,
            entry_ip,
        )
    except ServiceUnavailable as exc:
        await observe_entry_ip()
        logger.event("ERROR_SERVICE_UNAVAILABLE", f"key_id={key_identity.short_id} detail={exc}")
        return VerificationResult(Outcome.INCONCLUSIVE, str(exc), key_identity, entry_ip=entry_ip)
    except TimeoutError:
        await observe_entry_ip()
        detail = f"verification exceeded {settings.key_check_timeout:g}s"
        logger.event("ERROR_VERIFICATION", f"key_id={key_identity.short_id} detail={detail}")
        return VerificationResult(Outcome.FAILED, detail, key_identity, entry_ip=entry_ip)
    except (
        VerificationFailure,
        TunnelError,
        aiohttp.ClientError,
        ProxyConnectionError,
        ProxyError,
        ProxyTimeoutError,
        OSError,
    ) as exc:
        await observe_entry_ip()
        logger.event("ERROR_VERIFICATION", f"key_id={key_identity.short_id} detail={exc}")
        return VerificationResult(Outcome.FAILED, str(exc), key_identity, entry_ip=entry_ip)
    finally:
        if entry_observer is not None:
            entry_observer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await entry_observer
        if tunnel is not None:
            cleanup = asyncio.create_task(tunnel.stop())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await cleanup
                raise
