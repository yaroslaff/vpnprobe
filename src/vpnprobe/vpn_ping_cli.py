"""Direct VPN runner used by ``vpnprobe ping``."""

from __future__ import annotations

import asyncio
import sys
from dataclasses import replace
from urllib.parse import urlsplit

import aiohttp
from aiohttp_socks import ProxyConnectionError, ProxyConnector, ProxyError, ProxyTimeoutError

from vpnprobe.config import Settings
from vpnprobe.xray import Tunnel, TunnelError, start_tunnel

# xray-knife and the Hysteria client report their own verdicts on stdout but always
# exit 0, so the probe result is decided by our own request through the tunnel.
PROBE_ERRORS = (
    TimeoutError,
    TunnelError,
    aiohttp.ClientError,
    ProxyConnectionError,
    ProxyError,
    ProxyTimeoutError,
    OSError,
)


def _protocol_label(url: str) -> str:
    return urlsplit(url.strip()).scheme.lower() or "vpn"


async def _wait_for_connectivity(
    session: aiohttp.ClientSession,
    settings: Settings,
    tunnel: Tunnel,
    deadline: float,
) -> int:
    """Request the connectivity endpoint until it answers 204 or the deadline passes."""
    loop = asyncio.get_running_loop()
    last_detail = "no response"
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TunnelError(f"Connectivity check failed: {last_detail}")
        if tunnel.process.returncode is not None:
            detail = await tunnel.error_output()
            raise TunnelError(f"Tunnel exited early: {detail or tunnel.process.returncode}")
        try:
            async with asyncio.timeout(remaining):
                async with session.get(settings.connectivity_check_url) as response:
                    if response.status == 204:
                        await response.read()
                        return response.status
                    last_detail = f"HTTP {response.status}, expected 204"
        except TimeoutError:
            last_detail = f"timed out after {settings.connectivity_check_timeout:g}s"
        except PROBE_ERRORS as exc:
            last_detail = str(exc).strip() or type(exc).__name__
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TunnelError(f"Connectivity check failed: {last_detail}")
        await asyncio.sleep(min(settings.connectivity_retry_interval, remaining))


async def _measure_download(session: aiohttp.ClientSession, settings: Settings) -> float:
    loop = asyncio.get_running_loop()
    started = loop.time()
    byte_count = 0
    async with session.get(settings.speed_test_url) as response:
        if response.status < 200 or response.status >= 300:
            raise TunnelError(f"Speed endpoint returned HTTP {response.status}")
        async for chunk in response.content.iter_chunked(64 * 1024):
            byte_count += len(chunk)
    elapsed = loop.time() - started
    if not byte_count or elapsed <= 0:
        raise TunnelError("Speed endpoint returned an empty response")
    return byte_count * 8 / elapsed / 1_000_000


async def run_vpn_ping(
    url: str,
    settings: Settings,
    timeout_seconds: float | None,
    *,
    speedtest: bool,
) -> int:
    """Probe one direct VPN URL and return 0 only when traffic really flows."""
    label = _protocol_label(url)
    timeout = timeout_seconds or settings.connectivity_check_timeout
    effective = replace(
        settings,
        key_check_timeout=timeout,
        connectivity_check_timeout=timeout,
    )
    deadline = asyncio.get_running_loop().time() + timeout
    tunnel = None
    try:
        try:
            async with asyncio.timeout_at(deadline):
                tunnel = await start_tunnel(url, effective)
        except TimeoutError:
            raise TunnelError(f"Tunnel was not ready after {timeout:g}s") from None
        connector = ProxyConnector.from_url(tunnel.proxy_url, rdns=True, force_close=True)
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=client_timeout,
            trust_env=False,
        ) as session:
            status = await _wait_for_connectivity(session, effective, tunnel, deadline)
            print(f"OK {label} connectivity HTTP {status}")
            if speedtest:
                async with asyncio.timeout(timeout):
                    print(f"Download: {await _measure_download(session, effective):.1f} Mbps")
        return 0
    except PROBE_ERRORS as exc:
        detail = str(exc).strip() or type(exc).__name__
        print(f"ERR {label} {detail}", file=sys.stderr)
        return 1
    finally:
        if tunnel is not None:
            await tunnel.stop()
