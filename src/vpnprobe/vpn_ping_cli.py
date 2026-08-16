"""Direct VPN runner used by ``vpnprobe ping``."""

from __future__ import annotations

import asyncio
import sys
from dataclasses import replace

import aiohttp
from aiohttp_socks import ProxyConnector

from vpnprobe.config import Settings
from vpnprobe.processes import stop_process_group
from vpnprobe.xray import TunnelError, start_tunnel


async def _run_hysteria_ping(
    url: str,
    settings: Settings,
    timeout_seconds: float | None,
    *,
    speedtest: bool,
) -> int:
    timeout = timeout_seconds or settings.connectivity_check_timeout
    effective = replace(
        settings,
        key_check_timeout=timeout,
        connectivity_check_timeout=timeout,
    )
    tunnel = None
    try:
        async with asyncio.timeout(timeout):
            tunnel = await start_tunnel(url, effective)
            connector = ProxyConnector.from_url(tunnel.proxy_url, rdns=True, force_close=True)
            client_timeout = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=client_timeout,
                trust_env=False,
            ) as session:
                async with session.get(effective.connectivity_check_url) as response:
                    if response.status != 204:
                        raise TunnelError(
                            f"Connectivity endpoint returned HTTP {response.status}, expected 204"
                        )
                    await response.read()
                print(f"OK Hysteria2 connectivity HTTP {response.status}")
                if speedtest:
                    started = asyncio.get_running_loop().time()
                    byte_count = 0
                    async with session.get(effective.speed_test_url) as response:
                        if response.status < 200 or response.status >= 300:
                            raise TunnelError(f"Speed endpoint returned HTTP {response.status}")
                        async for chunk in response.content.iter_chunked(64 * 1024):
                            byte_count += len(chunk)
                    elapsed = asyncio.get_running_loop().time() - started
                    if not byte_count or elapsed <= 0:
                        raise TunnelError("Speed endpoint returned an empty response")
                    print(f"Download: {byte_count * 8 / elapsed / 1_000_000:.1f} Mbps")
        return 0
    except (TimeoutError, TunnelError, aiohttp.ClientError, OSError) as exc:
        detail = str(exc).strip() or type(exc).__name__
        print(f"ERR Hysteria2 {detail}", file=sys.stderr)
        return 1
    finally:
        if tunnel is not None:
            await tunnel.stop()


async def run_vpn_ping(
    url: str,
    settings: Settings,
    timeout_seconds: float | None,
    *,
    speedtest: bool,
) -> int:
    if url.strip().lower().startswith("hysteria2://"):
        return await _run_hysteria_ping(
            url,
            settings,
            timeout_seconds,
            speedtest=speedtest,
        )
    arguments = [
        settings.xray_knife_path,
        "http",
        "--config",
        url,
        "--out",
        "/dev/null",
    ]
    if speedtest:
        arguments.append("--speedtest")
    if timeout_seconds is not None:
        timeout_ms = max(1, round(timeout_seconds * 1000))
        arguments.extend(("--timeout", str(timeout_ms), "--mdelay", str(timeout_ms)))
    process = await asyncio.create_subprocess_exec(*arguments, start_new_session=True)
    try:
        return await process.wait()
    finally:
        await stop_process_group(process, settings.process_stop_timeout)
