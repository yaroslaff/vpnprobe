"""Public quick-ping dispatcher shared by the CLI and Python callers."""

from __future__ import annotations

from dataclasses import dataclass

from vpnprobe.config import Settings, parse_telegram_proxy_dc
from vpnprobe.errors import ConfigurationError
from vpnprobe.identity import is_telegram_proxy
from vpnprobe.proxy_ping_cli import run_proxy_ping
from vpnprobe.vpn_ping_cli import run_vpn_ping


@dataclass(frozen=True, slots=True)
class PingOptions:
    timeout: float | None = None
    speedtest: bool = False
    dc: str | None = None
    xray_knife_path: str = "xray-knife"
    hysteria_path: str = "hysteria"
    tdjson_library: str = ""
    process_stop_timeout: float = 5.0


async def ping(url: str, options: PingOptions | None = None) -> int:
    """Quickly test one direct VPN or MTProto proxy URL."""
    options = options or PingOptions()
    if options.timeout is not None and options.timeout <= 0:
        raise ConfigurationError("timeout must be a positive number")
    settings = Settings(
        xray_knife_path=options.xray_knife_path,
        hysteria_path=options.hysteria_path,
        tdjson_library=options.tdjson_library,
        process_stop_timeout=options.process_stop_timeout,
    )
    if is_telegram_proxy(url):
        if options.speedtest:
            raise ConfigurationError("--speedtest is not supported for MTProto proxies")
        timeout = options.timeout or settings.telegram_proxy_check_timeout
        dc = parse_telegram_proxy_dc(options.dc or settings.telegram_proxy_dc)
        return await run_proxy_ping(url, settings, timeout, dc)
    if options.dc is not None:
        raise ConfigurationError("--dc is supported only for MTProto proxies")
    return await run_vpn_ping(
        url,
        settings,
        options.timeout,
        speedtest=options.speedtest,
    )
