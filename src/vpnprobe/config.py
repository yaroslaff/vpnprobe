"""Explicit, persistence-free probe configuration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from vpnprobe.errors import ConfigurationError


class ProbeConfig(Protocol):
    """ProbeConfig required by the reusable verification functions."""

    @property
    def xray_knife_path(self) -> str: ...

    @property
    def hysteria_path(self) -> str: ...

    @property
    def key_check_timeout(self) -> float: ...

    @property
    def process_stop_timeout(self) -> float: ...

    @property
    def tunnel_settle_delay(self) -> float: ...

    @property
    def connectivity_check_url(self) -> str: ...

    @property
    def connectivity_check_timeout(self) -> float: ...

    @property
    def connectivity_retry_interval(self) -> float: ...

    @property
    def geoip_url(self) -> str: ...

    @property
    def latency_test_url(self) -> str: ...

    @property
    def speed_test_url(self) -> str: ...

    @property
    def subscription_success_target(self) -> int: ...

    @property
    def subscription_max_attempts(self) -> int: ...

    @property
    def subscription_check_timeout(self) -> float: ...

    @property
    def subscription_max_bytes(self) -> int: ...

    @property
    def subscription_max_redirects(self) -> int: ...

    @property
    def subscription_hwid(self) -> str: ...

    @property
    def tdjson_library(self) -> str: ...

    @property
    def telegram_proxy_check_timeout(self) -> float: ...

    @property
    def telegram_proxy_dc(self) -> str: ...


@dataclass(frozen=True, slots=True)
class Settings:
    """Standalone defaults used by the vpnprobe CLI and library consumers."""

    xray_knife_path: str = "xray-knife"
    hysteria_path: str = "hysteria"
    key_check_timeout: float = 300.0
    process_stop_timeout: float = 5.0
    tunnel_settle_delay: float = 3.0
    connectivity_check_url: str = "https://www.gstatic.com/generate_204"
    connectivity_check_timeout: float = 30.0
    connectivity_retry_interval: float = 1.0
    geoip_url: str = "https://ipwho.is/"
    latency_test_url: str = "https://www.gstatic.com/generate_204"
    speed_test_url: str = "https://sse-testcenter.org/download/10m.bin"
    subscription_success_target: int = 3
    subscription_max_attempts: int = 20
    subscription_check_timeout: float = 1800.0
    subscription_max_bytes: int = 1_048_576
    subscription_max_redirects: int = 5
    subscription_hwid: str = "00112233-4455-6677-8899-aabbccddeeff"
    tdjson_library: str = ""
    telegram_proxy_check_timeout: float = 15.0
    telegram_proxy_dc: str = "ALL"


def parse_telegram_proxy_dc(value: str, *, name: str = "DC") -> str:
    normalized = value.strip().upper()
    if normalized == "ALL" or normalized in {"1", "2", "3", "4", "5"}:
        return normalized
    raise ConfigurationError(f"{name} must be 1, 2, 3, 4, 5, or ALL")


def telegram_proxy_dc_ids(value: str) -> tuple[int, ...]:
    normalized = parse_telegram_proxy_dc(value)
    if normalized == "ALL":
        return (1, 2, 3, 4, 5)
    return (int(normalized),)
