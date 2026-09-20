"""Unprivileged VPN and MTProto probing library."""

from vpnprobe.config import ProbeConfig, Settings
from vpnprobe.identity import Identity, TelegramProxy, identify, is_telegram_proxy
from vpnprobe.models import Outcome
from vpnprobe.ping import PingOptions, ping
from vpnprobe.subscription import SubscriptionResult, fetch_subscription, verify_subscription
from vpnprobe.tdlib import ProxyTestResult, ping_telegram_proxy, verify_telegram_proxy
from vpnprobe.verification import GeoData, VerificationResult, verify_key

__version__ = "0.3.4"

__all__ = [
    "GeoData",
    "Identity",
    "Outcome",
    "PingOptions",
    "ProbeConfig",
    "ProxyTestResult",
    "Settings",
    "SubscriptionResult",
    "TelegramProxy",
    "VerificationResult",
    "fetch_subscription",
    "identify",
    "is_telegram_proxy",
    "ping",
    "ping_telegram_proxy",
    "verify_key",
    "verify_subscription",
    "verify_telegram_proxy",
]
