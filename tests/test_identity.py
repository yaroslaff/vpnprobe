from __future__ import annotations

import base64

import pytest

from vpnprobe.config import parse_telegram_proxy_dc, telegram_proxy_dc_ids
from vpnprobe.errors import ConfigurationError
from vpnprobe.identity import canonicalize_url, identify, server_endpoint, telegram_proxy


def test_dc_selection() -> None:
    assert parse_telegram_proxy_dc("all") == "ALL"
    assert telegram_proxy_dc_ids("ALL") == (1, 2, 3, 4, 5)
    assert telegram_proxy_dc_ids("3") == (3,)
    with pytest.raises(ConfigurationError, match="1, 2, 3, 4, 5"):
        parse_telegram_proxy_dc("6")


def test_canonical_identity() -> None:
    first = identify("VLESS://ABC@Example.COM:443?type=tcp&security=tls#first")
    second = identify("vless://ABC@example.com:443?security=tls&type=tcp#second")
    assert first.canonical == second.canonical
    assert first.digest == second.digest
    assert first.short_id == first.digest.hex()[:8]
    assert canonicalize_url("https://EXAMPLE.com:443/a%20b#x") == "https://example.com/a%20b"
    with pytest.raises(ConfigurationError, match="Unsupported"):
        identify("ftp://example.com/key")


def test_direct_server_endpoint() -> None:
    assert server_endpoint("vless://id@example.com:443") == ("example.com", 443)
    encoded = (
        base64.urlsafe_b64encode(b"aes-256-gcm:password@legacy.example:9443").decode().rstrip("=")
    )
    assert server_endpoint(f"ss://{encoded}#name") == ("legacy.example", 9443)
    with pytest.raises(ConfigurationError, match="direct"):
        server_endpoint("https://example.com/sub")
    with pytest.raises(ConfigurationError, match="legacy SS authority"):
        server_endpoint("ss://\u041f\u0430\u0440\u043e\u043b\u044c")


def test_mtproto_proxy_identity() -> None:
    secret = "00112233445566778899aabbccddeeff"
    tg = f"tg://proxy?secret={secret.upper()}&port=443&server=Proxy.Example"
    https = f"https://t.me/proxy?server=proxy.example&port=443&secret={secret}"
    parsed = telegram_proxy(tg)
    assert parsed.server == "proxy.example"
    assert parsed.canonical_url == https
    assert identify(tg).canonical == identify(https).canonical
    with pytest.raises(ConfigurationError, match="Telegram proxy"):
        telegram_proxy("tg://proxy?server=x&port=0&secret=00")


@pytest.mark.parametrize(
    "url",
    (
        "tg://proxy?server=x&port=443",
        "tg://proxy?server=x&port=443&port=444&secret=00112233445566778899aabbccddeeff",
        "tg://proxy?server=bad host&port=443&secret=00112233445566778899aabbccddeeff",
        "tg://proxy?server=x&port=bad&secret=00112233445566778899aabbccddeeff",
        "tg://proxy?server=x&port=443&secret=not-hex",
    ),
)
def test_mtproto_proxy_rejects_invalid_links(url: str) -> None:
    with pytest.raises(ConfigurationError):
        telegram_proxy(url)
