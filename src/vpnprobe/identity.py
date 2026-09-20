"""Canonical identities for keys and subscriptions."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from vpnprobe.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class Identity:
    original: str
    canonical: str
    digest: bytes
    short_id: str


@dataclass(frozen=True, slots=True)
class TelegramProxy:
    server: str
    port: int
    secret: str
    canonical_url: str


def _telegram_proxy_shape(value: str) -> bool:
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() == "tg":
        return parsed.netloc.lower() == "proxy" and parsed.path in {"", "/"}
    return (
        parsed.scheme.lower() == "https"
        and parsed.hostname is not None
        and parsed.hostname.lower() == "t.me"
        and parsed.path.rstrip("/").lower() == "/proxy"
    )


def telegram_proxy(value: str) -> TelegramProxy:
    """Parse and canonicalize an official MTProto Telegram proxy link."""
    if not _telegram_proxy_shape(value):
        raise ConfigurationError("An MTProto Telegram proxy link is required")
    parsed = urlsplit(value.strip())
    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
    allowed = {"server", "port", "secret"}
    if any(name not in allowed for name, _item in pairs):
        raise ConfigurationError("Telegram proxy link contains unsupported parameters")
    values: dict[str, str] = {}
    for name, item in pairs:
        if name in values:
            raise ConfigurationError(f"Telegram proxy parameter {name} is repeated")
        values[name] = item
    if set(values) != allowed:
        raise ConfigurationError("Telegram proxy link requires server, port, and secret")

    raw_server = values["server"].strip().removeprefix("[").removesuffix("]")
    if not raw_server or any(character.isspace() for character in raw_server):
        raise ConfigurationError("Telegram proxy server is invalid")
    try:
        server = str(ipaddress.ip_address(raw_server))
    except ValueError:
        try:
            server = raw_server.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ConfigurationError("Telegram proxy server is invalid") from exc
        labels = server.split(".")
        if len(server) > 253 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        ):
            raise ConfigurationError("Telegram proxy server is invalid") from None

    try:
        port = int(values["port"])
    except ValueError as exc:
        raise ConfigurationError("Telegram proxy port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ConfigurationError("Telegram proxy port must be between 1 and 65535")

    secret = values["secret"].strip().lower()
    try:
        secret_bytes = bytes.fromhex(secret)
    except ValueError as exc:
        raise ConfigurationError("Telegram proxy secret must be hexadecimal") from exc
    if len(secret_bytes) < 16 or len(secret_bytes) > 256:
        raise ConfigurationError("Telegram proxy secret must contain 16-256 bytes")
    canonical = "https://t.me/proxy?" + urlencode(
        (("server", server), ("port", str(port)), ("secret", secret)),
        safe=":",
    )
    return TelegramProxy(server, port, secret, canonical)


def is_telegram_proxy(value: str) -> bool:
    return _telegram_proxy_shape(value)


def server_endpoint(value: str) -> tuple[str, int]:
    """Return the configured direct VPN server host and port."""
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"ss", "vless", "hysteria2"}:
        raise ConfigurationError("A direct VPN key is required")
    if parsed.scheme.lower() == "ss" and "@" not in parsed.netloc:
        payload = parsed.netloc
        padding = "=" * (-len(payload) % 4)
        try:
            decoded = base64.urlsafe_b64decode(payload + padding).decode("utf-8")
        except ValueError as exc:
            raise ConfigurationError("Invalid legacy SS authority") from exc
        parsed = urlsplit(f"ss://{decoded}")
    hostname = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("URL contains an invalid port") from exc
    if hostname is None or port is None:
        raise ConfigurationError("VPN URL must include a server host and port")
    return hostname, port


def canonicalize_url(value: str) -> str:
    """Conservatively canonicalize a supported key or subscription URL."""
    original = value.strip()
    if is_telegram_proxy(original):
        return telegram_proxy(original).canonical_url
    parsed = urlsplit(original)
    scheme = parsed.scheme.lower()
    if scheme not in {"ss", "vless", "hysteria2", "http", "https"}:
        raise ConfigurationError(f"Unsupported URL scheme: {parsed.scheme or '<missing>'}")
    if not parsed.netloc:
        raise ConfigurationError("URL must include an authority")

    if scheme == "ss":
        # Legacy SS stores a case-sensitive Base64 payload in netloc. Treat the
        # authority conservatively because it is ambiguous without decoding it.
        netloc = parsed.netloc
    else:
        hostname = parsed.hostname
        if hostname is None:
            raise ConfigurationError("URL must include a hostname")
        host = hostname.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = parsed.port
        except ValueError as exc:
            raise ConfigurationError("URL contains an invalid port") from exc
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        port_part = "" if port is None or default_port else f":{port}"
        userinfo = ""
        if parsed.username is not None:
            userinfo = quote(parsed.username, safe="-._~:")
            if parsed.password is not None:
                userinfo += ":" + quote(parsed.password, safe="-._~:")
            userinfo += "@"
        netloc = f"{userinfo}{host}{port_part}"

    query_items = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
    query_items.sort(key=lambda pair: (pair[0], pair[1]))
    query = urlencode(query_items, doseq=True, safe=":")
    path = quote(parsed.path or "", safe="/%:@-._~")
    return urlunsplit((scheme, netloc, path, query, ""))


def identify(value: str) -> Identity:
    canonical = canonicalize_url(value)
    digest = hashlib.sha256(canonical.encode()).digest()
    return Identity(value.strip(), canonical, digest, digest.hex()[:8])
