"""Lifecycle management for one disposable direct-VPN SOCKS tunnel."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import os
import random
import signal
import socket
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlsplit

import psutil

from vpnprobe.config import ProbeConfig
from vpnprobe.errors import ProbeError
from vpnprobe.identity import server_endpoint


class TunnelError(ProbeError):
    pass


def _random_free_port() -> int:
    generator = random.SystemRandom()
    for _attempt in range(20):
        port = generator.randint(20_000, 60_999)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            try:
                candidate.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise TunnelError("Cannot find a free proxy port after 20 attempts")


@dataclass(slots=True)
class Tunnel:
    process: asyncio.subprocess.Process
    port: int
    stop_timeout: float
    username: str = ""
    password: str = ""
    config_path: Path | None = None

    @property
    def proxy_url(self) -> str:
        if self.username:
            username = quote(self.username, safe="")
            password = quote(self.password, safe="")
            return f"socks5://{username}:{password}@127.0.0.1:{self.port}"
        return f"socks5://127.0.0.1:{self.port}"

    async def error_output(self) -> str:
        if self.process.stderr is None:
            return ""
        data = await self.process.stderr.read()
        return data.decode(errors="replace").strip()[-1000:]

    async def entry_ip(self, config_url: str) -> str | None:
        """Observe the remote server IP used by the tunnel process tree."""
        hostname, server_port = server_endpoint(config_url)
        try:
            return str(ipaddress.ip_address(hostname))
        except ValueError:
            return await asyncio.to_thread(_process_tree_remote_ip, self.process.pid, server_port)

    async def stop(self) -> None:
        try:
            if self.process.returncode is not None:
                await self.process.wait()
                return
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGTERM)
            try:
                await asyncio.wait_for(self.process.wait(), timeout=self.stop_timeout)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.process.pid, signal.SIGKILL)
                await self.process.wait()
        finally:
            if self.config_path is not None:
                with contextlib.suppress(OSError):
                    self.config_path.unlink()


def _process_tree_remote_ip(process_id: int, server_port: int) -> str | None:
    try:
        root = psutil.Process(process_id)
        processes = (root, *root.children(recursive=True))
    except (psutil.Error, OSError):
        return None
    addresses: set[str] = set()
    for process in processes:
        try:
            connections = process.net_connections(kind="inet")
        except (psutil.Error, OSError):
            continue
        for connection in connections:
            if not connection.raddr or connection.raddr.port != server_port:
                continue
            try:
                address = ipaddress.ip_address(connection.raddr.ip)
            except ValueError:
                continue
            if not address.is_loopback:
                addresses.add(str(address))
    if len(addresses) == 1:
        return addresses.pop()
    return None


def _single_query_values(query: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for name, value in parse_qsl(query, keep_blank_values=True):
        if name in values:
            raise TunnelError(f"Hysteria2 parameter {name} is repeated")
        values[name] = value
    return values


def _hysteria_config(config_url: str, port: int) -> dict[str, object]:
    parsed = urlsplit(config_url.strip())
    if parsed.scheme.lower() != "hysteria2":
        raise TunnelError("A Hysteria2 URL is required")
    hostname = parsed.hostname
    try:
        server_port = parsed.port
    except ValueError as exc:
        raise TunnelError("Hysteria2 URL contains an invalid port") from exc
    if hostname is None or server_port is None:
        raise TunnelError("Hysteria2 URL must include a server host and port")
    authority = parsed.netloc.rsplit("@", 1)
    if len(authority) != 2 or not authority[0]:
        raise TunnelError("Hysteria2 URL must include an authentication password")
    auth = unquote(authority[0])
    values = _single_query_values(parsed.query)
    obfs_type = values.get("obfs", "")
    obfs_password = values.get("obfs-password", "")
    if obfs_password and not obfs_type:
        raise TunnelError("Hysteria2 obfs-password requires obfs=salamander")
    if obfs_type and obfs_type != "salamander":
        raise TunnelError(f"Unsupported Hysteria2 obfuscation type: {obfs_type}")
    if obfs_type == "salamander" and not obfs_password:
        raise TunnelError("Hysteria2 obfs=salamander requires obfs-password")

    host = f"[{hostname}]" if ":" in hostname else hostname
    tls: dict[str, object] = {}
    if sni := values.get("sni"):
        tls["sni"] = sni
    if values.get("insecure", "0").lower() in {"1", "true"}:
        tls["insecure"] = True
    if pin := values.get("pinSHA256"):
        tls["pinSHA256"] = pin
    config: dict[str, object] = {
        "server": f"{host}:{server_port}",
        "auth": auth,
        "socks5": {"listen": f"127.0.0.1:{port}"},
    }
    if tls:
        config["tls"] = tls
    if obfs_type:
        config["obfs"] = {
            "type": "salamander",
            "salamander": {"password": obfs_password},
        }
    return config


def _write_hysteria_config(config_url: str, port: int) -> Path:
    descriptor, name = tempfile.mkstemp(prefix="vpnprobe-hysteria-", suffix=".json")
    path = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(_hysteria_config(config_url, port), stream)
            stream.write("\n")
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink()
        raise
    return path


async def _wait_for_socks(tunnel: Tunnel, timeout_seconds: float) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while True:
        if tunnel.process.returncode is not None:
            detail = await tunnel.error_output()
            raise TunnelError(f"Hysteria exited before SOCKS was ready: {detail}")
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", tunnel.port)
        except OSError:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TunnelError(
                    f"Hysteria SOCKS was not ready after {timeout_seconds:g}s"
                ) from None
            await asyncio.sleep(min(0.05, remaining))
        else:
            writer.close()
            await writer.wait_closed()
            del reader
            return


async def _start_hysteria_tunnel(config_url: str, settings: ProbeConfig, port: int) -> Tunnel:
    config_path = _write_hysteria_config(config_url, port)
    arguments = [
        settings.hysteria_path,
        "client",
        "--disable-update-check",
        "--log-level",
        "warn",
        "--config",
        str(config_path),
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        config_path.unlink(missing_ok=True)
        raise TunnelError(f"Cannot start Hysteria: {exc}") from exc
    tunnel = Tunnel(process, port, settings.process_stop_timeout, config_path=config_path)
    try:
        await _wait_for_socks(tunnel, settings.connectivity_check_timeout)
    except (TimeoutError, TunnelError):
        await tunnel.stop()
        raise
    return tunnel


async def start_tunnel(config_url: str, settings: ProbeConfig) -> Tunnel:
    port = _random_free_port()
    if config_url.strip().lower().startswith("hysteria2://"):
        return await _start_hysteria_tunnel(config_url, settings, port)
    arguments = [
        settings.xray_knife_path,
        "proxy",
        "inbound",
        "--addr",
        "127.0.0.1",
        "--port",
        str(port),
        "--stdin",
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise TunnelError(f"Cannot start xray-knife: {exc}") from exc
    assert process.stdin is not None
    assert process.stdout is not None
    tunnel = Tunnel(process, port, settings.process_stop_timeout)
    try:
        process.stdin.write((config_url + "\n").encode())
        await process.stdin.drain()
        process.stdin.close()
        await process.stdin.wait_closed()
        username = ""
        password = ""
        async with asyncio.timeout(settings.connectivity_check_timeout):
            while not username or not password:
                line = await process.stdout.readline()
                if not line:
                    detail = await tunnel.error_output()
                    raise TunnelError(f"xray-knife exited before SOCKS credentials: {detail}")
                text = line.decode(errors="replace").strip()
                if text.startswith("Username:"):
                    username = text.partition(":")[2].strip()
                elif text.startswith("Password:"):
                    password = text.partition(":")[2].strip()
        tunnel.username = username
        tunnel.password = password
    except (BrokenPipeError, ConnectionResetError) as exc:
        await tunnel.stop()
        raise TunnelError("xray-knife closed stdin before reading the configuration") from exc
    except (TimeoutError, TunnelError):
        await tunnel.stop()
        raise
    return tunnel
