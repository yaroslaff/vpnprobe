from __future__ import annotations

import asyncio
import json
import os
import signal
from types import SimpleNamespace
from typing import Any

import pytest

from vpnprobe.config import Settings
from vpnprobe.xray import (
    ERROR_OUTPUT_CHARS,
    Tunnel,
    TunnelError,
    _hysteria_config,
    _process_tree_remote_ip,
    _random_free_port,
    _start_hysteria_tunnel,
    _wait_for_socks,
    condense_output,
    start_tunnel,
)


class FakeStdin:
    def __init__(self) -> None:
        self.data = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class FakeProcess:
    def __init__(self) -> None:
        self.pid = 12345
        self.returncode: int | None = None
        self.stdin = FakeStdin()
        self.stderr: Any = None
        self.stdout = FakeStdout()

    async def wait(self) -> int:
        self.returncode = 0
        return 0


class FakeStdout:
    def __init__(self) -> None:
        self.lines = [b"Username: test-user\n", b"Password: test-password\n"]

    async def readline(self) -> bytes:
        return self.lines.pop(0) if self.lines else b""


def test_random_port_is_in_range(monkeypatch: pytest.MonkeyPatch) -> None:
    class Generator:
        def randint(self, _start: int, _end: int) -> int:
            return 23456

    class Candidate:
        def __enter__(self) -> Candidate:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def bind(self, address: tuple[str, int]) -> None:
            assert address == ("127.0.0.1", 23456)

    monkeypatch.setattr("vpnprobe.xray.random.SystemRandom", Generator)
    monkeypatch.setattr("vpnprobe.xray.socket.socket", lambda *_args: Candidate())
    assert _random_free_port() == 23456


@pytest.mark.asyncio
async def test_start_and_stop_tunnel(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess()
    calls: list[tuple[object, ...]] = []

    async def create(*args: object, **_kwargs: object) -> FakeProcess:
        calls.append(args)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr("vpnprobe.xray._random_free_port", lambda: 23456)
    tunnel = await start_tunnel("vless://id@example.com:443", settings)
    assert tunnel.port == 23456
    assert tunnel.proxy_url == "socks5://test-user:test-password@127.0.0.1:23456"
    assert process.stdin.data.startswith(b"vless://")
    assert "--core" not in calls[-1]
    stop_calls: list[tuple[int, signal.Signals]] = []
    monkeypatch.setattr(os, "killpg", lambda pid, sig: stop_calls.append((pid, sig)))
    monkeypatch.setattr("vpnprobe.processes._process_group_exists", lambda _pid: False)
    await tunnel.stop()
    assert stop_calls == [(12345, signal.SIGTERM)]
    await tunnel.stop()


@pytest.mark.asyncio
async def test_hysteria2_tunnel_uses_native_client(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = FakeProcess()
    calls: list[tuple[object, ...]] = []

    async def create(*args: object, **_kwargs: object) -> FakeProcess:
        calls.append(args)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr("vpnprobe.xray._random_free_port", lambda: 23456)

    async def ready(_tunnel: Tunnel, _timeout: float) -> None:
        return None

    monkeypatch.setattr("vpnprobe.xray._wait_for_socks", ready)
    tunnel = await start_tunnel(
        "hysteria2://user:password@example.com:9443?"
        "obfs=salamander&obfs-password=secret&sni=vpn.example",
        settings,
    )
    assert calls[-1][0] == settings.hysteria_path
    assert tunnel.config_path is not None
    payload = json.loads(tunnel.config_path.read_text())
    assert payload["auth"] == "user:password"
    assert payload["server"] == "example.com:9443"
    assert payload["tls"] == {"sni": "vpn.example"}
    assert payload["obfs"]["salamander"]["password"] == "secret"
    monkeypatch.setattr(os, "killpg", lambda _pid, _sig: None)
    path = tunnel.config_path
    await tunnel.stop()
    assert not path.exists()


def test_hysteria_config_validation() -> None:
    config = _hysteria_config(
        "hysteria2://p%3Aa@[2001:db8::1]:443?insecure=1&pinSHA256=abc",
        23456,
    )
    assert config["server"] == "[2001:db8::1]:443"
    assert config["auth"] == "p:a"
    assert config["tls"] == {"insecure": True, "pinSHA256": "abc"}

    invalid = (
        "vless://id@example.com:443",
        "hysteria2://example.com:443",
        "hysteria2://password@example.com",
        "hysteria2://password@example.com:443?obfs-password=secret",
        "hysteria2://password@example.com:443?obfs=salamander",
        "hysteria2://password@example.com:443?obfs=unknown",
        "hysteria2://password@example.com:443?sni=a&sni=b",
    )
    for url in invalid:
        with pytest.raises(TunnelError):
            _hysteria_config(url, 23456)


@pytest.mark.asyncio
async def test_wait_for_hysteria_socks(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess()
    tunnel = Tunnel(process, 23456, 0.01)  # type: ignore[arg-type]

    class Writer:
        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def connected(_host: str, _port: int) -> tuple[object, Writer]:
        return object(), Writer()

    monkeypatch.setattr(asyncio, "open_connection", connected)
    await _wait_for_socks(tunnel, 0.01)

    process.returncode = 2
    with pytest.raises(TunnelError, match="exited before SOCKS"):
        await _wait_for_socks(tunnel, 0.01)

    process.returncode = None

    async def refused(_host: str, _port: int) -> tuple[object, Writer]:
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", refused)
    with pytest.raises(TunnelError, match="not ready"):
        await _wait_for_socks(tunnel, 0)


@pytest.mark.asyncio
async def test_hysteria_start_failure_removes_config(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    config_path = tmp_path / "secret.json"
    config_path.write_text("{}")
    monkeypatch.setattr("vpnprobe.xray._write_hysteria_config", lambda _url, _port: config_path)

    async def cannot_start(*_args: object, **_kwargs: object) -> FakeProcess:
        raise OSError("missing")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", cannot_start)
    with pytest.raises(TunnelError, match="Cannot start Hysteria"):
        await _start_hysteria_tunnel("hysteria2://password@example.com:443", settings, 23456)
    assert not config_path.exists()


@pytest.mark.asyncio
async def test_tunnel_error_output() -> None:
    class Stderr:
        async def read(self) -> bytes:
            return b"details"

    process = FakeProcess()
    process.stderr = Stderr()
    tunnel = Tunnel(process, 12345, 0.01)  # type: ignore[arg-type]
    assert await tunnel.error_output() == "details"
    process.stderr = None
    assert await tunnel.error_output() == ""
    tunnel.username = ""
    assert tunnel.proxy_url == "socks5://127.0.0.1:12345"


def test_condense_output_keeps_both_ends() -> None:
    assert condense_output("short") == "short"
    # A rejected command line prints the cause first, then a long usage block.
    usage = "Error: missing port in address\nUsage:\n" + "  --flag string\n" * 400
    usage = usage.strip()
    condensed = condense_output(usage)
    assert len(condensed) == ERROR_OUTPUT_CHARS
    assert condensed.startswith("Error: missing port in address")
    # A client that fails after starting prints the cause last.
    assert condensed.endswith("--flag string")


@pytest.mark.asyncio
async def test_entry_ip_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    async def inline_to_thread(function, /, *args, **kwargs):  # type: ignore[no-untyped-def]
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", inline_to_thread)
    process = FakeProcess()
    tunnel = Tunnel(process, 12345, 0.01)  # type: ignore[arg-type]
    assert await tunnel.entry_ip("vless://id@192.0.2.20:443") == "192.0.2.20"
    monkeypatch.setattr("vpnprobe.xray._process_tree_remote_ip", lambda _pid, _port: "203.0.113.8")
    assert await tunnel.entry_ip("vless://id@example.com:443") == "203.0.113.8"


def test_process_tree_remote_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = SimpleNamespace(raddr=SimpleNamespace(ip="203.0.113.9", port=443))

    class Process:
        def children(self, *, recursive: bool) -> tuple[Process, ...]:
            assert recursive
            return ()

        def net_connections(self, *, kind: str) -> tuple[object, ...]:
            assert kind == "inet"
            return (connection,)

    monkeypatch.setattr("vpnprobe.xray.psutil.Process", lambda _pid: Process())
    assert _process_tree_remote_ip(1, 443) == "203.0.113.9"
    assert _process_tree_remote_ip(1, 8443) is None

    class DeniedProcess(Process):
        def net_connections(self, *, kind: str) -> tuple[object, ...]:
            raise __import__("psutil").AccessDenied()

    monkeypatch.setattr("vpnprobe.xray.psutil.Process", lambda _pid: DeniedProcess())
    assert _process_tree_remote_ip(1, 443) is None

    def missing(_pid: int) -> object:
        raise __import__("psutil").NoSuchProcess(1)

    monkeypatch.setattr("vpnprobe.xray.psutil.Process", missing)
    assert _process_tree_remote_ip(1, 443) is None


@pytest.mark.asyncio
async def test_start_errors_and_forced_stop(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def cannot_start(*_args: object, **_kwargs: object) -> FakeProcess:
        raise OSError("missing")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", cannot_start)
    monkeypatch.setattr("vpnprobe.xray._random_free_port", lambda: 23456)
    with pytest.raises(TunnelError, match="Cannot start"):
        await start_tunnel("vless://id@example.com:443", settings)

    class BrokenStdin(FakeStdin):
        async def drain(self) -> None:
            raise BrokenPipeError

    broken = FakeProcess()
    broken.stdin = BrokenStdin()

    async def create_broken(*_args: object, **_kwargs: object) -> FakeProcess:
        return broken

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_broken)
    monkeypatch.setattr(os, "killpg", lambda *_args: None)
    monkeypatch.setattr("vpnprobe.processes._process_group_exists", lambda _pid: False)
    with pytest.raises(TunnelError, match="closed stdin"):
        await start_tunnel("vless://id@example.com:443", settings)

    class SlowProcess(FakeProcess):
        def __init__(self) -> None:
            super().__init__()
            self.waits = 0

        async def wait(self) -> int:
            self.waits += 1
            if self.waits == 1:
                await asyncio.sleep(10)
            self.returncode = -9
            return -9

    slow = SlowProcess()
    signals: list[signal.Signals] = []
    monkeypatch.setattr(os, "killpg", lambda _pid, sig: signals.append(sig))
    monkeypatch.setattr("vpnprobe.processes._process_group_exists", lambda _pid: True)
    await Tunnel(slow, 12345, 0.001).stop()  # type: ignore[arg-type]
    assert signals == [signal.SIGTERM, signal.SIGKILL]


@pytest.mark.asyncio
async def test_cancelled_tunnel_start_stops_spawned_process(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = FakeProcess()
    reading = asyncio.Event()
    stopped = False

    async def readline() -> bytes:
        reading.set()
        await asyncio.Event().wait()
        return b""

    process.stdout.readline = readline  # type: ignore[method-assign]

    async def create(*_args: object, **_kwargs: object) -> FakeProcess:
        return process

    async def stop(_process: object, _timeout: float) -> None:
        nonlocal stopped
        stopped = True

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr("vpnprobe.xray._random_free_port", lambda: 23456)
    monkeypatch.setattr("vpnprobe.processes.stop_process_group", stop)
    monkeypatch.setattr("vpnprobe.xray.stop_process_group", stop)
    task = asyncio.create_task(start_tunnel("vless://id@example.com:443", settings))
    await reading.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stopped
