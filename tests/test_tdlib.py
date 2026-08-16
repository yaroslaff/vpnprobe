from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import replace
from typing import Any

import pytest

from vpnprobe.errors import ConfigurationError
from vpnprobe.events import NullEventSink
from vpnprobe.models import Outcome
from vpnprobe.tdlib import (
    ProxyDcTest,
    ProxyTestResult,
    TdJson,
    TdlibError,
    check_tdjson_library,
    find_tdjson_library,
    verify_telegram_proxy,
)

PROXY_URL = "tg://proxy?server=proxy.example&port=443&secret=00112233445566778899aabbccddeeff"


class Function:
    def __init__(self, function) -> None:  # type: ignore[no-untyped-def]
        self.function = function
        self.argtypes: list[object] = []
        self.restype: object = None

    def __call__(self, *args: object) -> Any:
        return self.function(*args)


class Library:
    def __init__(
        self,
        response_type: str = "ok",
        failed_dcs: frozenset[int] = frozenset(),
    ) -> None:
        self.responses: deque[bytes] = deque()
        self.closed = False
        self.response_type = response_type
        self.failed_dcs = failed_dcs
        self.requests: list[dict[str, object]] = []
        self.td_create_client_id = Function(lambda: 7)
        self.td_execute = Function(lambda _request: b'{"@type":"ok"}')
        self.td_send = Function(self.send)
        self.td_receive = Function(
            lambda _timeout: self.responses.popleft() if self.responses else None
        )

    def send(self, client_id: object, raw: object) -> None:
        assert client_id == 7
        assert isinstance(raw, bytes)
        request = json.loads(raw)
        if request["@type"] == "close":
            self.closed = True
            return
        self.requests.append(request)
        if request["@type"] == "setTdlibParameters":
            assert request["use_file_database"] is False
            assert request["api_id"] == 1
            self.responses.append(
                json.dumps(
                    {
                        "@type": "ok",
                        "@client_id": 7,
                        "@extra": request["@extra"],
                    }
                ).encode()
            )
            return
        if request["@type"] == "setNetworkType":
            assert request["type"] == {"@type": "networkTypeOther"}
            self.responses.append(
                json.dumps(
                    {
                        "@type": "ok",
                        "@client_id": 7,
                        "@extra": request["@extra"],
                    }
                ).encode()
            )
            return
        assert request["type"]["@type"] == "proxyTypeMtproto"
        assert request["@type"] == "testProxy"
        response_type = "error" if request["dc_id"] in self.failed_dcs else self.response_type
        if self.response_type == "malformed":
            self.responses.append(b"{")
        else:
            response: dict[str, object] = {
                "@type": response_type,
                "@client_id": 7,
                "@extra": request["@extra"],
            }
            if response_type == "error":
                response["message"] = "connection refused"
            self.responses.append(json.dumps(response).encode())


def test_tdjson_ping(monkeypatch: pytest.MonkeyPatch) -> None:
    library = Library()
    monkeypatch.setattr("vpnprobe.tdlib.ctypes.CDLL", lambda _name: library)
    client = TdJson("fake-libtdjson.so")
    assert client.library_name == "fake-libtdjson.so"
    result = client.ping("proxy.example", 443, "00" * 16, 1, (1, 2))
    assert result.successful_dc_ids == (1, 2)
    assert result.failed_dc_ids == ()
    assert result.fastest_seconds >= 0
    assert [request["@type"] for request in library.requests] == [
        "setTdlibParameters",
        "setNetworkType",
        "testProxy",
        "testProxy",
    ]
    assert library.closed


def test_find_tdjson_library(monkeypatch: pytest.MonkeyPatch) -> None:
    assert find_tdjson_library("/opt/libtdjson.so") == "/opt/libtdjson.so"
    monkeypatch.setattr("vpnprobe.tdlib.ctypes.util.find_library", lambda _name: "tdjson.so.1")
    assert find_tdjson_library() == "tdjson.so.1"

    monkeypatch.setattr("vpnprobe.tdlib.ctypes.util.find_library", lambda _name: None)
    monkeypatch.setattr(
        "vpnprobe.tdlib.glob.glob",
        lambda pattern: ["/usr/lib/TDLib/libtdjson.so.1"] if pattern.startswith("/usr/") else [],
    )
    assert find_tdjson_library() == "/usr/lib/TDLib/libtdjson.so.1"

    monkeypatch.setattr("vpnprobe.tdlib.glob.glob", lambda _pattern: [])
    with pytest.raises(ConfigurationError, match="was not found"):
        find_tdjson_library()


def test_tdjson_load_errors(monkeypatch: pytest.MonkeyPatch, settings) -> None:  # type: ignore[no-untyped-def]
    def cannot_load(_name: str) -> None:
        raise OSError("wrong architecture")

    monkeypatch.setattr("vpnprobe.tdlib.ctypes.CDLL", cannot_load)
    with pytest.raises(ConfigurationError, match="Unable to load"):
        TdJson("bad.so")

    monkeypatch.setattr("vpnprobe.tdlib.ctypes.CDLL", lambda _name: object())
    with pytest.raises(ConfigurationError, match="lacks the current"):
        TdJson("old.so")

    library = Library()
    monkeypatch.setattr("vpnprobe.tdlib.ctypes.CDLL", lambda _name: library)
    configured = replace(settings, tdjson_library="fake.so")
    assert check_tdjson_library(configured) == "fake.so"


@pytest.mark.parametrize(
    ("response_type", "message"),
    (
        ("error", "connection refused"),
        ("unexpected", "returned 'unexpected'"),
        ("malformed", "malformed JSON"),
    ),
)
def test_tdjson_rejects_bad_responses(
    monkeypatch: pytest.MonkeyPatch,
    response_type: str,
    message: str,
) -> None:
    library = Library(response_type)
    monkeypatch.setattr("vpnprobe.tdlib.ctypes.CDLL", lambda _name: library)
    with pytest.raises(TdlibError, match=message):
        TdJson("fake.so").ping("proxy.example", 443, "00" * 16, 1, (1,))
    assert library.closed


def test_tdjson_accepts_partial_dc_success(monkeypatch: pytest.MonkeyPatch) -> None:
    library = Library(failed_dcs=frozenset({2}))
    monkeypatch.setattr("vpnprobe.tdlib.ctypes.CDLL", lambda _name: library)
    result = TdJson("fake.so").ping("proxy.example", 443, "00" * 16, 1, (1, 2))
    assert result.successful_dc_ids == (1,)
    assert result.failed_dc_ids == (2,)


def test_tdjson_timeout_and_interruption(monkeypatch: pytest.MonkeyPatch) -> None:
    library = Library()
    monkeypatch.setattr("vpnprobe.tdlib.ctypes.CDLL", lambda _name: library)
    with pytest.raises(TdlibError, match="timed out"):
        TdJson("fake.so").ping("proxy.example", 443, "00" * 16, 0, (1,))

    stopped = threading.Event()
    stopped.set()
    with pytest.raises(TdlibError, match="interrupted"):
        TdJson("fake.so").ping("proxy.example", 443, "00" * 16, 1, (1,), stopped)


@pytest.mark.asyncio
async def test_verify_telegram_proxy(settings, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    async def inline_to_thread(function, /, *args, **kwargs):  # type: ignore[no-untyped-def]
        return function(*args, **kwargs)

    monkeypatch.setattr("vpnprobe.tdlib.asyncio.to_thread", inline_to_thread)
    monkeypatch.setattr(
        "vpnprobe.tdlib._ping_sync",
        lambda *_args: ProxyTestResult(
            (
                ProxyDcTest(1, 0.042),
                ProxyDcTest(2, None, "timeout"),
            )
        ),
    )
    result = await verify_telegram_proxy(
        PROXY_URL,
        settings,
        NullEventSink(),
    )
    assert result.outcome is Outcome.SUCCESS
    assert result.latency_ms == 42.0

    def failed(*_args: object) -> ProxyTestResult:
        raise TdlibError("bad secret")

    monkeypatch.setattr("vpnprobe.tdlib._ping_sync", failed)
    result = await verify_telegram_proxy(
        PROXY_URL,
        settings,
        NullEventSink(),
    )
    assert result.outcome is Outcome.FAILED
    assert "bad secret" in result.detail
