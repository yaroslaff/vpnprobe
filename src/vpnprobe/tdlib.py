"""TDLib JSON binding and MTProto proxy verification."""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import ctypes.util
import glob
import json
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

from vpnprobe.config import ProbeConfig, telegram_proxy_dc_ids
from vpnprobe.errors import ConfigurationError
from vpnprobe.events import EventSink
from vpnprobe.identity import identify, telegram_proxy
from vpnprobe.models import Outcome
from vpnprobe.verification import VerificationResult


class TdlibError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ProxyDcTest:
    dc_id: int
    seconds: float | None
    error: str = ""


@dataclass(frozen=True, slots=True)
class ProxyTestResult:
    tests: tuple[ProxyDcTest, ...]

    @property
    def successful_dc_ids(self) -> tuple[int, ...]:
        return tuple(test.dc_id for test in self.tests if test.seconds is not None)

    @property
    def failed_dc_ids(self) -> tuple[int, ...]:
        return tuple(test.dc_id for test in self.tests if test.seconds is None)

    @property
    def fastest_seconds(self) -> float:
        successful = [test.seconds for test in self.tests if test.seconds is not None]
        if not successful:
            raise TdlibError("TDLib testProxy returned no successful DC")
        return min(successful)


def find_tdjson_library(configured: str = "") -> str:
    if configured:
        return configured
    discovered = ctypes.util.find_library("tdjson")
    if discovered:
        return discovered
    candidates = sorted(
        {
            *glob.glob("/usr/lib/*/TDLib*/libtdjson.so*"),
            *glob.glob("/usr/local/lib*/libtdjson.so*"),
        }
    )
    if candidates:
        return candidates[-1]
    raise ConfigurationError(
        "TDLib JSON library was not found; install Debian package libtdjson1.8.38 "
        "or set TDJSON_LIBRARY"
    )


class TdJson:
    """Small synchronous wrapper around TDLib's current global JSON interface."""

    def __init__(self, configured_library: str = "") -> None:
        self.library_name = find_tdjson_library(configured_library)
        try:
            self._library: Any = ctypes.CDLL(self.library_name)
        except OSError as exc:
            raise ConfigurationError(
                f"Unable to load TDLib JSON library {self.library_name}: {exc}"
            ) from exc
        try:
            self._create = self._library.td_create_client_id
            self._send = self._library.td_send
            self._receive = self._library.td_receive
            self._execute = self._library.td_execute
        except AttributeError as exc:
            raise ConfigurationError(
                f"TDLib JSON library {self.library_name} lacks the current JSON interface"
            ) from exc
        self._create.argtypes = []
        self._create.restype = ctypes.c_int
        self._send.argtypes = [ctypes.c_int, ctypes.c_char_p]
        self._send.restype = None
        self._receive.argtypes = [ctypes.c_double]
        self._receive.restype = ctypes.c_char_p
        self._execute.argtypes = [ctypes.c_char_p]
        self._execute.restype = ctypes.c_char_p
        self._execute(
            json.dumps({"@type": "setLogVerbosityLevel", "new_verbosity_level": 0}).encode()
        )

    def ping(
        self,
        server: str,
        port: int,
        secret: str,
        timeout: float,
        dc_ids: tuple[int, ...],
        stop_requested: threading.Event | None = None,
    ) -> ProxyTestResult:
        with tempfile.TemporaryDirectory(prefix="vpnprobe-tdlib-") as data_directory:
            client_id = int(self._create())
            deadline = time.monotonic() + timeout
            try:
                parameters_response = self._request(
                    client_id,
                    {
                        "@type": "setTdlibParameters",
                        "use_test_dc": False,
                        "database_directory": data_directory,
                        "files_directory": data_directory,
                        "database_encryption_key": "",
                        "use_file_database": False,
                        "use_chat_info_database": False,
                        "use_message_database": False,
                        "use_secret_chats": False,
                        # This disposable client never logs in or accesses an account.
                        "api_id": 1,
                        "api_hash": "0" * 32,
                        "system_language_code": "en",
                        "device_model": "vpnprobe",
                        "system_version": "",
                        "application_version": "proxy-ping",
                    },
                    "setTdlibParameters",
                    deadline,
                    timeout,
                    stop_requested,
                )
                if parameters_response.get("@type") != "ok":
                    raise TdlibError(
                        f"TDLib setTdlibParameters returned {parameters_response.get('@type')!r}"
                    )
                network_response = self._request(
                    client_id,
                    {
                        "@type": "setNetworkType",
                        "type": {"@type": "networkTypeOther"},
                    },
                    "setNetworkType",
                    deadline,
                    timeout,
                    stop_requested,
                )
                if network_response.get("@type") != "ok":
                    raise TdlibError(
                        f"TDLib setNetworkType returned {network_response.get('@type')!r}"
                    )
                pending: dict[str, tuple[int, float]] = {}
                for dc_id in dc_ids:
                    extra = uuid.uuid4().hex
                    pending[extra] = (dc_id, time.monotonic())
                    request = {
                        "@type": "testProxy",
                        "server": server,
                        "port": port,
                        "type": {
                            "@type": "proxyTypeMtproto",
                            "secret": secret,
                        },
                        "dc_id": dc_id,
                        "timeout": timeout,
                        "@extra": extra,
                    }
                    self._send(
                        client_id,
                        json.dumps(request, separators=(",", ":")).encode(),
                    )
                tests: dict[int, ProxyDcTest] = {}
                test_deadline = time.monotonic() + timeout
                while pending:
                    if stop_requested is not None and stop_requested.is_set():
                        raise TdlibError("TDLib testProxy was interrupted")
                    remaining = test_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    raw = self._receive(min(remaining, 1.0))
                    if not raw:
                        continue
                    try:
                        response = json.loads(raw.decode())
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise TdlibError("TDLib returned malformed JSON") from exc
                    if not isinstance(response, dict):
                        continue
                    if response.get("@client_id") != client_id:
                        continue
                    response_extra = response.get("@extra")
                    if not isinstance(response_extra, str) or response_extra not in pending:
                        continue
                    dc_id, started = pending.pop(response_extra)
                    response_type = response.get("@type")
                    if response_type == "ok":
                        tests[dc_id] = ProxyDcTest(
                            dc_id,
                            time.monotonic() - started,
                        )
                    elif response_type == "error":
                        message = response.get("message")
                        detail = (
                            message if isinstance(message, str) and message else "unknown error"
                        )
                        tests[dc_id] = ProxyDcTest(dc_id, None, detail)
                    else:
                        tests[dc_id] = ProxyDcTest(
                            dc_id,
                            None,
                            f"TDLib returned {response_type!r}",
                        )
                for dc_id, _started in pending.values():
                    tests[dc_id] = ProxyDcTest(
                        dc_id,
                        None,
                        f"timed out after {timeout:g}s",
                    )
                result = ProxyTestResult(tuple(tests[dc_id] for dc_id in dc_ids))
                if not result.successful_dc_ids:
                    failures = "; ".join(f"dc={test.dc_id}: {test.error}" for test in result.tests)
                    raise TdlibError(f"TDLib testProxy failed: {failures}")
                return result
            finally:
                self._send(client_id, b'{"@type":"close"}')

    def _request(
        self,
        client_id: int,
        request: dict[str, object],
        operation: str,
        deadline: float,
        timeout: float,
        stop_requested: threading.Event | None,
    ) -> dict[str, object]:
        extra = uuid.uuid4().hex
        request["@extra"] = extra
        self._send(client_id, json.dumps(request, separators=(",", ":")).encode())
        while True:
            if stop_requested is not None and stop_requested.is_set():
                raise TdlibError(f"TDLib {operation} was interrupted")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TdlibError(f"TDLib {operation} timed out after {timeout:g}s")
            raw = self._receive(min(remaining, 1.0))
            if not raw:
                continue
            try:
                response = json.loads(raw.decode())
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TdlibError("TDLib returned malformed JSON") from exc
            if not isinstance(response, dict):
                continue
            if response.get("@client_id") != client_id or response.get("@extra") != extra:
                continue
            if response.get("@type") == "error":
                message = response.get("message")
                detail = message if isinstance(message, str) and message else "unknown error"
                raise TdlibError(f"TDLib {operation} failed: {detail}")
            return response


def check_tdjson_library(settings: ProbeConfig) -> str:
    return TdJson(settings.tdjson_library).library_name


def _ping_sync(
    settings: ProbeConfig,
    server: str,
    port: int,
    secret: str,
    stop_requested: threading.Event,
    timeout: float | None = None,
    dc: str | None = None,
) -> ProxyTestResult:
    return TdJson(settings.tdjson_library).ping(
        server,
        port,
        secret,
        settings.telegram_proxy_check_timeout if timeout is None else timeout,
        telegram_proxy_dc_ids(settings.telegram_proxy_dc if dc is None else dc),
        stop_requested,
    )


async def verify_telegram_proxy(
    proxy_url: str,
    settings: ProbeConfig,
    logger: EventSink,
) -> VerificationResult:
    identity = identify(proxy_url)
    logger.event("VERIFICATION_START", f"key_id={identity.short_id} type=mtproto")
    try:
        test_result = await ping_telegram_proxy(
            proxy_url,
            settings,
            settings.telegram_proxy_check_timeout,
        )
    except (ConfigurationError, TdlibError, OSError) as exc:
        logger.event("ERROR_VERIFICATION", f"key_id={identity.short_id} detail={exc}")
        return VerificationResult(Outcome.FAILED, str(exc), identity)
    latency_ms = round(test_result.fastest_seconds * 1000, 1)
    successful_dcs = ",".join(map(str, test_result.successful_dc_ids))
    failed_dcs = ",".join(map(str, test_result.failed_dc_ids)) or "-"
    logger.event(
        "VERIFICATION_OK",
        f"key_id={identity.short_id} type=mtproto latency_ms={latency_ms:.1f} "
        f"dc_ok={successful_dcs} dc_failed={failed_dcs}",
    )
    return VerificationResult(
        Outcome.SUCCESS,
        f"MTProto proxy verification succeeded for DC {successful_dcs}",
        identity,
        latency_ms=latency_ms,
    )


async def ping_telegram_proxy(
    proxy_url: str,
    settings: ProbeConfig,
    timeout_seconds: float,
) -> ProxyTestResult:
    proxy = telegram_proxy(proxy_url)
    stop_requested = threading.Event()
    work = asyncio.create_task(
        asyncio.to_thread(
            _ping_sync,
            settings,
            proxy.server,
            proxy.port,
            proxy.secret,
            stop_requested,
            timeout_seconds,
        )
    )
    try:
        result = await asyncio.shield(work)
    except asyncio.CancelledError:
        stop_requested.set()
        with contextlib.suppress(Exception):
            await work
        raise
    return result
