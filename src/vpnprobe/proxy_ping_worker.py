"""Disposable TDLib worker used only by ``vpnprobe ping``."""

from __future__ import annotations

import argparse
import os
import resource
import sys
import time

from vpnprobe.config import telegram_proxy_dc_ids
from vpnprobe.errors import ConfigurationError
from vpnprobe.identity import telegram_proxy
from vpnprobe.tdlib import TdJson, TdlibError


def ping_once(url: str, library: str, timeout: float, dc: str) -> tuple[int, str]:
    started = time.perf_counter()
    try:
        proxy = telegram_proxy(url)
        result = TdJson(library).ping(
            proxy.server,
            proxy.port,
            proxy.secret,
            timeout,
            telegram_proxy_dc_ids(dc),
        )
    except (ConfigurationError, TdlibError, OSError) as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        detail = str(exc).strip() or type(exc).__name__
        return 1, f"ERR {elapsed_ms:.1f} ms {detail}"
    successful = ",".join(map(str, result.successful_dc_ids))
    failed = ",".join(map(str, result.failed_dc_ids)) or "-"
    return (
        0,
        f"OK {result.fastest_seconds * 1000:.1f} ms dc_ok={successful} dc_failed={failed}",
    )


def main() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--library", default="")
    parser.add_argument("--timeout", required=True, type=float)
    parser.add_argument("--dc", required=True)
    parser.add_argument("url")
    args = parser.parse_args()
    code, message = ping_once(args.url, args.library, args.timeout, args.dc)
    print(message, file=sys.stderr if code else sys.stdout, flush=True)
    os._exit(code)


if __name__ == "__main__":
    main()
