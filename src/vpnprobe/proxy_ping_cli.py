"""Isolated process runner for the short-lived MTProto ping command."""

from __future__ import annotations

import asyncio
import sys
import time

from vpnprobe.config import ProbeConfig


async def run_proxy_ping(
    url: str,
    settings: ProbeConfig,
    timeout_seconds: float,
    dc: str,
) -> int:
    started = time.perf_counter()
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "vpnprobe.proxy_ping_worker",
        "--library",
        settings.tdjson_library,
        "--timeout",
        str(timeout_seconds),
        "--dc",
        dc,
        url,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        maximum_runtime = timeout_seconds * 2
        async with asyncio.timeout(maximum_runtime + settings.process_stop_timeout):
            stdout, stderr = await process.communicate()
    except TimeoutError:
        process.kill()
        await process.communicate()
        elapsed_ms = (time.perf_counter() - started) * 1000
        print(
            f"ERR {elapsed_ms:.1f} ms TDLib ping helper did not stop",
            file=sys.stderr,
        )
        return 1

    if stdout:
        print(stdout.decode(errors="replace").rstrip())
    if stderr:
        print(stderr.decode(errors="replace").rstrip(), file=sys.stderr)
    if process.returncode in {0, 1}:
        return process.returncode

    elapsed_ms = (time.perf_counter() - started) * 1000
    print(
        f"ERR {elapsed_ms:.1f} ms TDLib ping helper exited with code {process.returncode}",
        file=sys.stderr,
    )
    return 1
