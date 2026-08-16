"""Cancellation-safe lifecycle helpers for disposable child processes."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def _stop_process_group(
    process: asyncio.subprocess.Process,
    timeout_seconds: float,
) -> None:
    process_group_id = process.pid
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, timeout_seconds)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process_group_id, signal.SIGTERM)

    if process.returncode is None:
        remaining = max(0.0, deadline - loop.time())
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(process.wait(), timeout=remaining)
    else:
        await process.wait()

    while _process_group_exists(process_group_id):
        remaining = deadline - loop.time()
        if remaining <= 0:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process_group_id, signal.SIGKILL)
            break
        await asyncio.sleep(min(0.05, remaining))

    if process.returncode is None:
        await process.wait()


async def stop_process_group(
    process: asyncio.subprocess.Process,
    timeout_seconds: float,
) -> None:
    """Stop a process group fully even if the awaiting task is cancelled."""
    cleanup = asyncio.create_task(_stop_process_group(process, timeout_seconds))
    cancellation: asyncio.CancelledError | None = None
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError as exc:
            cancellation = exc
    cleanup.result()
    if cancellation is not None:
        raise cancellation
