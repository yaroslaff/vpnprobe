from __future__ import annotations

import signal

import pytest

from vpnprobe.processes import stop_process_group


class CompletedProcess:
    pid = 23456
    returncode: int | None = 0

    async def wait(self) -> int:
        return 0


@pytest.mark.asyncio
async def test_completed_leader_still_terminates_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signals: list[tuple[int, signal.Signals]] = []
    monkeypatch.setattr(
        "vpnprobe.processes.os.killpg",
        lambda pid, sent_signal: signals.append((pid, sent_signal)),
    )
    monkeypatch.setattr("vpnprobe.processes._process_group_exists", lambda _pid: False)
    await stop_process_group(CompletedProcess(), 0.01)  # type: ignore[arg-type]
    assert signals == [(23456, signal.SIGTERM)]


@pytest.mark.asyncio
async def test_process_cleanup_finishes_during_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    process = CompletedProcess()
    process.returncode = None
    waiting = asyncio.Event()
    release = asyncio.Event()
    signals: list[signal.Signals] = []

    async def wait() -> int:
        waiting.set()
        await release.wait()
        process.returncode = -15
        return -15

    process.wait = wait  # type: ignore[method-assign]
    monkeypatch.setattr(
        "vpnprobe.processes.os.killpg", lambda _pid, sent_signal: signals.append(sent_signal)
    )
    monkeypatch.setattr("vpnprobe.processes._process_group_exists", lambda _pid: False)
    task = asyncio.create_task(stop_process_group(process, 1))  # type: ignore[arg-type]
    await waiting.wait()
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert signals == [signal.SIGTERM]
    assert process.returncode == -15
