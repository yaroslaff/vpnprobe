"""Optional event callback used by library consumers."""

from __future__ import annotations

from typing import Protocol


class EventSink(Protocol):
    def event(self, code: str, message: str, *, terminal: bool = False) -> None: ...


class NullEventSink:
    def event(self, code: str, message: str, *, terminal: bool = False) -> None:
        del code, message, terminal
