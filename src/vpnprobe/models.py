"""Persistence-independent probe result types."""

from __future__ import annotations

import enum


class Outcome(enum.StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    INTERRUPTED = "interrupted"
