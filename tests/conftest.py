from __future__ import annotations

from dataclasses import replace

import pytest

from vpnprobe.config import Settings


@pytest.fixture
def settings() -> Settings:
    return replace(
        Settings(),
        tunnel_settle_delay=0.001,
        connectivity_check_timeout=0.01,
        connectivity_retry_interval=0.001,
        key_check_timeout=1.0,
        process_stop_timeout=0.01,
        subscription_check_timeout=1.0,
    )
