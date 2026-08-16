from __future__ import annotations

from importlib.metadata import requires
from pathlib import Path


def test_runtime_dependencies_exclude_application_and_database_stacks() -> None:
    dependencies = "\n".join(requires("vpnprobe") or ()).lower()
    for forbidden in ("sqlite", "sqlalchemy", "alembic", "aiogram", "vpnshare"):
        assert forbidden not in dependencies


def test_source_does_not_import_vpnshare_database() -> None:
    source = Path("src/vpnprobe")
    combined = "\n".join(path.read_text(encoding="utf-8") for path in source.glob("*.py"))
    assert "vpnshare.database" not in combined
    assert "sqlalchemy" not in combined.lower()
