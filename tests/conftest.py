"""Keep test stores isolated and off /tmp (mirroring muse-mcp conventions)."""
from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from musefriends.store import Store


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    temporary_root = ROOT / ".pytest_cache" / "tmp"
    temporary_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = pytest.MonkeyPatch()
    for name in tuple(os.environ):
        if name.startswith("MUSE_FRIENDS_"):
            env.delenv(name)
    env.setenv("PYTEST_DEBUG_TEMPROOT", str(temporary_root))
    config.add_cleanup(env.undo)


@pytest.fixture(autouse=True)
def isolated_stores(monkeypatch):
    original_init = Store.__init__
    live_dir = (ROOT / "data").resolve()
    stores: list[Store] = []

    def guarded_init(self, state_dir, db_path=None):
        resolved = Path(state_dir).expanduser().resolve()
        if resolved == live_dir or live_dir in resolved.parents:
            raise RuntimeError("tests must not open the live data directory")
        original_init(self, state_dir, db_path=db_path)
        stores.append(self)

    monkeypatch.setattr(Store, "__init__", guarded_init)
    try:
        yield
    finally:
        for store in reversed(stores):
            store.close()
