"""SQLite store layer: 0700 state dir, WAL + synchronous=FULL,
single-writer transaction discipline, audit trail."""
from __future__ import annotations

import contextlib
import json
import os
import pathlib
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

from . import migrate


def now_iso(now: datetime | None = None) -> str:
    dt = now if now is not None else datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def new_id() -> str:
    """UUIDv7 (RFC 9562): time-ordered identifiers."""
    ms = int(time.time() * 1000)
    rand = bytearray(uuid.uuid4().bytes)
    raw = bytearray(16)
    raw[0:6] = ms.to_bytes(6, "big")
    raw[6] = 0x70 | (rand[6] & 0x0F)
    raw[7] = rand[7]
    raw[8] = 0x80 | (rand[8] & 0x3F)
    raw[9:16] = rand[9:16]
    return str(uuid.UUID(bytes=bytes(raw)))


class Store:
    def __init__(
        self,
        state_dir: str | pathlib.Path,
        db_path: str | pathlib.Path | None = None,
    ):
        self.state_dir = pathlib.Path(state_dir).expanduser().resolve()
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)

        self.db_path = (
            pathlib.Path(db_path).expanduser().resolve()
            if db_path is not None
            else self.state_dir / "friends.db"
        )
        self.db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._tx_depth = 0

        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.isolation_level = None
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA secure_delete=ON")
        self.conn = conn
        self.schema_version = migrate.apply_migrations(conn)

    def close(self) -> None:
        self.conn.close()

    def tx(self) -> sqlite3.Connection:
        return self.conn

    @contextlib.contextmanager
    def transaction(self):
        with self._lock:
            depth = self._tx_depth
            if depth > 0:
                sp = f"sp_{depth}"
                self.conn.execute(f"SAVEPOINT {sp}")
                self._tx_depth = depth + 1
                try:
                    yield self.conn
                    self.conn.execute(f"RELEASE {sp}")
                except Exception:
                    self.conn.execute(f"ROLLBACK TO {sp}")
                    self.conn.execute(f"RELEASE {sp}")
                    raise
                finally:
                    self._tx_depth = depth
            else:
                self.conn.execute("BEGIN IMMEDIATE")
                self._tx_depth = 1
                try:
                    yield self.conn
                    self.conn.execute("COMMIT")
                except Exception:
                    self.conn.execute("ROLLBACK")
                    raise
                finally:
                    self._tx_depth = 0

    def audit(
        self,
        actor: str,
        action: str,
        detail: dict | None = None,
        now: datetime | None = None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO audit (at, actor, action, detail_json) VALUES (?, ?, ?, ?)",
            (
                now_iso(now),
                actor,
                action,
                json.dumps(detail, sort_keys=True, separators=(",", ":"))
                if detail is not None
                else None,
            ),
        )
