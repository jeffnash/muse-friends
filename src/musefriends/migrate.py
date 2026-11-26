"""Numbered, checksummed SQLite migrations (mirroring muse-mcp)."""
from __future__ import annotations

import hashlib
import pathlib
import sqlite3

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[2] / "migrations"


def migration_files(*, include_parked: bool = False) -> list[tuple[int, pathlib.Path, str]]:
    out = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        sql = path.read_text(encoding="utf-8")
        if not include_parked and sql.lstrip().startswith("-- PARKED"):
            continue
        version = int(path.name.split("_", 1)[0])
        out.append((version, path, hashlib.sha256(sql.encode("utf-8")).hexdigest()))
    return out


def apply_migrations(db: sqlite3.Connection) -> int:
    """Apply pending migrations transactionally. Returns current schema version."""
    files = migration_files()
    known_max = max(v for v, _, _ in files) if files else 0
    db.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    applied = {
        row[0]: row[1]
        for row in db.execute("SELECT version, checksum FROM schema_migrations")
    }
    if applied and max(applied) > known_max:
        raise RuntimeError(
            f"database schema {max(applied)} is newer than this binary ({known_max}); refusing to open"
        )
    for version, path, checksum in files:
        if version in applied:
            if applied[version] != checksum:
                raise RuntimeError(f"migration {version} checksum mismatch")
            continue
        sql = path.read_text(encoding="utf-8")
        try:
            db.executescript("BEGIN;\n" + sql)
            db.execute(
                "INSERT INTO schema_migrations (version, checksum, applied_at)"
                " VALUES (?, ?, datetime('now'))",
                (version, checksum),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
    return known_max
