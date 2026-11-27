"""Numbered, checksummed SQLite migrations (mirroring muse-mcp).

A migration's checksum is taken over its semantic SQL — comments stripped
and whitespace canonicalized — so a comment-only or formatting edit to an
already-applied migration can never make the store refuse to start (the
2026-11-26 muse-mcp outage: a comment scrub in the repo changed six files'
bytes and the service crash-looped on "migration 1 checksum mismatch").
A change to what the SQL actually does still changes the checksum and
still fails closed. Databases recorded under the pre-semantic raw-byte
scheme are re-baselined on first open, provided the file is byte-identical
to what was applied.
"""
from __future__ import annotations

import hashlib
import pathlib
import sqlite3

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[2] / "migrations"


def _semantic_sql(sql: str) -> str:
    """The SQL that does the work: comments removed, whitespace canonical.

    String literals and quoted identifiers are copied byte-for-byte
    (a ``--`` or ``/*`` inside quotes is data, not a comment, and spaces
    inside a literal are significant). Outside them, ``--`` line comments
    and ``/* */`` block comments are dropped and every whitespace run
    collapses to a single space; a comment also acts as a token separator,
    so ``a/**/b`` normalizes to ``a b``, never ``ab``.
    """
    out: list[str] = []
    pending_space = False

    def emit(text: str) -> None:
        nonlocal pending_space
        if pending_space and out:
            out.append(" ")
        pending_space = False
        out.append(text)

    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if ch in "'\"":
            j = i + 1
            while j < n:
                if sql[j] == ch:
                    if j + 1 < n and sql[j + 1] == ch:
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            emit(sql[i:j])
            i = j
        elif ch == "-" and nxt == "-":
            while i < n and sql[i] != "\n":
                i += 1
            pending_space = True
        elif ch == "/" and nxt == "*":
            i += 2
            while i + 1 < n and not (sql[i] == "*" and sql[i + 1] == "/"):
                i += 1
            i = min(i + 2, n)
            pending_space = True
        elif ch.isspace():
            pending_space = True
            i += 1
        else:
            emit(ch)
            i += 1
    return "".join(out)


def _checksum(sql: str) -> str:
    """Semantic checksum: the identity a migration is recorded under."""
    return hashlib.sha256(_semantic_sql(sql).encode("utf-8")).hexdigest()


def _legacy_checksum(sql: str) -> str:
    """Pre-semantic checksum (raw file bytes), kept only so databases
    recorded under the old scheme can be recognized and re-baselined."""
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def migration_files(*, include_parked: bool = False) -> list[tuple[int, pathlib.Path, str]]:
    out = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        sql = path.read_text(encoding="utf-8")
        if not include_parked and sql.lstrip().startswith("-- PARKED"):
            continue
        version = int(path.name.split("_", 1)[0])
        out.append((version, path, _checksum(sql)))
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
            if applied[version] == checksum:
                continue
            if applied[version] == _legacy_checksum(path.read_text(encoding="utf-8")):
                # Recorded under the pre-semantic raw-byte scheme and the
                # file is byte-identical to what was applied: only the
                # checksum scheme changed. Re-baseline the stored checksum
                # to the semantic one and carry on.
                db.execute(
                    "UPDATE schema_migrations SET checksum = ? WHERE version = ?",
                    (checksum, version),
                )
                db.commit()
                continue
            raise RuntimeError(f"migration {version} checksum mismatch")
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
