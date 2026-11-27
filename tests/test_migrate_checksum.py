"""Semantic migration checksums (mirroring the muse-mcp fix).

Regression coverage for the 2026-11-26 muse-mcp outage: a comment scrub in
the repo changed the bytes of already-applied migration files and the
service crash-looped on "migration 1 checksum mismatch" at startup. This
module carried the identical raw-byte checksum, so it gets the identical
fix: a migration's checksum covers its semantic SQL only — comments and
whitespace are not identity — while a change to what the SQL does still
fails closed.
"""

import hashlib
import sqlite3

import pytest

from musefriends import migrate


TOY_001 = """-- Toy migration one.
CREATE TABLE toy (
    id INTEGER PRIMARY KEY,
    note TEXT NOT NULL DEFAULT 'a--b'  -- literal holding a comment marker
);
"""

TOY_002 = """CREATE INDEX idx_toy_id ON toy (id); /* block comment */
"""


def _write_migrations(tmp_path, one=TOY_001, two=TOY_002):
    d = tmp_path / "migrations"
    d.mkdir(exist_ok=True)
    (d / "001_toy.sql").write_text(one)
    (d / "002_toy.sql").write_text(two)
    return d


# --- _semantic_sql -------------------------------------------------------

def test_semantic_sql_strips_comments_and_canonicalizes_whitespace():
    sql = "CREATE  TABLE t (\n  a INTEGER, -- the a column\n  b TEXT /* why */\n);"
    assert migrate._semantic_sql(sql) == "CREATE TABLE t ( a INTEGER, b TEXT );"


def test_semantic_sql_comment_is_a_token_separator():
    assert migrate._semantic_sql("a/**/b") == "a b"
    assert migrate._semantic_sql("a-- x\nb") == "a b"


def test_semantic_sql_preserves_string_literals_byte_for_byte():
    sql = "SELECT 'a--b', 'it''s /* not a comment */', 'x  y'"
    assert migrate._semantic_sql(sql) == sql


# --- checksum identity ---------------------------------------------------

def test_comment_only_edit_keeps_checksum():
    edited = TOY_001.replace("Toy migration one", "A different comment entirely")
    edited = edited.replace("-- literal holding a comment marker", "-- scrubbed")
    edited += "\n-- An extra comment appended by a later cleanup.\n"
    assert migrate._checksum(edited) == migrate._checksum(TOY_001)


def test_semantic_edit_changes_checksum():
    assert migrate._checksum(TOY_001.replace("'a--b'", "'a--c'")) != migrate._checksum(TOY_001)
    assert migrate._checksum(TOY_001.replace("INTEGER", "TEXT")) != migrate._checksum(TOY_001)


def test_real_migration_checksum_survives_a_comment_scrub():
    real = migrate.MIGRATIONS_DIR / "001_initial.sql"
    original = real.read_text(encoding="utf-8")
    scrubbed = original + "\n-- scrubbed comment, added after the fact\n"
    assert migrate._checksum(scrubbed) == migrate._checksum(original)


def test_parked_migration_still_skipped():
    versions = [v for v, _, _ in migrate.migration_files()]
    assert 2 not in versions
    versions_with_parked = [v for v, _, _ in migrate.migration_files(include_parked=True)]
    assert 2 in versions_with_parked


# --- apply_migrations behaviour ------------------------------------------

def test_apply_survives_comment_edit_and_rejects_semantic_edit(tmp_path, monkeypatch):
    d = _write_migrations(tmp_path)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", d)
    conn = sqlite3.connect(tmp_path / "test.db")
    assert migrate.apply_migrations(conn) == 2

    # Comment-only edit to an applied migration: startup proceeds.
    (d / "001_toy.sql").write_text(TOY_001.replace("Toy migration one", "Reworded"))
    assert migrate.apply_migrations(conn) == 2

    # A change to what the SQL does: still fails closed.
    (d / "001_toy.sql").write_text(TOY_001.replace("INTEGER PRIMARY KEY", "TEXT"))
    with pytest.raises(RuntimeError, match="migration 1 checksum mismatch"):
        migrate.apply_migrations(conn)


def test_legacy_raw_checksums_rebaseline_then_survive_comment_edits(tmp_path, monkeypatch):
    """A database recorded under the pre-semantic raw-byte scheme opens
    under the new scheme, its stored checksums are re-baselined, and a
    later comment scrub is harmless."""
    d = _write_migrations(tmp_path)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", d)
    conn = sqlite3.connect(tmp_path / "test.db")
    conn.execute(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, "
        "checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    for name, sql in (("001_toy.sql", TOY_001), ("002_toy.sql", TOY_002)):
        conn.executescript("BEGIN;\n" + sql)
        legacy = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        version = int(name.split("_", 1)[0])
        conn.execute(
            "INSERT INTO schema_migrations VALUES (?, ?, '2026-11-26T00:00:00Z')",
            (version, legacy),
        )
        conn.commit()

    assert migrate.apply_migrations(conn) == 2
    stored = dict(conn.execute("SELECT version, checksum FROM schema_migrations"))
    assert stored[1] == migrate._checksum(TOY_001)
    assert stored[2] == migrate._checksum(TOY_002)

    (d / "001_toy.sql").write_text(TOY_001 + "\n-- post-incident scrub\n")
    assert migrate.apply_migrations(conn) == 2
