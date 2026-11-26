-- PARKED (2026-11-26): Superseded by (Muse Mail re-scope).
-- Kept in place for reference only; skipped by default in musefriends.migrate.

-- Phase 2-5 schema additions: idempotency, quotas, callbacks, abuse tracking,
-- key rotation statements, and coarse presence.

ALTER TABLE identity ADD COLUMN rotation_statement_json TEXT;

ALTER TABLE friend_requests ADD COLUMN callback_url TEXT;

ALTER TABLE friends ADD COLUMN callback_url TEXT;
ALTER TABLE friends ADD COLUMN max_open_conversations INTEGER NOT NULL DEFAULT 5;
ALTER TABLE friends ADD COLUMN max_asks_per_day INTEGER NOT NULL DEFAULT 50;

ALTER TABLE conversations ADD COLUMN subject TEXT NOT NULL DEFAULT '';
ALTER TABLE conversations ADD COLUMN callback_url TEXT;
ALTER TABLE conversations ADD COLUMN parked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE conversations ADD COLUMN last_activity_at TEXT;

CREATE TABLE idempotency_keys (
    friend_id       TEXT NOT NULL REFERENCES friends(id),
    endpoint        TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_hash    TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    response_json   TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (friend_id, endpoint, idempotency_key)
);

CREATE TABLE ask_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    friend_id TEXT NOT NULL REFERENCES friends(id),
    at        TEXT NOT NULL,
    kind      TEXT NOT NULL
);
CREATE INDEX idx_ask_events_friend_at ON ask_events(friend_id, at);

CREATE TABLE auth_failures (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key TEXT NOT NULL,
    at         TEXT NOT NULL,
    reason     TEXT NOT NULL
);
CREATE INDEX idx_auth_failures_key_at ON auth_failures(public_key, at);

CREATE TABLE presence (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    status         TEXT NOT NULL DEFAULT 'awake',
    last_active_at TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
