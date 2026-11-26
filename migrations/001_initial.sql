-- Muse Friends daemon store schema.
-- SQLite WAL + synchronous=FULL, owned by muse-friendsd in its 0700 state dir.

CREATE TABLE identity (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    private_key_path  TEXT NOT NULL,
    public_key        TEXT NOT NULL,
    fingerprint       TEXT NOT NULL,
    current_card_json TEXT NOT NULL,
    card_history_json TEXT NOT NULL DEFAULT '[]',
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE pairing_codes (
    id         TEXT PRIMARY KEY,
    code_hash  TEXT NOT NULL,
    state      TEXT NOT NULL DEFAULT 'minted',
    -- minted | requested | consumed | denied | expired | exhausted | invalidated
    attempts   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_pairing_codes_state ON pairing_codes(state);
CREATE INDEX idx_pairing_codes_code_hash ON pairing_codes(code_hash);

CREATE TABLE friend_requests (
    id                    TEXT PRIMARY KEY,
    pairing_code_id       TEXT NOT NULL REFERENCES pairing_codes(id),
    requester_public_key  TEXT NOT NULL,
    requester_fingerprint TEXT NOT NULL,
    requester_card_json   TEXT NOT NULL,
    request_signature     TEXT NOT NULL,
    request_timestamp     INTEGER NOT NULL,
    request_nonce         TEXT NOT NULL,
    state                 TEXT NOT NULL DEFAULT 'pending',
    -- pending | approved | denied
    received_at           TEXT NOT NULL,
    decided_at            TEXT,
    decision_actor        TEXT,
    decision_note         TEXT
);
CREATE INDEX idx_friend_requests_state ON friend_requests(state);
CREATE INDEX idx_friend_requests_pubkey ON friend_requests(requester_public_key);

CREATE TABLE friends (
    id                 TEXT PRIMARY KEY,
    public_key         TEXT NOT NULL UNIQUE,
    fingerprint        TEXT NOT NULL UNIQUE,
    handle             TEXT NOT NULL,
    display_name       TEXT NOT NULL,
    card_json          TEXT NOT NULL,
    tier               TEXT NOT NULL DEFAULT 'acquaintance',
    -- inner | friend | acquaintance
    verified           INTEGER NOT NULL DEFAULT 0,
    discretion_profile TEXT NOT NULL DEFAULT '',
    state              TEXT NOT NULL DEFAULT 'active',
    -- active | suspended | revoked
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE INDEX idx_friends_state ON friends(state);

CREATE TABLE conversations (
    id            TEXT PRIMARY KEY,
    friend_id     TEXT NOT NULL REFERENCES friends(id),
    mcp_thread_id TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'open',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX idx_conversations_friend ON conversations(friend_id);

CREATE TABLE nonces (
    public_key TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    timestamp  INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (public_key, nonce)
);
CREATE INDEX idx_nonces_timestamp ON nonces(timestamp);

-- DB-backed sliding-window rate limiter for pairing endpoints.
CREATE TABLE pair_rate_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT NOT NULL,
    endpoint TEXT NOT NULL
);
CREATE INDEX idx_pair_rate_events_at ON pair_rate_events(at);

CREATE TABLE audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail_json TEXT
);
CREATE INDEX idx_audit_at ON audit(at);
