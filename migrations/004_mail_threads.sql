-- Muse Mail <-> local muse-mcp thread mirroring.
-- Numbered 004 to preserve ordering past parked 002_friend_api.sql and 003_muse_mail.sql.

CREATE TABLE mail_thread_links (
    id             TEXT PRIMARY KEY,
    friend_id      TEXT NOT NULL REFERENCES friends(id),
    mail_thread_id TEXT NOT NULL UNIQUE,
    mcp_thread_id  TEXT NOT NULL,
    thread_class   TEXT NOT NULL DEFAULT 'channel',
    -- channel (standing per-relationship) | task (discrete job with approval semantics)
    subject        TEXT NOT NULL DEFAULT '',
    state          TEXT NOT NULL DEFAULT 'active',
    -- active | closed
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX idx_mail_thread_links_friend ON mail_thread_links(friend_id);
CREATE INDEX idx_mail_thread_links_mcp ON mail_thread_links(mcp_thread_id);
