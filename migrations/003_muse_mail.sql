-- Muse Mail binding.
-- Numbered 003 to preserve ordering past the parked 002_friend_api.sql draft.
-- Applies cleanly on top of schema v1.

-- Bind each approved friend to their Muse Mail address (unique when set,
-- nullable until paired via Muse Mail).
ALTER TABLE friends ADD COLUMN mail_address TEXT;
CREATE UNIQUE INDEX idx_friends_mail_address
    ON friends(mail_address)
    WHERE mail_address IS NOT NULL;

-- Record claimed sender Muse Mail address on mail-initiated friend requests.
ALTER TABLE friend_requests ADD COLUMN requester_mail_address TEXT;

-- Pin signed capability-bundle revision hashes per friend (inbound bundles
-- received from a friend, or outbound bundles shared with a friend).
CREATE TABLE friend_capability_pins (
    id            TEXT PRIMARY KEY,
    friend_id     TEXT NOT NULL REFERENCES friends(id),
    bundle_name   TEXT NOT NULL,
    revision_hash TEXT NOT NULL,
    direction     TEXT NOT NULL DEFAULT 'inbound',
    -- inbound | outbound
    pinned_at     TEXT NOT NULL,
    pinned_by     TEXT NOT NULL DEFAULT 'owner_cli',
    note          TEXT,
    UNIQUE (friend_id, bundle_name, direction)
);
CREATE INDEX idx_friend_capability_pins_friend ON friend_capability_pins(friend_id);
