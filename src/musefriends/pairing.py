"""Pairing-code flow and local owner approval.

Invariants:
- Pairing codes are 8 symbols from a 32-char unambiguous alphabet (XXXX-XXXX),
  stored as SHA-256 hashes only, single-use, 15-minute TTL, 5-attempt cap.
- At most one outstanding minted code at a time; minting invalidates prior
  unrequested codes.
- Unknown, expired, and exhausted codes return a single uniform error
  (no oracle).
- Pairing endpoints are rate-limited via SQLite (pair_rate_events).
- A valid pairing code never grants API access by itself; owner approval is
  the sole gate that creates a friend record.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone

from .errors import FriendsError
from .identity import (
    IdentityManager,
    canonical_json_bytes,
    key_fingerprint,
    verify_card,
    verify_http_signature,
)
from .store import Store, new_id, now_iso

# 32 unambiguous symbols (no 0, I, L, O).
CODE_ALPHABET = "123456789ABCDEFGHJKMNPQRSTUVWXYZ"
CODE_TTL_S = 900 # 15 minutes
MAX_CODE_ATTEMPTS = 5 # per code
TIMESTAMP_WINDOW_S = 120 # ±120s replay window
KNOWN_TIERS = ("inner", "friend", "acquaintance")
DEFAULT_TIER = "acquaintance"


def _uniform_pairing_error() -> FriendsError:
    return FriendsError("pairing_unavailable", "pairing unavailable", status_code=400)


def normalize_code(code: str) -> str:
    return re.sub(r"[\s-]+", "", code).upper()


def hash_code(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def generate_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def _utc_now(now: datetime | None = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class PairingManager:
    RATE_WINDOW_S = 60

    def __init__(
        self,
        store: Store,
        identity: IdentityManager,
        *,
        rate_limit_per_min: int = 60,
    ):
        self.store = store
        self.identity = identity
        self.rate_limit_per_min = rate_limit_per_min

    def _rate_limit(self, endpoint: str, *, now: datetime) -> None:
        cutoff = now_iso(now - timedelta(seconds=self.RATE_WINDOW_S))
        prune = now_iso(now - timedelta(seconds=2 * self.RATE_WINDOW_S))
        with self.store.transaction():
            self.store.tx().execute(
                "DELETE FROM pair_rate_events WHERE at < ?", (prune,)
            )
            self.store.tx().execute(
                "INSERT INTO pair_rate_events (at, endpoint) VALUES (?, ?)",
                (now_iso(now), endpoint),
            )
            count = self.store.tx().execute(
                "SELECT COUNT(*) AS n FROM pair_rate_events WHERE endpoint = ? AND at >= ?",
                (endpoint, cutoff),
            ).fetchone()["n"]
            if count > self.rate_limit_per_min:
                raise FriendsError(
                    "rate_limited",
                    "pairing endpoint rate limited; retry shortly",
                    status_code=429,
                )

    def _expire_if_due(self, row, *, now: datetime) -> str:
        """Lazily expire a minted code if past expires_at. Caller holds tx."""
        if row["state"] == "minted" and now > _parse_iso(row["expires_at"]):
            self.store.tx().execute(
                "UPDATE pairing_codes SET state='expired', updated_at=? WHERE id=?",
                (now_iso(now), row["id"]),
            )
            self.store.audit(
                "pairing", "pairing_code_expired", {"code_id": row["id"]}, now=now
            )
            return "expired"
        return row["state"]

    # -- owner: mint ------------------------------------------------------
    def mint_code(self, *, now: datetime | None = None) -> dict:
        ts = _utc_now(now)
        card = self.identity.current_card()
        code = generate_code()
        code_id = new_id()
        created = now_iso(ts)
        expires = now_iso(ts + timedelta(seconds=CODE_TTL_S))
        code_digest = hash_code(normalize_code(code))

        with self.store.transaction():
            # At most one outstanding minted code per owner.
            prior = self.store.tx().execute(
                "SELECT id FROM pairing_codes WHERE state='minted'"
            ).fetchall()
            for row in prior:
                self.store.tx().execute(
                    "UPDATE pairing_codes SET state='invalidated', updated_at=? WHERE id=?",
                    (created, row["id"]),
                )
                self.store.audit(
                    "owner",
                    "pairing_code_invalidated",
                    {"code_id": row["id"], "superseded_by": code_id},
                    now=ts,
                )
            self.store.tx().execute(
                "INSERT INTO pairing_codes (id, code_hash, state, attempts, created_at, expires_at, updated_at)"
                " VALUES (?, ?, 'minted', 0, ?, ?, ?)",
                (code_id, code_digest, created, expires, created),
            )
            self.store.audit(
                "owner", "pairing_code_minted", {"code_id": code_id}, now=ts
            )

        card_url = f"{card['friend_api']}/card"
        return {
            "code_id": code_id,
            "code": code,
            "expires_at": expires,
            "card_url": card_url,
            "share_text": f"Add my Muse: {card_url} code {code}",
        }

    # -- public: submit friend request ------------------------------------
    def submit_request(
        self,
        *,
        code: str,
        requester_card: dict,
        method: str,
        path: str,
        body: bytes,
        headers: dict[str, str],
        now: datetime | None = None,
    ) -> dict:
        ts = _utc_now(now)
        self._rate_limit("request", now=ts)

        # Ensure daemon identity exists before accepting pairing traffic.
        own_card = self.identity.current_card()

        # Verify requester's friend card and HTTP request signature first.
        verified_card = verify_card(requester_card, require_signature=True)
        requester_pub = verified_card["public_key"]
        if requester_pub == own_card["public_key"]:
            raise FriendsError("invalid_request", "cannot pair with self", status_code=400)

        norm_headers = {k.lower(): v for k, v in headers.items()}
        hdr_key = norm_headers.get("x-muse-friend-key", "")
        hdr_ts_raw = norm_headers.get("x-muse-friend-timestamp", "")
        hdr_nonce = norm_headers.get("x-muse-friend-nonce", "")
        hdr_sig = norm_headers.get("x-muse-friend-signature", "")

        if hdr_key != requester_pub:
            raise FriendsError("unauthorized", "unauthorized", status_code=401)
        try:
            req_ts = int(hdr_ts_raw)
        except (TypeError, ValueError) as exc:
            raise FriendsError("unauthorized", "unauthorized", status_code=401) from exc
        if abs(int(ts.timestamp()) - req_ts) > TIMESTAMP_WINDOW_S:
            raise FriendsError("unauthorized", "unauthorized", status_code=401)
        if not isinstance(hdr_nonce, str) or not (1 <= len(hdr_nonce) <= 128):
            raise FriendsError("unauthorized", "unauthorized", status_code=401)

        verify_http_signature(
            requester_pub, method, path, body, req_ts, hdr_nonce, hdr_sig
        )

        # Normalize presented pairing code (never logged or stored plaintext).
        normalized = normalize_code(code) if isinstance(code, str) else ""
        presented_hash = (
            hash_code(normalized)
            if len(normalized) == 8 and all(c in CODE_ALPHABET for c in normalized)
            else None
        )

        failure: FriendsError | None = None
        result: dict | None = None
        now_str = now_iso(ts)
        prune_ts = int(ts.timestamp()) - TIMESTAMP_WINDOW_S

        with self.store.transaction():
            # Prune old nonces and reject replay.
            self.store.tx().execute(
                "DELETE FROM nonces WHERE timestamp < ?", (prune_ts,)
            )
            seen = self.store.tx().execute(
                "SELECT 1 FROM nonces WHERE public_key=? AND nonce=?",
                (requester_pub, hdr_nonce),
            ).fetchone()
            if seen is not None:
                failure = FriendsError("unauthorized", "unauthorized", status_code=401)
            else:
                self.store.tx().execute(
                    "INSERT INTO nonces (public_key, nonce, timestamp, created_at)"
                    " VALUES (?, ?, ?, ?)",
                    (requester_pub, hdr_nonce, req_ts, now_str),
                )

                # Look up active minted code matching hash.
                row = None
                if presented_hash is not None:
                    row = self.store.tx().execute(
                        "SELECT * FROM pairing_codes WHERE code_hash=? AND state='minted'",
                        (presented_hash,),
                    ).fetchone()
                if row is not None and self._expire_if_due(row, now=ts) != "minted":
                    row = None

                if row is not None and row["attempts"] < MAX_CODE_ATTEMPTS:
                    req_id = new_id()
                    fp = key_fingerprint(requester_pub)
                    # Single-use: move code from minted -> requested immediately.
                    self.store.tx().execute(
                        "UPDATE pairing_codes SET state='requested', updated_at=? WHERE id=?",
                        (now_str, row["id"]),
                    )
                    self.store.tx().execute(
                        "INSERT INTO friend_requests ("
                        "id, pairing_code_id, requester_public_key, requester_fingerprint,"
                        " requester_card_json, request_signature, request_timestamp,"
                        " request_nonce, state, received_at"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
                        (
                            req_id,
                            row["id"],
                            requester_pub,
                            fp,
                            canonical_json_bytes(verified_card).decode("utf-8"),
                            hdr_sig,
                            req_ts,
                            hdr_nonce,
                            now_str,
                        ),
                    )
                    self.store.audit(
                        "pairing",
                        "friend_request_received",
                        {
                            "request_id": req_id,
                            "code_id": row["id"],
                            "claimed_handle": verified_card["handle"],
                            "claimed_display_name": verified_card["display_name"],
                            "requester_fingerprint": fp,
                        },
                        now=ts,
                    )
                    result = {
                        "request_id": req_id,
                        "status": "pending",
                    }
                else:
                    # Failed verification: attribute attempt to the single
                    # outstanding minted code (if any) and exhaust at cap.
                    outstanding = self.store.tx().execute(
                        "SELECT * FROM pairing_codes WHERE state='minted'"
                        " ORDER BY created_at DESC LIMIT 1"
                    ).fetchone()
                    if outstanding is not None:
                        if self._expire_if_due(outstanding, now=ts) == "minted":
                            new_attempts = outstanding["attempts"] + 1
                            new_state = (
                                "exhausted"
                                if new_attempts >= MAX_CODE_ATTEMPTS
                                else "minted"
                            )
                            self.store.tx().execute(
                                "UPDATE pairing_codes SET attempts=?, state=?, updated_at=?"
                                " WHERE id=?",
                                (new_attempts, new_state, now_str, outstanding["id"]),
                            )
                            self.store.audit(
                                "pairing",
                                "pairing_attempt_failed",
                                {
                                    "code_id": outstanding["id"],
                                    "attempts": new_attempts,
                                    "exhausted": new_state == "exhausted",
                                },
                                now=ts,
                            )
                        else:
                            self.store.audit(
                                "pairing",
                                "pairing_attempt_failed",
                                {"code_id": None},
                                now=ts,
                            )
                    else:
                        self.store.audit(
                            "pairing",
                            "pairing_attempt_failed",
                            {"code_id": None},
                            now=ts,
                        )
                    failure = _uniform_pairing_error()

        if failure is not None:
            raise failure
        return result

    # -- owner: review, approve, deny -------------------------------------
    def list_requests(self, *, state: str | None = None) -> list[dict]:
        if state is not None:
            rows = self.store.tx().execute(
                "SELECT * FROM friend_requests WHERE state=? ORDER BY received_at DESC",
                (state,),
            ).fetchall()
        else:
            rows = self.store.tx().execute(
                "SELECT * FROM friend_requests ORDER BY received_at DESC"
            ).fetchall()
        out = []
        for row in rows:
            card = json.loads(row["requester_card_json"])
            out.append(
                {
                    "request_id": row["id"],
                    "pairing_code_id": row["pairing_code_id"],
                    "state": row["state"],
                    "claimed_handle": card["handle"],
                    "claimed_display_name": card["display_name"],
                    "claimed_url": card["url"],
                    "requester_public_key": row["requester_public_key"],
                    "requester_fingerprint": row["requester_fingerprint"],
                    "received_at": row["received_at"],
                    "decided_at": row["decided_at"],
                    "decision_actor": row["decision_actor"],
                    "decision_note": row["decision_note"],
                }
            )
        return out

    def approve_request(
        self,
        request_id: str,
        *,
        tier: str = DEFAULT_TIER,
        discretion_profile: str = "",
        actor: str = "owner_cli",
        note: str | None = None,
        now: datetime | None = None,
    ) -> dict:
        if tier not in KNOWN_TIERS:
            raise FriendsError(
                "invalid_request",
                f"tier must be one of {', '.join(KNOWN_TIERS)}",
                status_code=400,
            )
        ts = _utc_now(now)
        now_str = now_iso(ts)
        with self.store.transaction():
            row = self.store.tx().execute(
                "SELECT * FROM friend_requests WHERE id=?", (request_id,)
            ).fetchone()
            if row is None:
                raise FriendsError("not_found", "friend request not found", status_code=404)
            if row["state"] != "pending":
                raise FriendsError(
                    "invalid_state",
                    f"friend request is already {row['state']}",
                    status_code=409,
                )
            card = json.loads(row["requester_card_json"])
            existing = self.store.tx().execute(
                "SELECT * FROM friends WHERE public_key=?",
                (row["requester_public_key"],),
            ).fetchone()
            if existing is not None:
                friend_id = existing["id"]
                self.store.tx().execute(
                    "UPDATE friends SET handle=?, display_name=?, card_json=?,"
                    " tier=?, discretion_profile=?, state='active', updated_at=?"
                    " WHERE id=?",
                    (
                        card["handle"],
                        card["display_name"],
                        row["requester_card_json"],
                        tier,
                        discretion_profile,
                        now_str,
                        friend_id,
                    ),
                )
            else:
                friend_id = new_id()
                self.store.tx().execute(
                    "INSERT INTO friends ("
                    "id, public_key, fingerprint, handle, display_name, card_json,"
                    " tier, verified, discretion_profile, state, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'active', ?, ?)",
                    (
                        friend_id,
                        row["requester_public_key"],
                        row["requester_fingerprint"],
                        card["handle"],
                        card["display_name"],
                        row["requester_card_json"],
                        tier,
                        discretion_profile,
                        now_str,
                        now_str,
                    ),
                )
            self.store.tx().execute(
                "UPDATE friend_requests SET state='approved', decided_at=?,"
                " decision_actor=?, decision_note=? WHERE id=?",
                (now_str, actor, note, request_id),
            )
            self.store.tx().execute(
                "UPDATE pairing_codes SET state='consumed', updated_at=? WHERE id=?",
                (now_str, row["pairing_code_id"]),
            )
            self.store.audit(
                actor,
                "friend_request_approved",
                {
                    "request_id": request_id,
                    "friend_id": friend_id,
                    "tier": tier,
                    "fingerprint": row["requester_fingerprint"],
                },
                now=ts,
            )
        return {
            "request_id": request_id,
            "friend_id": friend_id,
            "status": "approved",
            "tier": tier,
            "handle": card["handle"],
            "display_name": card["display_name"],
            "fingerprint": row["requester_fingerprint"],
            "verified": False,
        }

    def deny_request(
        self,
        request_id: str,
        *,
        actor: str = "owner_cli",
        note: str | None = None,
        now: datetime | None = None,
    ) -> dict:
        ts = _utc_now(now)
        now_str = now_iso(ts)
        with self.store.transaction():
            row = self.store.tx().execute(
                "SELECT * FROM friend_requests WHERE id=?", (request_id,)
            ).fetchone()
            if row is None:
                raise FriendsError("not_found", "friend request not found", status_code=404)
            if row["state"] != "pending":
                raise FriendsError(
                    "invalid_state",
                    f"friend request is already {row['state']}",
                    status_code=409,
                )
            self.store.tx().execute(
                "UPDATE friend_requests SET state='denied', decided_at=?,"
                " decision_actor=?, decision_note=? WHERE id=?",
                (now_str, actor, note, request_id),
            )
            self.store.tx().execute(
                "UPDATE pairing_codes SET state='denied', updated_at=? WHERE id=?",
                (now_str, row["pairing_code_id"]),
            )
            self.store.audit(
                actor,
                "friend_request_denied",
                {
                    "request_id": request_id,
                    "fingerprint": row["requester_fingerprint"],
                },
                now=ts,
            )
        return {
            "request_id": request_id,
            "status": "denied",
        }

    # -- owner: friend list, safety-number verification, revocation -------
    def list_friends(self, *, include_revoked: bool = False) -> list[dict]:
        if include_revoked:
            rows = self.store.tx().execute(
                "SELECT * FROM friends ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = self.store.tx().execute(
                "SELECT * FROM friends WHERE state != 'revoked' ORDER BY created_at DESC"
            ).fetchall()
        return [
            {
                "friend_id": row["id"],
                "handle": row["handle"],
                "display_name": row["display_name"],
                "public_key": row["public_key"],
                "fingerprint": row["fingerprint"],
                "tier": row["tier"],
                "verified": bool(row["verified"]),
                "state": row["state"],
                "discretion_profile": row["discretion_profile"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def verify_friend(
        self,
        friend_id: str,
        *,
        actor: str = "owner_cli",
        now: datetime | None = None,
    ) -> dict:
        ts = _utc_now(now)
        now_str = now_iso(ts)
        with self.store.transaction():
            row = self.store.tx().execute(
                "SELECT * FROM friends WHERE id=?", (friend_id,)
            ).fetchone()
            if row is None:
                raise FriendsError("not_found", "friend not found", status_code=404)
            if row["state"] != "active":
                raise FriendsError(
                    "invalid_state", f"friend is {row['state']}", status_code=409
                )
            self.store.tx().execute(
                "UPDATE friends SET verified=1, updated_at=? WHERE id=?",
                (now_str, friend_id),
            )
            self.store.audit(
                actor,
                "friend_verified",
                {"friend_id": friend_id, "fingerprint": row["fingerprint"]},
                now=ts,
            )
        return {
            "friend_id": friend_id,
            "fingerprint": row["fingerprint"],
            "tier": row["tier"],
            "verified": True,
        }

    def revoke_friend(
        self,
        friend_id: str,
        *,
        actor: str = "owner_cli",
        now: datetime | None = None,
    ) -> dict:
        ts = _utc_now(now)
        now_str = now_iso(ts)
        with self.store.transaction():
            row = self.store.tx().execute(
                "SELECT * FROM friends WHERE id=?", (friend_id,)
            ).fetchone()
            if row is None:
                raise FriendsError("not_found", "friend not found", status_code=404)
            self.store.tx().execute(
                "UPDATE friends SET state='revoked', updated_at=? WHERE id=?",
                (now_str, friend_id),
            )
            self.store.tx().execute(
                "UPDATE conversations SET state='closed', updated_at=? WHERE friend_id=?",
                (now_str, friend_id),
            )
            self.store.audit(
                actor,
                "friend_revoked",
                {"friend_id": friend_id, "fingerprint": row["fingerprint"]},
                now=ts,
            )
        return {
            "friend_id": friend_id,
            "state": "revoked",
        }
