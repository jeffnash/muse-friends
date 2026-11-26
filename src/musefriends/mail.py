"""Muse Mail trust helpers: signed envelopes, verification, mail-confirmed
pairing completion, and pinned capability-bundle revisions.

Local-only: no network listener, no outbound transport.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import FriendsError
from .identity import (
    IdentityManager,
    canonical_json_bytes,
    decode_public_key,
    encode_public_key,
    key_fingerprint,
    verify_card,
)
from .pairing import (
    CODE_ALPHABET,
    DEFAULT_TIER,
    KNOWN_TIERS,
    MAX_CODE_ATTEMPTS,
    hash_code,
    normalize_code,
)
from .store import Store, new_id, now_iso

MAIL_ENVELOPE_VERSION = 1
MAIL_ENVELOPE_PREFIX = b"muse-mail-envelope-v1\n"
KNOWN_ENVELOPE_KINDS = ("message", "friend_card", "pairing_confirmation", "capability_bundle")
KNOWN_PIN_DIRECTIONS = ("inbound", "outbound")
MAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
BUNDLE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
REVISION_HASH_RE = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{16,128}$")


def normalize_mail_address(address: str) -> str:
    if not isinstance(address, str):
        raise FriendsError("invalid_mail_address", "mail_address must be a string")
    cleaned = address.strip().lower()
    if not cleaned or len(cleaned) > 254 or not MAIL_RE.fullmatch(cleaned):
        raise FriendsError("invalid_mail_address", f"malformed mail_address: {address!r}")
    return cleaned


def _utc_now(now: datetime | None = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _unsigned_envelope(envelope: dict) -> dict:
    return {k: v for k, v in envelope.items() if k != "signature"}


def sign_mail_envelope(
    private_key: Ed25519PrivateKey,
    *,
    sender_mail: str,
    payload: dict,
    kind: str = "message",
    recipient_mail: str | None = None,
    timestamp: datetime | None = None,
) -> dict:
    """Create a self-signed Muse Mail envelope for cards, confirmations, or messages."""
    if kind not in KNOWN_ENVELOPE_KINDS:
        raise FriendsError(
            "invalid_envelope",
            f"envelope kind must be one of {', '.join(KNOWN_ENVELOPE_KINDS)}",
        )
    if not isinstance(payload, dict):
        raise FriendsError("invalid_envelope", "envelope payload must be a JSON object")

    norm_sender = normalize_mail_address(sender_mail)
    pub = encode_public_key(private_key.public_key())
    body: dict = {
        "version": MAIL_ENVELOPE_VERSION,
        "kind": kind,
        "sender_mail": norm_sender,
        "public_key": pub,
        "timestamp": now_iso(_utc_now(timestamp)),
        "payload": payload,
    }
    if recipient_mail is not None:
        body["recipient_mail"] = normalize_mail_address(recipient_mail)

    sig = private_key.sign(MAIL_ENVELOPE_PREFIX + canonical_json_bytes(body))
    signed = dict(body)
    signed["signature"] = base64.b64encode(sig).decode("ascii")
    return signed


def verify_mail_envelope_signature(envelope: dict) -> dict:
    """Validate Muse Mail envelope schema and Ed25519 signature."""
    if not isinstance(envelope, dict):
        raise FriendsError("invalid_envelope", "envelope must be a JSON object")
    if envelope.get("version") != MAIL_ENVELOPE_VERSION:
        raise FriendsError(
            "invalid_envelope", f"unsupported envelope version: {envelope.get('version')!r}"
        )
    if envelope.get("kind") not in KNOWN_ENVELOPE_KINDS:
        raise FriendsError(
            "invalid_envelope", f"unsupported envelope kind: {envelope.get('kind')!r}"
        )
    normalize_mail_address(envelope.get("sender_mail", ""))
    if envelope.get("recipient_mail") is not None:
        normalize_mail_address(envelope["recipient_mail"])
    if not isinstance(envelope.get("payload"), dict):
        raise FriendsError("invalid_envelope", "envelope payload must be a JSON object")
    ts = envelope.get("timestamp")
    if not isinstance(ts, str) or not ts:
        raise FriendsError("invalid_envelope", "envelope timestamp is required")
    try:
        _parse_iso(ts)
    except ValueError as exc:
        raise FriendsError("invalid_envelope", "envelope timestamp must be ISO-8601") from exc

    signature = envelope.get("signature")
    if not isinstance(signature, str) or not signature:
        raise FriendsError("invalid_signature", "mail envelope is missing signature")
    try:
        sig_bytes = base64.b64decode(signature, validate=True)
    except Exception as exc:
        raise FriendsError(
            "invalid_signature", "mail envelope signature is not valid base64"
        ) from exc
    if len(sig_bytes) != 64:
        raise FriendsError("invalid_signature", "Ed25519 signature must be 64 bytes")

    pubkey = decode_public_key(envelope.get("public_key", ""))
    unsigned = _unsigned_envelope(envelope)
    try:
        pubkey.verify(sig_bytes, MAIL_ENVELOPE_PREFIX + canonical_json_bytes(unsigned))
    except InvalidSignature as exc:
        raise FriendsError(
            "invalid_signature", "mail envelope signature verification failed"
        ) from exc
    return envelope


def verify_incoming_mail(
    store: Store,
    *,
    sender_mail: str,
    envelope: dict | None = None,
    card: dict | None = None,
    friend_id: str | None = None,
) -> dict:
    """Verify a signed incoming friend card or mail envelope against a friend record.

    Checks all three bindings:
      1. Ed25519 signature is valid on the card or envelope (and embedded card if any).
      2. Transport sender_mail matches the friend record's bound mail_address
         (and envelope.sender_mail when an envelope is supplied).
      3. Presented public_key matches the pinned friend-card key on the record.

    Returns a structured accept/reject dict with code and human-readable reason.
    """
    def _reject(code: str, reason: str, *, row=None) -> dict:
        return {
            "accepted": False,
            "code": code,
            "reason": reason,
            "friend_id": row["id"] if row is not None else friend_id,
            "handle": row["handle"] if row is not None else None,
            "mail_address": row["mail_address"] if row is not None else None,
            "fingerprint": row["fingerprint"] if row is not None else None,
            "tier": row["tier"] if row is not None else None,
            "verified": bool(row["verified"]) if row is not None else None,
        }

    try:
        norm_sender = normalize_mail_address(sender_mail)
    except FriendsError as exc:
        return _reject(exc.code, exc.message)

    if (envelope is None) == (card is None):
        return _reject("invalid_input", "provide exactly one of envelope or card")

    # 1. Verify cryptographic signature on the incoming artifact.
    presented_pub: str
    if card is not None:
        try:
            verified_card = verify_card(card, require_signature=True)
        except FriendsError as exc:
            return _reject(exc.code, exc.message)
        presented_pub = verified_card["public_key"]
    else:
        assert envelope is not None
        try:
            verified_env = verify_mail_envelope_signature(envelope)
        except FriendsError as exc:
            return _reject(exc.code, exc.message)
        env_sender = normalize_mail_address(verified_env["sender_mail"])
        if env_sender != norm_sender:
            return _reject(
                "sender_mismatch",
                f"envelope sender_mail '{env_sender}' does not match transport sender '{norm_sender}'",
            )
        presented_pub = verified_env["public_key"]
        # If envelope carries a friend card, verify that card too and ensure key agreement.
        embedded_card = verified_env["payload"].get("card")
        if embedded_card is not None:
            try:
                verified_embedded = verify_card(embedded_card, require_signature=True)
            except FriendsError as exc:
                return _reject(exc.code, exc.message)
            if verified_embedded["public_key"] != presented_pub:
                return _reject(
                    "key_mismatch",
                    "embedded friend card public_key does not match envelope public_key",
                )

    # 2. Resolve friend record.
    conn = store.tx()
    row = None
    if friend_id is not None:
        row = conn.execute("SELECT * FROM friends WHERE id=?", (friend_id,)).fetchone()
        if row is None:
            return _reject("unknown_friend", f"no friend record found for id '{friend_id}'")
    else:
        row = conn.execute(
            "SELECT * FROM friends WHERE lower(mail_address)=?", (norm_sender,)
        ).fetchone()
        if row is None:
            # Fall back to key lookup so we can report sender_mismatch accurately.
            row = conn.execute(
                "SELECT * FROM friends WHERE public_key=?", (presented_pub,)
            ).fetchone()
            if row is None:
                return _reject(
                    "unknown_friend",
                    f"no friend record matches sender '{norm_sender}' or presented key",
                )

    # 3. Check friend record state, sender mail_address binding, and pinned key.
    if row["state"] != "active":
        return _reject(
            "friend_not_active",
            f"friend '{row['handle']}' is {row['state']}, not active",
            row=row,
        )

    bound_mail = row["mail_address"]
    if not bound_mail:
        return _reject(
            "sender_mismatch",
            f"friend '{row['handle']}' has no bound mail_address",
            row=row,
        )
    if normalize_mail_address(bound_mail) != norm_sender:
        return _reject(
            "sender_mismatch",
            f"sender '{norm_sender}' does not match bound mail_address '{bound_mail}'",
            row=row,
        )

    if not hmac.compare_digest(row["public_key"], presented_pub):
        return _reject(
            "key_mismatch",
            "presented public key does not match pinned friend-card key",
            row=row,
        )

    return {
        "accepted": True,
        "code": "ok",
        "reason": "signature, sender mail_address, and pinned key verified",
        "friend_id": row["id"],
        "handle": row["handle"],
        "mail_address": row["mail_address"],
        "fingerprint": row["fingerprint"],
        "tier": row["tier"],
        "verified": bool(row["verified"]),
    }


def complete_mail_pairing(
    store: Store,
    identity: IdentityManager,
    *,
    confirmation_envelope: dict,
    sender_mail: str,
    owner_approved: bool,
    code_id: str | None = None,
    tier: str = DEFAULT_TIER,
    discretion_profile: str = "",
    actor: str = "owner_cli",
    note: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Complete a mail-confirmed pairing.

    Requires:
      - A pending minted pairing code (unexpired, below 5-attempt cap).
      - A signed mail confirmation envelope (`kind='pairing_confirmation'`) from
        `sender_mail` containing the matching pairing code and signed friend card.
      - Explicit local `owner_approved=True`.

    Refuses on missing owner approval, invalid signature, sender/key mismatch,
    code mismatch (burning an attempt up to the 5-attempt cap), expiry, or
    exhausted/non-minted code state.
    """
    if not owner_approved:
        raise FriendsError(
            "owner_approval_required",
            "local owner approval is required to complete pairing",
            status_code=403,
        )
    if tier not in KNOWN_TIERS:
        raise FriendsError(
            "invalid_request",
            f"tier must be one of {', '.join(KNOWN_TIERS)}",
            status_code=400,
        )

    ts = _utc_now(now)
    now_str = now_iso(ts)
    norm_sender = normalize_mail_address(sender_mail)
    own_card = identity.current_card()

    # Verify signed confirmation envelope and embedded friend card before touching code state.
    verified_env = verify_mail_envelope_signature(confirmation_envelope)
    if verified_env["kind"] != "pairing_confirmation":
        raise FriendsError(
            "invalid_envelope",
            f"expected kind 'pairing_confirmation', got {verified_env['kind']!r}",
            status_code=400,
        )
    env_sender = normalize_mail_address(verified_env["sender_mail"])
    if env_sender != norm_sender:
        raise FriendsError(
            "sender_mismatch",
            f"envelope sender_mail '{env_sender}' does not match sender '{norm_sender}'",
            status_code=400,
        )

    payload = verified_env["payload"]
    presented_code = payload.get("code")
    peer_card_raw = payload.get("card")
    if not isinstance(presented_code, str) or not presented_code.strip():
        raise FriendsError("invalid_envelope", "confirmation payload must include 'code'")
    verified_card = verify_card(peer_card_raw, require_signature=True)
    peer_pub = verified_card["public_key"]
    if peer_pub != verified_env["public_key"]:
        raise FriendsError(
            "key_mismatch",
            "confirmation envelope public_key does not match friend card public_key",
            status_code=400,
        )
    if peer_pub == own_card["public_key"]:
        raise FriendsError("invalid_request", "cannot pair with self", status_code=400)

    normalized_code = normalize_code(presented_code)
    presented_hash = (
        hash_code(normalized_code)
        if len(normalized_code) == 8 and all(c in CODE_ALPHABET for c in normalized_code)
        else None
    )

    failure: FriendsError | None = None
    result: dict | None = None

    with store.transaction():
        if code_id is not None:
            row = store.tx().execute(
                "SELECT * FROM pairing_codes WHERE id=?", (code_id,)
            ).fetchone()
        else:
            row = store.tx().execute(
                "SELECT * FROM pairing_codes WHERE state='minted'"
                " ORDER BY created_at DESC LIMIT 1"
            ).fetchone()

        if row is None:
            failure = FriendsError(
                "pairing_not_found", "no pending pairing code found", status_code=404
            )
        elif row["state"] == "expired" or (
            row["state"] == "minted" and ts > _parse_iso(row["expires_at"])
        ):
            if row["state"] == "minted":
                store.tx().execute(
                    "UPDATE pairing_codes SET state='expired', updated_at=? WHERE id=?",
                    (now_str, row["id"]),
                )
                store.audit(
                    "pairing", "pairing_code_expired", {"code_id": row["id"]}, now=ts
                )
            failure = FriendsError(
                "pairing_expired", "pairing code has expired", status_code=400
            )
        elif row["state"] == "exhausted" or row["attempts"] >= MAX_CODE_ATTEMPTS:
            if row["state"] != "exhausted":
                store.tx().execute(
                    "UPDATE pairing_codes SET state='exhausted', updated_at=? WHERE id=?",
                    (now_str, row["id"]),
                )
            failure = FriendsError(
                "pairing_exhausted",
                "pairing code attempt limit reached",
                status_code=400,
            )
        elif row["state"] != "minted":
            failure = FriendsError(
                "invalid_state",
                f"pairing code is already {row['state']}",
                status_code=409,
            )
        elif presented_hash is None or not hmac.compare_digest(
            row["code_hash"], presented_hash
        ):
            new_attempts = row["attempts"] + 1
            new_state = "exhausted" if new_attempts >= MAX_CODE_ATTEMPTS else "minted"
            store.tx().execute(
                "UPDATE pairing_codes SET attempts=?, state=?, updated_at=? WHERE id=?",
                (new_attempts, new_state, now_str, row["id"]),
            )
            store.audit(
                "pairing",
                "mail_pairing_attempt_failed",
                {
                    "code_id": row["id"],
                    "attempts": new_attempts,
                    "exhausted": new_state == "exhausted",
                    "sender_mail": norm_sender,
                },
                now=ts,
            )
            failure = FriendsError(
                "code_mismatch",
                "pairing code does not match",
                status_code=400,
            )
        else:
            # Ensure mail_address isn't already bound to a different friend key.
            clash = store.tx().execute(
                "SELECT id, public_key FROM friends WHERE lower(mail_address)=?",
                (norm_sender,),
            ).fetchone()
            if clash is not None and clash["public_key"] != peer_pub:
                failure = FriendsError(
                    "mail_address_in_use",
                    f"mail_address '{norm_sender}' is already bound to another friend",
                    status_code=409,
                )
            else:
                fp = key_fingerprint(peer_pub)
                card_json = canonical_json_bytes(verified_card).decode("utf-8")
                req_id = new_id()
                env_ts = int(_parse_iso(verified_env["timestamp"]).timestamp())
                env_nonce = hashlib.sha256(
                    verified_env["signature"].encode("ascii")
                ).hexdigest()[:32]

                store.tx().execute(
                    "INSERT INTO friend_requests ("
                    "id, pairing_code_id, requester_public_key, requester_fingerprint,"
                    " requester_card_json, requester_mail_address, request_signature,"
                    " request_timestamp, request_nonce, state, received_at, decided_at,"
                    " decision_actor, decision_note"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?)",
                    (
                        req_id,
                        row["id"],
                        peer_pub,
                        fp,
                        card_json,
                        norm_sender,
                        verified_env["signature"],
                        env_ts,
                        env_nonce,
                        now_str,
                        now_str,
                        actor,
                        note,
                    ),
                )

                existing = store.tx().execute(
                    "SELECT id FROM friends WHERE public_key=?", (peer_pub,)
                ).fetchone()
                if existing is not None:
                    friend_id = existing["id"]
                    store.tx().execute(
                        "UPDATE friends SET handle=?, display_name=?, card_json=?,"
                        " mail_address=?, tier=?, discretion_profile=?,"
                        " state='active', updated_at=? WHERE id=?",
                        (
                            verified_card["handle"],
                            verified_card["display_name"],
                            card_json,
                            norm_sender,
                            tier,
                            discretion_profile,
                            now_str,
                            friend_id,
                        ),
                    )
                else:
                    friend_id = new_id()
                    store.tx().execute(
                        "INSERT INTO friends ("
                        "id, public_key, fingerprint, handle, display_name, card_json,"
                        " mail_address, tier, verified, discretion_profile, state,"
                        " created_at, updated_at"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 'active', ?, ?)",
                        (
                            friend_id,
                            peer_pub,
                            fp,
                            verified_card["handle"],
                            verified_card["display_name"],
                            card_json,
                            norm_sender,
                            tier,
                            discretion_profile,
                            now_str,
                            now_str,
                        ),
                    )

                store.tx().execute(
                    "UPDATE pairing_codes SET state='consumed', updated_at=? WHERE id=?",
                    (now_str, row["id"]),
                )
                store.audit(
                    actor,
                    "mail_pairing_completed",
                    {
                        "request_id": req_id,
                        "code_id": row["id"],
                        "friend_id": friend_id,
                        "mail_address": norm_sender,
                        "tier": tier,
                        "fingerprint": fp,
                    },
                    now=ts,
                )
                result = {
                    "status": "paired",
                    "friend_id": friend_id,
                    "request_id": req_id,
                    "code_id": row["id"],
                    "handle": verified_card["handle"],
                    "display_name": verified_card["display_name"],
                    "mail_address": norm_sender,
                    "public_key": peer_pub,
                    "fingerprint": fp,
                    "tier": tier,
                    "verified": False,
                }

    if failure is not None:
        raise failure
    assert result is not None
    return result


def pin_capability_bundle(
    store: Store,
    *,
    friend_id: str,
    bundle_name: str,
    revision_hash: str,
    direction: str = "inbound",
    actor: str = "owner_cli",
    note: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Pin or update a signed capability-bundle revision hash for a friend."""
    if direction not in KNOWN_PIN_DIRECTIONS:
        raise FriendsError(
            "invalid_request",
            f"direction must be one of {', '.join(KNOWN_PIN_DIRECTIONS)}",
        )
    if not isinstance(bundle_name, str) or not BUNDLE_NAME_RE.fullmatch(bundle_name):
        raise FriendsError("invalid_request", "bundle_name is malformed")
    if not isinstance(revision_hash, str) or not REVISION_HASH_RE.fullmatch(revision_hash):
        raise FriendsError("invalid_request", "revision_hash is malformed")

    ts = _utc_now(now)
    now_str = now_iso(ts)
    norm_hash = revision_hash.lower()

    with store.transaction():
        friend = store.tx().execute(
            "SELECT id, state FROM friends WHERE id=?", (friend_id,)
        ).fetchone()
        if friend is None:
            raise FriendsError("not_found", "friend not found", status_code=404)
        if friend["state"] != "active":
            raise FriendsError(
                "invalid_state", f"friend is {friend['state']}", status_code=409
            )

        existing = store.tx().execute(
            "SELECT id FROM friend_capability_pins"
            " WHERE friend_id=? AND bundle_name=? AND direction=?",
            (friend_id, bundle_name, direction),
        ).fetchone()
        if existing is not None:
            pin_id = existing["id"]
            store.tx().execute(
                "UPDATE friend_capability_pins SET revision_hash=?, pinned_at=?,"
                " pinned_by=?, note=? WHERE id=?",
                (norm_hash, now_str, actor, note, pin_id),
            )
        else:
            pin_id = new_id()
            store.tx().execute(
                "INSERT INTO friend_capability_pins ("
                "id, friend_id, bundle_name, revision_hash, direction, pinned_at, pinned_by, note"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (pin_id, friend_id, bundle_name, norm_hash, direction, now_str, actor, note),
            )
        store.audit(
            actor,
            "capability_bundle_pinned",
            {
                "pin_id": pin_id,
                "friend_id": friend_id,
                "bundle_name": bundle_name,
                "revision_hash": norm_hash,
                "direction": direction,
            },
            now=ts,
        )

    return {
        "pin_id": pin_id,
        "friend_id": friend_id,
        "bundle_name": bundle_name,
        "revision_hash": norm_hash,
        "direction": direction,
        "pinned_at": now_str,
    }


def list_capability_pins(store: Store, *, friend_id: str) -> list[dict]:
    rows = store.tx().execute(
        "SELECT id, friend_id, bundle_name, revision_hash, direction, pinned_at, pinned_by, note"
        " FROM friend_capability_pins WHERE friend_id=? ORDER BY bundle_name, direction",
        (friend_id,),
    ).fetchall()
    return [dict(r) for r in rows]
