"""Muse Mail integration workflow helpers.

Local-only integration layer invoked by the owner's Muse when handling mail:
  - Intake: identify sender, verify signed card/envelope/bundle attachments,
    evaluate tier + discretion policy, and emit a structured verdict.
  - Outbound: gate proposed outgoing friend messages or capability bundles
    against tier + discretion policy before anything is sent.
  - Thread mirroring: map Muse Mail threads to local muse-mcp standing channel
    threads (one per relationship) or discrete task threads.
"""
from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Any, Protocol

from .bundles import verify_capability_bundle
from .errors import FriendsError
from .mail import (
    KNOWN_ENVELOPE_KINDS,
    normalize_mail_address,
    verify_incoming_mail,
)
from .policy import evaluate_policy
from .store import Store, new_id, now_iso

KNOWN_THREAD_CLASSES = ("channel", "task")
KNOWN_OUTBOUND_KINDS = ("message", "capability_bundle")


def _utc_now(now: datetime | None = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _friend_summary(row) -> dict:
    return {
        "friend_id": row["id"],
        "handle": row["handle"],
        "display_name": row["display_name"],
        "mail_address": row["mail_address"],
        "fingerprint": row["fingerprint"],
        "tier": row["tier"],
        "verified": bool(row["verified"]),
        "state": row["state"],
        "discretion_profile": row["discretion_profile"],
    }


def _classify_attachment(
    item: str | pathlib.Path | dict,
) -> tuple[str, dict | None, str, str | None]:
    """Load an attachment (file path or dict) and classify its artifact type.

    Returns `(name, data, artifact_type, load_error)`. `load_error` is set only
    when a declared attachment cannot be read at all (missing file, permission
    error, non-UTF-8 bytes): the caller must fail closed there, because the
    unreadable file may be the signature that authenticates the message.
    Readable non-protocol content (a PDF, plain text, unrelated JSON) is not an
    error; it is reported as `other` and ignored.
    """
    if isinstance(item, dict):
        name = "<inline>"
        data = item
    else:
        path = pathlib.Path(item)
        name = path.name
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return name, None, "unreadable", f"{type(exc).__name__}: {exc}"
        try:
            data = json.loads(raw)
        except ValueError:
            return name, None, "other", None
        if not isinstance(data, dict):
            return name, None, "other", None

    if data.get("version") == 1 and data.get("kind") in KNOWN_ENVELOPE_KINDS:
        return name, data, "envelope", None
    if data.get("version") == 1 and "public_key" in data and "friend_api" in data:
        return name, data, "friend_card", None
    return name, data, "other", None


def _infer_request_kind(
    subject: str,
    body: str,
    attachment_results: list[dict],
) -> tuple[str, str]:
    """Infer (apparent_intent, policy_request_kind) from mail content and attachments."""
    for att in attachment_results:
        if att.get("envelope_kind") == "capability_bundle":
            return "capability_bundle", "command"
        if att.get("envelope_kind") == "pairing_confirmation":
            return "pairing_confirmation", "question"
        if att.get("artifact_type") == "friend_card":
            return "friend_card", "question"

    text = f"{subject}\n{body}".lower()
    if any(tok in text for tok in ("delegate", "book ", "schedule ", "purchase ", "on my behalf")):
        return "delegation", "delegation"
    if any(tok in text for tok in ("run command", "invoke ", "/commands/", "execute ")):
        return "command", "command"
    return "question", "question"


def _compute_permitted_actions(
    store: Store,
    *,
    friend_id: str,
    topics: list[str] | None,
    touches_private_data: bool,
    external_side_effects: bool,
    sensitive: bool,
) -> list[str]:
    permitted: list[str] = []
    checks = [
        ("answer_question", {"action": "act_on_request", "request_kind": "question"}),
        ("run_command", {"action": "act_on_request", "request_kind": "command"}),
        ("delegate", {"action": "act_on_request", "request_kind": "delegation"}),
        ("send_reply", {"action": "send_message"}),
        ("share_capability_bundle", {"action": "share_capability_bundle"}),
    ]
    for label, params in checks:
        res = evaluate_policy(
            store,
            friend_id=friend_id,
            topics=topics,
            touches_private_data=touches_private_data,
            external_side_effects=external_side_effects,
            sensitive=sensitive,
            **params,
        )
        if res["decision"] == "allow":
            permitted.append(label)
    return permitted


def evaluate_mail_intake(
    store: Store,
    *,
    from_address: str,
    subject: str = "",
    body: str = "",
    attachments: list[str | pathlib.Path | dict] | None = None,
    mail_thread_id: str | None = None,
    request_kind: str | None = None,
    topics: list[str] | tuple[str, ...] | None = None,
    touches_private_data: bool = False,
    external_side_effects: bool = False,
    sensitive: bool = False,
) -> dict:
    """Evaluate an incoming Muse Mail message against registry, signatures, pins, and policy.

    Local-only: performs no network I/O and sends no mail.
    """
    norm_from = normalize_mail_address(from_address)
    row = store.tx().execute(
        "SELECT * FROM friends WHERE lower(mail_address)=?", (norm_from,)
    ).fetchone()

    # A mail thread link is only meaningful for the friend it was recorded for.
    # A link belonging to another friend must never be handed back here: it
    # would point the Muse at a different relationship's local thread.
    thread_link = None
    if mail_thread_id:
        matches = lookup_mail_thread(store, mail_thread_id=mail_thread_id)
        if matches and row is not None and matches[0]["friend_id"] == row["id"]:
            thread_link = matches[0]

    # Inspect and verify all structured attachments.
    attachment_results: list[dict] = []
    any_signed = False
    verified_signed = False
    first_crypto_failure: dict | None = None
    first_bundle_pin_issue: dict | None = None
    first_unreadable: dict | None = None

    for item in attachments or []:
        name, data, artifact_type, load_error = _classify_attachment(item)
        if load_error is not None:
            entry = {
                "name": name,
                "artifact_type": "unreadable",
                "accepted": False,
                "code": "attachment_unreadable",
                "reason": f"declared attachment could not be read: {load_error}",
            }
            if first_unreadable is None:
                first_unreadable = entry
            attachment_results.append(entry)
            continue
        if artifact_type == "envelope" and data is not None:
            any_signed = True
            env_kind = data.get("kind")
            if env_kind == "capability_bundle":
                ver = verify_capability_bundle(
                    store,
                    sender_mail=norm_from,
                    envelope=data,
                    friend_id=row["id"] if row is not None else None,
                )
                entry = {
                    "name": name,
                    "artifact_type": "envelope",
                    "envelope_kind": env_kind,
                    "accepted": ver["accepted"],
                    "code": ver["code"],
                    "reason": ver["reason"],
                    "bundle_name": ver["bundle_name"],
                    "revision_hash": ver["revision_hash"],
                    "pinned_revision_hash": ver["pinned_revision_hash"],
                    "needs_owner_pin": ver["needs_owner_pin"],
                }
                if ver["accepted"]:
                    verified_signed = True
                elif ver["needs_owner_pin"]:
                    # Signature, sender, and key verified; only pin approval is missing/mismatched.
                    verified_signed = True
                    if first_bundle_pin_issue is None:
                        first_bundle_pin_issue = entry
                elif first_crypto_failure is None:
                    first_crypto_failure = entry
                attachment_results.append(entry)
            else:
                ver = verify_incoming_mail(
                    store,
                    sender_mail=norm_from,
                    envelope=data,
                    friend_id=row["id"] if row is not None else None,
                )
                entry = {
                    "name": name,
                    "artifact_type": "envelope",
                    "envelope_kind": env_kind,
                    "accepted": ver["accepted"],
                    "code": ver["code"],
                    "reason": ver["reason"],
                }
                if ver["accepted"]:
                    verified_signed = True
                elif first_crypto_failure is None:
                    first_crypto_failure = entry
                attachment_results.append(entry)
        elif artifact_type == "friend_card" and data is not None:
            any_signed = True
            ver = verify_incoming_mail(
                store,
                sender_mail=norm_from,
                card=data,
                friend_id=row["id"] if row is not None else None,
            )
            entry = {
                "name": name,
                "artifact_type": "friend_card",
                "accepted": ver["accepted"],
                "code": ver["code"],
                "reason": ver["reason"],
            }
            if ver["accepted"]:
                verified_signed = True
            elif first_crypto_failure is None:
                first_crypto_failure = entry
            attachment_results.append(entry)
        else:
            attachment_results.append(
                {
                    "name": name,
                    "artifact_type": "other",
                    "accepted": None,
                    "code": "ignored",
                    "reason": "non-protocol attachment",
                }
            )

    inferred_intent, inferred_req_kind = _infer_request_kind(
        subject, body, attachment_results
    )
    effective_req_kind = request_kind or inferred_req_kind

    # 0. A declared attachment the Muse could not read at all: fail closed,
    #    because it may be the signature that would authenticate this message.
    if first_unreadable is not None:
        return {
            "sender_status": "unverified" if row is not None else "unknown_sender",
            "verdict": "deny",
            "code": "attachment_unreadable",
            "reason": first_unreadable["reason"],
            "from_address": norm_from,
            "subject": subject,
            "apparent_intent": inferred_intent,
            "friend": _friend_summary(row) if row is not None else None,
            "permitted_actions": [],
            "attachments": attachment_results,
            "policy": None,
            "thread_link": thread_link,
        }

    # 1. Unknown sender.
    if row is None:
        return {
            "sender_status": "unknown_sender",
            "verdict": "deny",
            "code": "unknown_sender",
            "reason": f"sender '{norm_from}' is not in the friend registry",
            "from_address": norm_from,
            "subject": subject,
            "apparent_intent": inferred_intent,
            "friend": None,
            "permitted_actions": [],
            "attachments": attachment_results,
            "policy": None,
            "thread_link": thread_link,
        }

    friend_info = _friend_summary(row)

    # 2. Inactive friend (revoked / suspended).
    if row["state"] != "active":
        return {
            "sender_status": f"friend_{row['state']}",
            "verdict": "deny",
            "code": f"friend_{row['state']}",
            "reason": f"friend '{row['handle']}' is {row['state']}",
            "from_address": norm_from,
            "subject": subject,
            "apparent_intent": inferred_intent,
            "friend": friend_info,
            "permitted_actions": [],
            "attachments": attachment_results,
            "policy": None,
            "thread_link": thread_link,
        }

    # 3. Signed attachment failed cryptographic / binding verification.
    if first_crypto_failure is not None:
        return {
            "sender_status": "unverified",
            "verdict": "deny",
            "code": first_crypto_failure["code"],
            "reason": first_crypto_failure["reason"],
            "from_address": norm_from,
            "subject": subject,
            "apparent_intent": inferred_intent,
            "friend": friend_info,
            "permitted_actions": [],
            "attachments": attachment_results,
            "policy": None,
            "thread_link": thread_link,
        }

    # 4. Active friend, but message has no signed card/envelope attachment.
    if not any_signed or not verified_signed:
        return {
            "sender_status": "unverified",
            "verdict": "needs_owner_approval",
            "code": "unsigned_mail",
            "reason": f"mail from '{norm_from}' matches friend '{row['handle']}' but carries no verified Ed25519 signature",
            "from_address": norm_from,
            "subject": subject,
            "apparent_intent": inferred_intent,
            "friend": friend_info,
            "permitted_actions": [],
            "attachments": attachment_results,
            "policy": None,
            "thread_link": thread_link,
        }

    # 5. Verified friend! Check capability-bundle pin status if a bundle was attached.
    norm_topics = list(topics) if topics else None
    permitted = _compute_permitted_actions(
        store,
        friend_id=row["id"],
        topics=norm_topics,
        touches_private_data=touches_private_data,
        external_side_effects=external_side_effects,
        sensitive=sensitive,
    )

    if first_bundle_pin_issue is not None:
        return {
            "sender_status": "verified_friend",
            "verdict": "needs_owner_approval",
            "code": first_bundle_pin_issue["code"],
            "reason": first_bundle_pin_issue["reason"],
            "from_address": norm_from,
            "subject": subject,
            "apparent_intent": inferred_intent,
            "friend": friend_info,
            "permitted_actions": permitted,
            "attachments": attachment_results,
            "policy": None,
            "thread_link": thread_link,
        }

    # 6. Evaluate tier + discretion policy for the message's apparent intent.
    policy_res = evaluate_policy(
        store,
        friend_id=row["id"],
        action="act_on_request",
        request_kind=effective_req_kind,
        topics=norm_topics,
        touches_private_data=touches_private_data,
        external_side_effects=external_side_effects,
        sensitive=sensitive,
    )
    if inferred_intent == "capability_bundle" and policy_res["decision"] == "allow":
        permitted.append("accept_capability_bundle")

    return {
        "sender_status": "verified_friend",
        "verdict": policy_res["decision"],
        "code": policy_res["code"],
        "reason": policy_res["reason"],
        "from_address": norm_from,
        "subject": subject,
        "apparent_intent": inferred_intent,
        "friend": friend_info,
        "permitted_actions": permitted,
        "attachments": attachment_results,
        "policy": policy_res,
        "thread_link": thread_link,
    }


def check_mail_outbound(
    store: Store,
    *,
    friend_id: str | None = None,
    mail_address: str | None = None,
    kind: str = "message",
    subject: str = "",
    bundle_name: str | None = None,
    topics: list[str] | tuple[str, ...] | None = None,
    touches_private_data: bool = False,
    external_side_effects: bool = False,
    sensitive: bool = False,
) -> dict:
    """Pre-send policy gate for outgoing Muse Mail messages or capability bundles."""
    if kind not in KNOWN_OUTBOUND_KINDS:
        raise FriendsError(
            "invalid_request",
            f"outbound kind must be one of {', '.join(KNOWN_OUTBOUND_KINDS)}",
        )
    if kind == "capability_bundle" and not bundle_name:
        raise FriendsError(
            "invalid_request",
            "kind 'capability_bundle' requires bundle_name",
        )
    action = "send_message" if kind == "message" else "share_capability_bundle"
    pol = evaluate_policy(
        store,
        action=action,
        friend_id=friend_id,
        mail_address=mail_address,
        topics=list(topics) if topics else None,
        touches_private_data=touches_private_data,
        external_side_effects=external_side_effects,
        sensitive=sensitive,
    )

    pinned_outbound_revision = None
    discretion_profile = None
    resolved_mail = mail_address
    if pol["friend_id"] is not None:
        row = store.tx().execute(
            "SELECT mail_address, discretion_profile FROM friends WHERE id=?",
            (pol["friend_id"],),
        ).fetchone()
        if row is not None:
            resolved_mail = row["mail_address"]
            discretion_profile = row["discretion_profile"]
        if bundle_name is not None:
            pin = store.tx().execute(
                "SELECT revision_hash FROM friend_capability_pins"
                " WHERE friend_id=? AND bundle_name=? AND direction='outbound'",
                (pol["friend_id"], bundle_name),
            ).fetchone()
            if pin is not None:
                pinned_outbound_revision = pin["revision_hash"]

    return {
        "decision": pol["decision"],
        "code": pol["code"],
        "reason": pol["reason"],
        "friend_id": pol["friend_id"],
        "mail_address": resolved_mail,
        "tier": pol["tier"],
        "verified": pol["verified"],
        "action": pol["action"],
        "kind": kind,
        "subject": subject,
        "bundle_name": bundle_name,
        "pinned_outbound_revision": pinned_outbound_revision,
        "discretion_profile": discretion_profile,
    }


# -- Thread mirroring ---------------------------------------------
class MuseMcpClient(Protocol):
    """Minimal protocol for a local muse-mcp client (or test stub)."""

    def create_thread(self, title: str, body: str | None = None, **kwargs: Any) -> dict: ...

    def post_message(self, thread_id: str, body: str, **kwargs: Any) -> dict: ...


def link_mail_thread(
    store: Store,
    *,
    friend_id: str,
    mail_thread_id: str,
    mcp_thread_id: str,
    thread_class: str = "channel",
    subject: str = "",
    actor: str = "owner_cli",
    now: datetime | None = None,
) -> dict:
    """Record or update a Muse Mail thread <-> local muse-mcp thread mapping."""
    if thread_class not in KNOWN_THREAD_CLASSES:
        raise FriendsError(
            "invalid_request",
            f"thread_class must be one of {', '.join(KNOWN_THREAD_CLASSES)}",
        )
    if not isinstance(mail_thread_id, str) or not mail_thread_id.strip():
        raise FriendsError("invalid_request", "mail_thread_id is required")
    if not isinstance(mcp_thread_id, str) or not mcp_thread_id.strip():
        raise FriendsError("invalid_request", "mcp_thread_id is required")

    ts = _utc_now(now)
    now_str = now_iso(ts)
    norm_mail_tid = mail_thread_id.strip()
    norm_mcp_tid = mcp_thread_id.strip()

    with store.transaction():
        friend = store.tx().execute(
            "SELECT id, state FROM friends WHERE id=?", (friend_id,)
        ).fetchone()
        if friend is None:
            raise FriendsError("not_found", "friend not found", status_code=404)

        existing = store.tx().execute(
            "SELECT * FROM mail_thread_links WHERE mail_thread_id=?",
            (norm_mail_tid,),
        ).fetchone()
        if existing is not None:
            if existing["friend_id"] != friend_id:
                raise FriendsError(
                    "thread_conflict",
                    f"mail_thread_id '{norm_mail_tid}' is already linked to another friend",
                    status_code=409,
                )
            link_id = existing["id"]
            store.tx().execute(
                "UPDATE mail_thread_links SET mcp_thread_id=?, thread_class=?,"
                " subject=?, state='active', updated_at=? WHERE id=?",
                (norm_mcp_tid, thread_class, subject, now_str, link_id),
            )
        else:
            link_id = new_id()
            store.tx().execute(
                "INSERT INTO mail_thread_links ("
                "id, friend_id, mail_thread_id, mcp_thread_id, thread_class,"
                " subject, state, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                (
                    link_id,
                    friend_id,
                    norm_mail_tid,
                    norm_mcp_tid,
                    thread_class,
                    subject,
                    now_str,
                    now_str,
                ),
            )
        store.audit(
            actor,
            "mail_thread_linked",
            {
                "link_id": link_id,
                "friend_id": friend_id,
                "mail_thread_id": norm_mail_tid,
                "mcp_thread_id": norm_mcp_tid,
                "thread_class": thread_class,
            },
            now=ts,
        )

    return {
        "link_id": link_id,
        "friend_id": friend_id,
        "mail_thread_id": norm_mail_tid,
        "mcp_thread_id": norm_mcp_tid,
        "thread_class": thread_class,
        "subject": subject,
        "state": "active",
    }


def lookup_mail_thread(
    store: Store,
    *,
    mail_thread_id: str | None = None,
    mcp_thread_id: str | None = None,
    friend_id: str | None = None,
    thread_class: str | None = None,
) -> list[dict]:
    """Look up mail <-> muse-mcp thread links by mail_thread_id, mcp_thread_id, or friend_id."""
    clauses: list[str] = []
    params: list[Any] = []
    if mail_thread_id is not None:
        clauses.append("mail_thread_id = ?")
        params.append(mail_thread_id.strip())
    if mcp_thread_id is not None:
        clauses.append("mcp_thread_id = ?")
        params.append(mcp_thread_id.strip())
    if friend_id is not None:
        clauses.append("friend_id = ?")
        params.append(friend_id)
    if thread_class is not None:
        if thread_class not in KNOWN_THREAD_CLASSES:
            raise FriendsError(
                "invalid_request",
                f"thread_class must be one of {', '.join(KNOWN_THREAD_CLASSES)}",
            )
        clauses.append("thread_class = ?")
        params.append(thread_class)

    sql = "SELECT * FROM mail_thread_links"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY updated_at DESC"
    rows = store.tx().execute(sql, tuple(params)).fetchall()
    return [
        {
            "link_id": r["id"],
            "friend_id": r["friend_id"],
            "mail_thread_id": r["mail_thread_id"],
            "mcp_thread_id": r["mcp_thread_id"],
            "thread_class": r["thread_class"],
            "subject": r["subject"],
            "state": r["state"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }
        for r in rows
    ]


def get_standing_channel(store: Store, *, friend_id: str) -> dict | None:
    """Return the active standing channel link for a friend, if any."""
    rows = lookup_mail_thread(store, friend_id=friend_id, thread_class="channel")
    for r in rows:
        if r["state"] == "active":
            return r
    return None


def mirror_mail_to_mcp(
    store: Store,
    *,
    friend_id: str,
    mail_thread_id: str,
    mcp_client: MuseMcpClient,
    subject: str = "",
    body: str | None = None,
    thread_class: str = "channel",
    actor: str = "muse_mail_mirror",
    now: datetime | None = None,
) -> dict:
    """Mirror a friend mail message into a local muse-mcp channel or task thread.

    For `channel` threads, reuses the friend's standing channel
    `mcp_thread_id` if one already exists; for `task` threads, spawns a new
    discrete thread. Works with any stub or live `MuseMcpClient`.
    """
    if thread_class not in KNOWN_THREAD_CLASSES:
        raise FriendsError(
            "invalid_request",
            f"thread_class must be one of {', '.join(KNOWN_THREAD_CLASSES)}",
        )
    friend = store.tx().execute(
        "SELECT id, handle, display_name, state FROM friends WHERE id=?", (friend_id,)
    ).fetchone()
    if friend is None:
        raise FriendsError("not_found", "friend not found", status_code=404)
    if friend["state"] != "active":
        raise FriendsError(
            "invalid_state", f"friend is {friend['state']}", status_code=409
        )

    existing_for_mail = lookup_mail_thread(store, mail_thread_id=mail_thread_id)
    if existing_for_mail:
        link = existing_for_mail[0]
        if link["friend_id"] != friend_id:
            raise FriendsError(
                "thread_conflict",
                f"mail_thread_id '{mail_thread_id}' belongs to another friend",
                status_code=409,
            )
        if body is not None:
            mcp_client.post_message(link["mcp_thread_id"], body)
        return {**link, "created": False}

    if thread_class == "channel":
        standing = get_standing_channel(store, friend_id=friend_id)
        if standing is not None:
            link = link_mail_thread(
                store,
                friend_id=friend_id,
                mail_thread_id=mail_thread_id,
                mcp_thread_id=standing["mcp_thread_id"],
                thread_class="channel",
                subject=subject or standing["subject"],
                actor=actor,
                now=now,
            )
            if body is not None:
                mcp_client.post_message(standing["mcp_thread_id"], body)
            return {**link, "created": False}

    title = (
        f"Friend channel: {friend['display_name']} ({friend['handle']})"
        if thread_class == "channel"
        else f"Friend task ({friend['handle']}): {subject or mail_thread_id}"
    )
    created_resp = mcp_client.create_thread(title=title, body=body)
    mcp_tid = created_resp["thread_id"]
    link = link_mail_thread(
        store,
        friend_id=friend_id,
        mail_thread_id=mail_thread_id,
        mcp_thread_id=mcp_tid,
        thread_class=thread_class,
        subject=subject,
        actor=actor,
        now=now,
    )
    return {**link, "created": True}
