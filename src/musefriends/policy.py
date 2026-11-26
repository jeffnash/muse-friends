"""Tier and discretion-profile policy evaluator.

Evaluates a proposed action for a friend record and returns one of:
  - allow
  - deny
  - needs_owner_approval
together with a machine-readable code and human-readable reason.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .errors import FriendsError
from .store import Store

KNOWN_ACTIONS = ("send_message", "share_capability_bundle", "act_on_request")
KNOWN_REQUEST_KINDS = ("question", "command", "delegation")

# deny-leaning defaults: never shared unless explicitly relaxed.
DEFAULT_PRIVATE_TOPICS = frozenset(
    {
        "finances",
        "health",
        "messages",
        "files",
        "other_friends",
        "credentials",
        "other_conversations",
    }
)


@dataclass
class DiscretionRules:
    deny_all: bool = False
    require_approval_all: bool = False
    denied: set[str] = field(default_factory=set)
    escalate: set[str] = field(default_factory=set)
    allowed: set[str] = field(default_factory=set)
    established_topics: set[str] = field(default_factory=set)


def parse_discretion_profile(profile: str | None) -> DiscretionRules:
    """Parse owner-authored discretion rules from plain text / directive lines.

    Recognized directives (case-insensitive, newline or ';' separated):
      - deny:<topic_or_action_or_all>
      - escalate:<topic_or_action_or_all>  (alias: approve:<...>)
      - allow:<topic_or_action>
      - topics:<t1>,<t2>,...               (sets established topics for §7.2)
    Free-form prose lines without directives are preserved verbatim on the
    friend record for the Muse and ignored by the deterministic parser.
    """
    rules = DiscretionRules()
    if not profile:
        return rules

    for raw_clause in re.split(r"[\n;]+", profile):
        clause = raw_clause.strip()
        if not clause or ":" not in clause:
            continue
        key, value = clause.split(":", 1)
        directive = key.strip().lower()
        items = [v.strip().lower() for v in value.split(",") if v.strip()]
        if not items:
            continue

        if directive == "deny":
            for item in items:
                if item == "all":
                    rules.deny_all = True
                else:
                    rules.denied.add(item)
        elif directive in ("escalate", "approve", "require_approval"):
            for item in items:
                if item == "all":
                    rules.require_approval_all = True
                else:
                    rules.escalate.add(item)
        elif directive == "allow":
            for item in items:
                rules.allowed.add(item)
        elif directive == "topics":
            for item in items:
                rules.established_topics.add(item)

    return rules


def _resolve_friend(store: Store, *, friend_id: str | None, mail_address: str | None):
    conn = store.tx()
    if friend_id is not None:
        return conn.execute("SELECT * FROM friends WHERE id=?", (friend_id,)).fetchone()
    if mail_address is not None:
        return conn.execute(
            "SELECT * FROM friends WHERE lower(mail_address)=?",
            (mail_address.strip().lower(),),
        ).fetchone()
    raise FriendsError("invalid_request", "friend_id or mail_address is required")


def evaluate_policy(
    store: Store,
    *,
    action: str,
    friend_id: str | None = None,
    mail_address: str | None = None,
    request_kind: str = "question",
    topics: list[str] | tuple[str, ...] | None = None,
    touches_private_data: bool = False,
    external_side_effects: bool = False,
    sensitive: bool = False,
) -> dict:
    """Evaluate tier + discretion profile for a proposed friend action.

    Returns:
      {
        "decision": "allow" | "deny" | "needs_owner_approval",
        "code": str,
        "reason": str,
        "friend_id": str | None,
        "tier": str | None,
        "verified": bool | None,
        "action": str,
      }
    """
    if action not in KNOWN_ACTIONS:
        raise FriendsError(
            "invalid_request",
            f"action must be one of {', '.join(KNOWN_ACTIONS)}",
        )
    if action == "act_on_request" and request_kind not in KNOWN_REQUEST_KINDS:
        raise FriendsError(
            "invalid_request",
            f"request_kind must be one of {', '.join(KNOWN_REQUEST_KINDS)}",
        )

    row = _resolve_friend(store, friend_id=friend_id, mail_address=mail_address)

    def _result(decision: str, code: str, reason: str) -> dict:
        return {
            "decision": decision,
            "code": code,
            "reason": reason,
            "friend_id": row["id"] if row is not None else friend_id,
            "tier": row["tier"] if row is not None else None,
            "verified": bool(row["verified"]) if row is not None else None,
            "action": action,
        }

    # 1. Friend existence, active state, and Muse Mail pairing binding.
    if row is None:
        return _result("deny", "unknown_friend", "no matching friend record")
    if row["state"] == "revoked":
        return _result("deny", "friend_revoked", "friend has been revoked")
    if row["state"] == "suspended":
        return _result("deny", "friend_suspended", "friend is suspended pending owner review")
    if not row["mail_address"]:
        return _result("deny", "friend_unpaired", "friend has no bound Muse Mail address")

    tier: str = row["tier"]
    verified = bool(row["verified"])
    rules = parse_discretion_profile(row["discretion_profile"])
    norm_topics = [t.strip().lower() for t in (topics or []) if t and t.strip()]

    # 2. Explicit discretion denies and default private-data guard.
    if rules.deny_all:
        return _result("deny", "discretion_deny_all", "discretion profile denies all actions")
    if action in rules.denied:
        return _result("deny", "discretion_deny_action", f"discretion profile denies '{action}'")
    if action == "act_on_request" and request_kind in rules.denied:
        return _result(
            "deny",
            "discretion_deny_request_kind",
            f"discretion profile denies '{request_kind}' requests",
        )
    for topic in norm_topics:
        if topic in rules.denied:
            return _result(
                "deny",
                "discretion_deny_topic",
                f"discretion profile denies topic '{topic}'",
            )

    if touches_private_data and "private_data" not in rules.allowed:
        return _result(
            "deny",
            "discretion_private_data",
            "private data is never shared by default under discretion rules",
        )
    for topic in norm_topics:
        if topic in DEFAULT_PRIVATE_TOPICS and topic not in rules.allowed:
            return _result(
                "deny",
                "discretion_private_topic",
                f"topic '{topic}' is private by default under discretion rules",
            )

    # 3. Explicit discretion escalations.
    if rules.require_approval_all:
        return _result(
            "needs_owner_approval",
            "discretion_escalate_all",
            "discretion profile requires owner approval for all actions",
        )
    if action in rules.escalate:
        return _result(
            "needs_owner_approval",
            "discretion_escalate_action",
            f"discretion profile requires owner approval for '{action}'",
        )
    if action == "act_on_request" and request_kind in rules.escalate:
        return _result(
            "needs_owner_approval",
            "discretion_escalate_request_kind",
            f"discretion profile requires owner approval for '{request_kind}' requests",
        )
    for topic in norm_topics:
        if topic in rules.escalate:
            return _result(
                "needs_owner_approval",
                "discretion_escalate_topic",
                f"discretion profile requires owner approval for topic '{topic}'",
            )

    # 4. Tier capability gating.
    if action == "send_message":
        if rules.established_topics and norm_topics:
            outside = [
                t
                for t in norm_topics
                if t not in rules.established_topics and t not in rules.allowed
            ]
            if outside:
                return _result(
                    "needs_owner_approval",
                    "outside_established_topics",
                    f"topic(s) {', '.join(outside)} fall outside established topics",
                )
        if sensitive and "sensitive" not in rules.allowed:
            return _result(
                "needs_owner_approval",
                "sensitive_content",
                "sending sensitive content requires owner approval",
            )
        return _result("allow", "ok", f"tier '{tier}' permits sending messages")

    if action == "share_capability_bundle":
        if tier == "acquaintance":
            return _result(
                "deny",
                "tier_disallows_capabilities",
                "acquaintance tier cannot receive shared capability bundles",
            )
        if tier == "friend":
            if "share_capability_bundle" in rules.allowed:
                return _result(
                    "allow",
                    "discretion_allow_bundle",
                    "discretion profile explicitly permits sharing capability bundles",
                )
            return _result(
                "needs_owner_approval",
                "tier_requires_approval_for_bundle",
                "sharing capability bundles with friend tier requires owner approval",
            )
        # inner tier
        if external_side_effects and not verified:
            return _result(
                "needs_owner_approval",
                "unverified_safety_number",
                "sharing side-effecting capability bundles with unverified inner friend requires owner approval",
            )
        return _result("allow", "ok", "inner tier permits sharing capability bundles")

    # action == "act_on_request"
    if request_kind == "question":
        if external_side_effects:
            return _result(
                "deny" if tier == "acquaintance" else "needs_owner_approval",
                "external_side_effects",
                "question requests must not trigger external side effects without approval",
            )
        if rules.established_topics and norm_topics:
            outside = [
                t
                for t in norm_topics
                if t not in rules.established_topics and t not in rules.allowed
            ]
            if outside:
                return _result(
                    "needs_owner_approval",
                    "outside_established_topics",
                    f"request topic(s) {', '.join(outside)} fall outside established topics",
                )
        if sensitive and tier != "inner" and "sensitive" not in rules.allowed:
            return _result(
                "needs_owner_approval",
                "sensitive_request",
                f"sensitive question from '{tier}' tier escalates to owner",
            )
        return _result("allow", "ok", f"tier '{tier}' permits answering questions")

    if request_kind == "command":
        if tier == "acquaintance":
            return _result(
                "deny",
                "tier_disallows_commands",
                "acquaintance tier may ask questions only; commands are denied",
            )
        if tier == "friend":
            if external_side_effects and "external_side_effects" not in rules.allowed:
                return _result(
                    "needs_owner_approval",
                    "tier_requires_approval_side_effects",
                    "friend tier commands with external side effects require owner approval",
                )
            return _result("allow", "ok", "friend tier permits invoking friend-visible commands")
        # inner tier
        if external_side_effects and not verified:
            return _result(
                "needs_owner_approval",
                "unverified_safety_number",
                "side-effecting commands from an unverified inner friend require owner approval",
            )
        return _result("allow", "ok", "inner tier permits invoking commands")

    # request_kind == "delegation"
    if tier == "acquaintance":
        return _result(
            "deny",
            "tier_disallows_delegation",
            "acquaintance tier cannot delegate work",
        )
    if tier == "friend":
        if "delegation" in rules.allowed and not external_side_effects:
            return _result(
                "allow",
                "discretion_allow_delegation",
                "discretion profile permits non-side-effecting delegation for friend tier",
            )
        return _result(
            "needs_owner_approval",
            "tier_requires_approval_delegation",
            "delegation from friend tier requires owner approval",
        )
    # inner tier
    if external_side_effects and not verified:
        return _result(
            "needs_owner_approval",
            "unverified_safety_number",
            "side-effecting delegation from an unverified inner friend requires owner approval",
        )
    return _result("allow", "ok", "inner tier permits delegation")
