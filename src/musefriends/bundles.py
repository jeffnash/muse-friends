"""Signed capability bundles over Muse Mail and pin verification.

Capability bundles (skills or commands) are packaged as signed
`muse-mail-envelope-v1` payloads (`kind="capability_bundle"`) with a
deterministic SHA-256 revision hash over their normalized contents. Incoming
bundles are accepted only when:
  1. The mail envelope signature, sender mail_address, and pinned friend key
     verify against an active paired friend record.
  2. The claimed revision_hash matches the recomputed hash of the signed files.
  3. The revision_hash matches a pin in `friend_capability_pins` for that
     friend and bundle_name (otherwise a clear `bundle_not_pinned` or
     `pin_mismatch` verdict is returned so the owner can review and approve).
"""
from __future__ import annotations

import hashlib
import hmac
import pathlib
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import FriendsError
from .identity import canonical_json_bytes
from .mail import (
    BUNDLE_NAME_RE,
    KNOWN_PIN_DIRECTIONS,
    sign_mail_envelope,
    verify_incoming_mail,
)
from .store import Store

BUNDLE_FORMAT_VERSION = 1
KNOWN_BUNDLE_KINDS = ("skill", "command")


def _validate_bundle_files(files: dict[str, str]) -> dict[str, str]:
    if not isinstance(files, dict) or not files:
        raise FriendsError("invalid_bundle", "bundle files must be a non-empty object")
    cleaned: dict[str, str] = {}
    for rel_path, content in files.items():
        if not isinstance(rel_path, str) or not rel_path.strip():
            raise FriendsError("invalid_bundle", "bundle file path must be a non-empty string")
        norm = rel_path.strip()
        if norm.startswith("/") or "\\" in norm:
            raise FriendsError("invalid_bundle", f"bundle file path must be relative POSIX: {rel_path!r}")
        parts = pathlib.PurePosixPath(norm).parts
        if any(p in ("", ".", "..") for p in parts):
            raise FriendsError("invalid_bundle", f"unsafe bundle file path: {rel_path!r}")
        if not isinstance(content, str):
            raise FriendsError("invalid_bundle", f"bundle file content must be UTF-8 text: {rel_path!r}")
        cleaned[norm] = content
    return cleaned


def compute_bundle_revision_hash(
    bundle_name: str,
    files: dict[str, str],
    *,
    bundle_kind: str = "skill",
    metadata: dict | None = None,
) -> str:
    """Compute canonical `sha256:<hex>` revision hash for a capability bundle."""
    if not isinstance(bundle_name, str) or not BUNDLE_NAME_RE.fullmatch(bundle_name):
        raise FriendsError("invalid_bundle", f"malformed bundle_name: {bundle_name!r}")
    if bundle_kind not in KNOWN_BUNDLE_KINDS:
        raise FriendsError(
            "invalid_bundle",
            f"bundle_kind must be one of {', '.join(KNOWN_BUNDLE_KINDS)}",
        )
    if metadata is not None and not isinstance(metadata, dict):
        raise FriendsError("invalid_bundle", "bundle metadata must be a JSON object")
    cleaned_files = _validate_bundle_files(files)
    canonical_payload = {
        "format_version": BUNDLE_FORMAT_VERSION,
        "bundle_name": bundle_name,
        "bundle_kind": bundle_kind,
        "files": cleaned_files,
        "metadata": metadata or {},
    }
    digest = hashlib.sha256(canonical_json_bytes(canonical_payload)).hexdigest()
    return f"sha256:{digest}"


def load_files_from_directory(directory: str | pathlib.Path) -> dict[str, str]:
    """Read all regular UTF-8 files under a directory into a relative-path map."""
    root = pathlib.Path(directory).expanduser().resolve()
    if not root.is_dir():
        raise FriendsError("invalid_bundle", f"bundle directory not found: {directory}")
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            try:
                files[rel] = path.read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                raise FriendsError(
                    "invalid_bundle", f"bundle file is not valid UTF-8: {rel}"
                ) from exc
    if not files:
        raise FriendsError("invalid_bundle", f"bundle directory contains no files: {directory}")
    return files


def package_capability_bundle(
    private_key: Ed25519PrivateKey,
    *,
    sender_mail: str,
    bundle_name: str,
    files: dict[str, str],
    bundle_kind: str = "skill",
    metadata: dict | None = None,
    recipient_mail: str | None = None,
    timestamp: datetime | None = None,
) -> dict:
    """Package and sign a capability bundle as a `muse-mail-envelope-v1` attachment."""
    cleaned_files = _validate_bundle_files(files)
    revision_hash = compute_bundle_revision_hash(
        bundle_name, cleaned_files, bundle_kind=bundle_kind, metadata=metadata
    )
    payload = {
        "format_version": BUNDLE_FORMAT_VERSION,
        "bundle_name": bundle_name,
        "bundle_kind": bundle_kind,
        "revision_hash": revision_hash,
        "files": cleaned_files,
        "metadata": metadata or {},
    }
    return sign_mail_envelope(
        private_key,
        sender_mail=sender_mail,
        recipient_mail=recipient_mail,
        kind="capability_bundle",
        payload=payload,
        timestamp=timestamp,
    )


def verify_capability_bundle(
    store: Store,
    *,
    sender_mail: str,
    envelope: dict,
    friend_id: str | None = None,
    direction: str = "inbound",
) -> dict:
    """Verify a signed capability bundle attachment against friend registry and pins."""
    if direction not in KNOWN_PIN_DIRECTIONS:
        raise FriendsError(
            "invalid_request",
            f"direction must be one of {', '.join(KNOWN_PIN_DIRECTIONS)}",
        )

    def _reject(
        code: str,
        reason: str,
        *,
        mail_verdict: dict | None = None,
        bundle_name: str | None = None,
        bundle_kind: str | None = None,
        revision_hash: str | None = None,
        pinned_revision_hash: str | None = None,
        needs_owner_pin: bool = False,
    ) -> dict:
        return {
            "accepted": False,
            "code": code,
            "reason": reason,
            "friend_id": mail_verdict["friend_id"] if mail_verdict else friend_id,
            "handle": mail_verdict["handle"] if mail_verdict else None,
            "mail_address": mail_verdict["mail_address"] if mail_verdict else None,
            "tier": mail_verdict["tier"] if mail_verdict else None,
            "bundle_name": bundle_name,
            "bundle_kind": bundle_kind,
            "revision_hash": revision_hash,
            "pinned_revision_hash": pinned_revision_hash,
            "needs_owner_pin": needs_owner_pin,
        }

    # 1. Verify envelope signature, sender mail_address, and pinned friend key.
    mail_verdict = verify_incoming_mail(
        store,
        sender_mail=sender_mail,
        envelope=envelope,
        friend_id=friend_id,
    )
    if not mail_verdict["accepted"]:
        return _reject(
            mail_verdict["code"],
            mail_verdict["reason"],
            mail_verdict=mail_verdict,
        )

    # 2. Validate bundle envelope kind and payload integrity.
    if envelope.get("kind") != "capability_bundle":
        return _reject(
            "invalid_bundle",
            f"expected envelope kind 'capability_bundle', got {envelope.get('kind')!r}",
            mail_verdict=mail_verdict,
        )

    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return _reject("invalid_bundle", "bundle payload must be a JSON object", mail_verdict=mail_verdict)

    bundle_name = payload.get("bundle_name")
    bundle_kind = payload.get("bundle_kind", "skill")
    claimed_hash = payload.get("revision_hash")
    files = payload.get("files")
    metadata = payload.get("metadata") or {}

    try:
        recomputed = compute_bundle_revision_hash(
            bundle_name, files, bundle_kind=bundle_kind, metadata=metadata
        )
    except FriendsError as exc:
        return _reject(
            exc.code,
            exc.message,
            mail_verdict=mail_verdict,
            bundle_name=bundle_name if isinstance(bundle_name, str) else None,
            bundle_kind=bundle_kind if isinstance(bundle_kind, str) else None,
        )

    if not isinstance(claimed_hash, str) or not hmac.compare_digest(
        claimed_hash.lower(), recomputed.lower()
    ):
        return _reject(
            "revision_hash_mismatch",
            f"bundle revision_hash '{claimed_hash}' does not match computed hash '{recomputed}'",
            mail_verdict=mail_verdict,
            bundle_name=bundle_name,
            bundle_kind=bundle_kind,
            revision_hash=recomputed,
        )

    # 3. Check friend_capability_pins for an exact pinned revision hash.
    pin_row = store.tx().execute(
        "SELECT revision_hash FROM friend_capability_pins"
        " WHERE friend_id=? AND bundle_name=? AND direction=?",
        (mail_verdict["friend_id"], bundle_name, direction),
    ).fetchone()

    if pin_row is None:
        return _reject(
            "bundle_not_pinned",
            f"bundle '{bundle_name}' ({recomputed}) is not pinned for friend '{mail_verdict['handle']}'; owner approval required to pin",
            mail_verdict=mail_verdict,
            bundle_name=bundle_name,
            bundle_kind=bundle_kind,
            revision_hash=recomputed,
            pinned_revision_hash=None,
            needs_owner_pin=True,
        )

    pinned_hash = pin_row["revision_hash"].lower()
    if not hmac.compare_digest(pinned_hash, recomputed.lower()):
        return _reject(
            "pin_mismatch",
            f"bundle '{bundle_name}' revision '{recomputed}' does not match pinned revision '{pinned_hash}'; owner approval required to update pin",
            mail_verdict=mail_verdict,
            bundle_name=bundle_name,
            bundle_kind=bundle_kind,
            revision_hash=recomputed,
            pinned_revision_hash=pinned_hash,
            needs_owner_pin=True,
        )

    return {
        "accepted": True,
        "code": "ok",
        "reason": "bundle signature, sender, pinned key, and pinned revision hash verified",
        "friend_id": mail_verdict["friend_id"],
        "handle": mail_verdict["handle"],
        "mail_address": mail_verdict["mail_address"],
        "tier": mail_verdict["tier"],
        "bundle_name": bundle_name,
        "bundle_kind": bundle_kind,
        "revision_hash": recomputed,
        "pinned_revision_hash": pinned_hash,
        "needs_owner_pin": False,
        "files": list(files.keys()),
    }
