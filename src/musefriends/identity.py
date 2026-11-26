"""Ed25519 identity management, signed friend cards, and request signing."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import FriendsError
from .store import Store, now_iso

CARD_VERSION = 1
SUPPORTED_PROTOCOLS = [1]
CARD_SIGNATURE_PREFIX = b"muse-friend-card-v1\n"
PUBKEY_PREFIX = "ed25519:"
HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PRIVATE_KEY_FILENAME = "identity.ed25519.pem"


def canonical_json_bytes(value: dict) -> bytes:
    """Deterministic UTF-8 JSON serialization used for card signing."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def encode_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return PUBKEY_PREFIX + base64.b64encode(raw).decode("ascii")


def decode_public_key(encoded: str) -> Ed25519PublicKey:
    if not isinstance(encoded, str) or not encoded.startswith(PUBKEY_PREFIX):
        raise FriendsError("invalid_key", "public_key must start with 'ed25519:'")
    b64 = encoded[len(PUBKEY_PREFIX) :]
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as exc:
        raise FriendsError("invalid_key", "public_key is not valid base64") from exc
    if len(raw) != 32:
        raise FriendsError("invalid_key", "Ed25519 public_key must be 32 bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise FriendsError("invalid_key", "invalid Ed25519 public_key") from exc


def key_fingerprint(public_key: str) -> str:
    """Canonical safety number: SHA-256(public_key) as 8x4 uppercase hex."""
    decode_public_key(public_key)
    digest = hashlib.sha256(public_key.encode("utf-8")).hexdigest().upper()
    # First 16 bytes (32 hex chars) grouped as 8 groups of 4 hex characters.
    short = digest[:32]
    return " ".join(short[i : i + 4] for i in range(0, 32, 4))


def _validate_url(url: str, field: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise FriendsError("invalid_card", f"{field} must be a non-empty URL")
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise FriendsError("invalid_card", f"{field} must be an http(s) URL with host")
    return url.rstrip("/")


def _unsigned_card_payload(card: dict) -> dict:
    return {k: v for k, v in card.items() if k != "signature"}


def validate_card_structure(card: dict) -> dict:
    """Validate friend card schema fields without checking signature."""
    if not isinstance(card, dict):
        raise FriendsError("invalid_card", "card must be a JSON object")
    if card.get("version") != CARD_VERSION:
        raise FriendsError("invalid_card", f"unsupported card version: {card.get('version')!r}")
    handle = card.get("handle")
    if not isinstance(handle, str) or not HANDLE_RE.fullmatch(handle):
        raise FriendsError("invalid_card", "handle is missing or malformed")
    display_name = card.get("display_name")
    if not isinstance(display_name, str) or not display_name.strip() or len(display_name) > 120:
        raise FriendsError("invalid_card", "display_name is missing or too long")
    _validate_url(card.get("url", ""), "url")
    _validate_url(card.get("friend_api", ""), "friend_api")
    public_key = card.get("public_key")
    decode_public_key(public_key)
    protocols = card.get("protocols")
    if (
        not isinstance(protocols, list)
        or not protocols
        or any(not isinstance(p, int) or isinstance(p, bool) for p in protocols)
        or 1 not in protocols
    ):
        raise FriendsError("invalid_card", "protocols must be a list containing 1")
    issued_at = card.get("issued_at")
    if not isinstance(issued_at, str) or not issued_at:
        raise FriendsError("invalid_card", "issued_at is required")
    try:
        datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FriendsError("invalid_card", "issued_at must be ISO-8601") from exc
    return card


def sign_card(card: dict, private_key: Ed25519PrivateKey) -> dict:
    """Attach a self-signature proving possession of the card's Ed25519 key."""
    validate_card_structure(card)
    expected_pub = encode_public_key(private_key.public_key())
    if card["public_key"] != expected_pub:
        raise FriendsError("invalid_key", "private key does not match card public_key")
    payload = _unsigned_card_payload(card)
    sig = private_key.sign(CARD_SIGNATURE_PREFIX + canonical_json_bytes(payload))
    signed = dict(payload)
    signed["signature"] = base64.b64encode(sig).decode("ascii")
    return signed


def verify_card(card: dict, *, require_signature: bool = True) -> dict:
    """Validate structure and Ed25519 signature of a friend card."""
    validate_card_structure(card)
    signature = card.get("signature")
    if signature is None:
        if require_signature:
            raise FriendsError("invalid_signature", "friend card is missing signature")
        return card
    if not isinstance(signature, str) or not signature:
        raise FriendsError("invalid_signature", "friend card signature is malformed")
    try:
        sig_bytes = base64.b64decode(signature, validate=True)
    except Exception as exc:
        raise FriendsError("invalid_signature", "friend card signature is not valid base64") from exc
    if len(sig_bytes) != 64:
        raise FriendsError("invalid_signature", "Ed25519 signature must be 64 bytes")
    pubkey = decode_public_key(card["public_key"])
    payload = _unsigned_card_payload(card)
    try:
        pubkey.verify(sig_bytes, CARD_SIGNATURE_PREFIX + canonical_json_bytes(payload))
    except InvalidSignature as exc:
        raise FriendsError("invalid_signature", "friend card signature verification failed") from exc
    return card


def signing_message(
    method: str,
    path: str,
    timestamp: int,
    nonce: str,
    body: bytes,
) -> bytes:
    """Canonical HTTP request signing payload."""
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")


def sign_http_request(
    private_key: Ed25519PrivateKey,
    method: str,
    path: str,
    body: bytes,
    timestamp: int,
    nonce: str,
) -> dict[str, str]:
    """Produce request signature headers."""
    pub = encode_public_key(private_key.public_key())
    msg = signing_message(method, path, timestamp, nonce, body)
    sig = base64.b64encode(private_key.sign(msg)).decode("ascii")
    return {
        "X-Muse-Friend-Key": pub,
        "X-Muse-Friend-Timestamp": str(timestamp),
        "X-Muse-Friend-Nonce": nonce,
        "X-Muse-Friend-Signature": sig,
    }


def verify_http_signature(
    public_key: str,
    method: str,
    path: str,
    body: bytes,
    timestamp: int,
    nonce: str,
    signature_b64: str,
) -> None:
    """Verify an Ed25519 request signature against a known public key."""
    if not isinstance(signature_b64, str) or not signature_b64:
        raise FriendsError("unauthorized", "unauthorized", status_code=401)
    try:
        sig_bytes = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise FriendsError("unauthorized", "unauthorized", status_code=401) from exc
    if len(sig_bytes) != 64:
        raise FriendsError("unauthorized", "unauthorized", status_code=401)
    try:
        pubkey = decode_public_key(public_key)
    except FriendsError as exc:
        raise FriendsError("unauthorized", "unauthorized", status_code=401) from exc
    msg = signing_message(method, path, timestamp, nonce, body)
    try:
        pubkey.verify(sig_bytes, msg)
    except InvalidSignature as exc:
        raise FriendsError("unauthorized", "unauthorized", status_code=401) from exc


def write_private_key(path: pathlib.Path, private_key: Ed25519PrivateKey) -> None:
    """Write Ed25519 private key in PKCS#8 PEM with strict 0600 permissions."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def load_private_key(path: pathlib.Path) -> Ed25519PrivateKey:
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise FriendsError("invalid_key", "stored key is not Ed25519")
    return key


class IdentityManager:
    """Owns the daemon's singleton Ed25519 identity and signed friend card."""

    def __init__(self, store: Store):
        self.store = store

    def get_row(self):
        return self.store.tx().execute("SELECT * FROM identity WHERE id=1").fetchone()

    def is_initialized(self) -> bool:
        return self.get_row() is not None

    def init_identity(
        self,
        handle: str,
        display_name: str,
        url: str,
        friend_api: str | None = None,
        *,
        overwrite: bool = False,
        now: datetime | None = None,
    ) -> dict:
        """Create (or update metadata on) the daemon's Ed25519 identity and card."""
        if not isinstance(handle, str) or not HANDLE_RE.fullmatch(handle):
            raise FriendsError("invalid_card", "handle is missing or malformed")
        if not isinstance(display_name, str) or not display_name.strip():
            raise FriendsError("invalid_card", "display_name is required")
        base_url = _validate_url(url, "url")
        api_url = _validate_url(friend_api or f"{base_url}/friends/v1", "friend_api")

        existing = self.get_row()
        if existing is not None and not overwrite:
            raise FriendsError("already_initialized", "identity is already initialized")

        key_path = self.store.state_dir / PRIVATE_KEY_FILENAME
        private_key = Ed25519PrivateKey.generate()
        write_private_key(key_path, private_key)

        pub = encode_public_key(private_key.public_key())
        fp = key_fingerprint(pub)
        issued = now_iso(now)
        card = sign_card(
            {
                "version": CARD_VERSION,
                "handle": handle,
                "display_name": display_name.strip(),
                "url": base_url,
                "friend_api": api_url,
                "public_key": pub,
                "protocols": list(SUPPORTED_PROTOCOLS),
                "issued_at": issued,
            },
            private_key,
        )
        card_json = canonical_json_bytes(card).decode("utf-8")

        with self.store.transaction():
            history: list[dict] = []
            if existing is not None:
                history = json.loads(existing["card_history_json"])
                history.append(json.loads(existing["current_card_json"]))
                self.store.tx().execute(
                    "UPDATE identity SET private_key_path=?, public_key=?, fingerprint=?,"
                    " current_card_json=?, card_history_json=?, updated_at=? WHERE id=1",
                    (
                        str(key_path),
                        pub,
                        fp,
                        card_json,
                        json.dumps(history, sort_keys=True),
                        issued,
                    ),
                )
            else:
                self.store.tx().execute(
                    "INSERT INTO identity (id, private_key_path, public_key, fingerprint,"
                    " current_card_json, card_history_json, created_at, updated_at)"
                    " VALUES (1, ?, ?, ?, ?, '[]', ?, ?)",
                    (str(key_path), pub, fp, card_json, issued, issued),
                )
            self.store.audit(
                "owner",
                "identity_initialized",
                {"handle": handle, "fingerprint": fp},
                now=now,
            )
        return card

    def load_private_key(self) -> Ed25519PrivateKey:
        row = self.get_row()
        if row is None:
            raise FriendsError("not_initialized", "identity has not been initialized", status_code=503)
        return load_private_key(pathlib.Path(row["private_key_path"]))

    def current_card(self) -> dict:
        row = self.get_row()
        if row is None:
            raise FriendsError("not_initialized", "identity has not been initialized", status_code=503)
        return json.loads(row["current_card_json"])

    def export_card_json(self, *, indent: int = 2) -> str:
        card = self.current_card()
        return json.dumps(card, indent=indent, sort_keys=True)

    def import_card(
        self,
        raw_json: str | dict,
        *,
        require_signature: bool = True,
    ) -> dict:
        """Parse and cryptographically verify an imported friend card."""
        if isinstance(raw_json, str):
            try:
                card = json.loads(raw_json)
            except ValueError as exc:
                raise FriendsError("invalid_card", "card is not valid JSON") from exc
        else:
            card = raw_json
        verified = verify_card(card, require_signature=require_signature)
        return {
            "card": verified,
            "fingerprint": key_fingerprint(verified["public_key"]),
        }
