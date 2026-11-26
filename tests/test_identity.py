"""Tests for Ed25519 identity generation, friend cards, and HTTP/CLI card flows."""
from __future__ import annotations

import base64
import json
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient

from musefriends.app import create_app
from musefriends.cli import run_cli
from musefriends.errors import FriendsError
from musefriends.identity import (
    IdentityManager,
    PRIVATE_KEY_FILENAME,
    key_fingerprint,
    sign_card,
    verify_card,
)
from musefriends.store import Store


def test_store_pragmas_and_permissions(tmp_path):
    state_dir = tmp_path / "state"
    store = Store(state_dir)
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert store.conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    # synchronous=FULL is 2 in SQLite
    assert store.conn.execute("PRAGMA synchronous").fetchone()[0] == 2
    assert store.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert store.schema_version == 4


def test_identity_generation_and_card_roundtrip(tmp_path):
    store = Store(tmp_path / "alice")
    mgr = IdentityManager(store)

    card = mgr.init_identity(
        handle="alice",
        display_name="Alice's Muse",
        url="https://alice.example.invalid",
    )

    key_path = store.state_dir / PRIVATE_KEY_FILENAME
    assert key_path.exists()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

    assert card["version"] == 1
    assert card["handle"] == "alice"
    assert card["display_name"] == "Alice's Muse"
    assert card["url"] == "https://alice.example.invalid"
    assert card["friend_api"] == "https://alice.example.invalid/friends/v1"
    assert card["public_key"].startswith("ed25519:")
    assert card["protocols"] == [1]
    assert "signature" in card

    # Safety number format: 8 groups of 4 uppercase hex chars.
    fp = key_fingerprint(card["public_key"])
    parts = fp.split(" ")
    assert len(parts) == 8
    assert all(len(p) == 4 and all(c in "0123456789ABCDEF" for c in p) for p in parts)

    # Export and import round-trip verifies signature and fingerprint.
    exported = mgr.export_card_json()
    imported = mgr.import_card(exported)
    assert imported["card"] == card
    assert imported["fingerprint"] == fp

    # Second init without overwrite fails; with overwrite archives prior card.
    with pytest.raises(FriendsError) as exc_info:
        mgr.init_identity(
            handle="alice",
            display_name="Alice's Muse",
            url="https://alice.example.invalid",
        )
    assert exc_info.value.code == "already_initialized"

    rotated = mgr.init_identity(
        handle="alice",
        display_name="Alice's Muse v2",
        url="https://alice.example.invalid",
        overwrite=True,
    )
    assert rotated["public_key"] != card["public_key"]
    history = json.loads(mgr.get_row()["card_history_json"])
    assert len(history) == 1
    assert history[0]["public_key"] == card["public_key"]


def test_card_signature_verification_rejects_tampering(tmp_path):
    store = Store(tmp_path / "alice")
    mgr = IdentityManager(store)
    card = mgr.init_identity(
        handle="alice",
        display_name="Alice's Muse",
        url="https://alice.example.invalid",
    )

    # Tampered handle
    bad_handle = dict(card, handle="mallory")
    with pytest.raises(FriendsError) as exc:
        verify_card(bad_handle)
    assert exc.value.code == "invalid_signature"

    # Tampered friend_api
    bad_api = dict(card, friend_api="https://evil.example.invalid/friends/v1")
    with pytest.raises(FriendsError) as exc:
        verify_card(bad_api)
    assert exc.value.code == "invalid_signature"

    # Missing signature
    unsigned = {k: v for k, v in card.items() if k != "signature"}
    with pytest.raises(FriendsError) as exc:
        verify_card(unsigned, require_signature=True)
    assert exc.value.code == "invalid_signature"

    # Signed by a different key than card.public_key
    other_key = Ed25519PrivateKey.generate()
    with pytest.raises(FriendsError) as exc:
        sign_card(unsigned, other_key)
    assert exc.value.code == "invalid_key"

    # Corrupted signature bytes
    bad_sig = dict(card, signature=base64.b64encode(b"\x00" * 64).decode("ascii"))
    with pytest.raises(FriendsError) as exc:
        verify_card(bad_sig)
    assert exc.value.code == "invalid_signature"


def test_http_card_endpoints_and_health(tmp_path):
    state_dir = tmp_path / "daemon"
    app = create_app(state_dir)
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["initialized"] is False

        # Before init, card endpoints return 503.
        assert client.get("/friends/v1/card").status_code == 503
        assert client.get("/.well-known/muse-friend.json").status_code == 503

        card = app.state.identity.init_identity(
            handle="alice",
            display_name="Alice's Muse",
            url="https://alice.example.invalid",
        )

        assert client.get("/health").json()["initialized"] is True
        r1 = client.get("/friends/v1/card")
        r2 = client.get("/.well-known/muse-friend.json")
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json() == card
        assert r2.json() == card
        verify_card(r1.json())


def test_cli_identity_and_card_export_import(tmp_path, capsys):
    alice_dir = tmp_path / "alice"
    bob_dir = tmp_path / "bob"
    card_file = tmp_path / "alice-card.json"

    assert (
        run_cli(
            [
                "--state-dir",
                str(alice_dir),
                "--json",
                "identity",
                "init",
                "--handle",
                "alice",
                "--display-name",
                "Alice's Muse",
                "--url",
                "https://alice.example.invalid",
            ]
        )
        == 0
    )
    init_out = json.loads(capsys.readouterr().out)
    assert init_out["card"]["handle"] == "alice"

    assert (
        run_cli(
            [
                "--state-dir",
                str(alice_dir),
                "card",
                "export",
                "--out",
                str(card_file),
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert (
        run_cli(
            [
                "--state-dir",
                str(bob_dir),
                "--json",
                "card",
                "import",
                str(card_file),
            ]
        )
        == 0
    )
    imp_out = json.loads(capsys.readouterr().out)
    assert imp_out["card"]["public_key"] == init_out["card"]["public_key"]
    assert imp_out["fingerprint"] == init_out["fingerprint"]

    # Tamper with exported file and confirm CLI import fails with non-zero exit.
    tampered = json.loads(card_file.read_text(encoding="utf-8"))
    tampered["display_name"] = "Impostor"
    card_file.write_text(json.dumps(tampered), encoding="utf-8")
    assert (
        run_cli(["--state-dir", str(bob_dir), "card", "import", str(card_file)]) == 1
    )
    assert "invalid_signature" in capsys.readouterr().err
