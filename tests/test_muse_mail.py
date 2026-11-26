"""Tests for Muse Mail binding: migration 003, incoming card/envelope verification,
mail-confirmed pairing completion, capability-bundle pins, and policy evaluation."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from musefriends import migrate
from musefriends.cli import run_cli
from musefriends.errors import FriendsError
from musefriends.identity import IdentityManager
from musefriends.mail import (
    complete_mail_pairing,
    list_capability_pins,
    pin_capability_bundle,
    sign_mail_envelope,
    verify_incoming_mail,
)
from musefriends.pairing import CODE_TTL_S, MAX_CODE_ATTEMPTS, PairingManager
from musefriends.policy import evaluate_policy
from musefriends.store import Store


def _init_peer(tmp_path, name: str):
    store = Store(tmp_path / name)
    identity = IdentityManager(store)
    card = identity.init_identity(
        handle=name,
        display_name=f"{name.title()}'s Muse",
        url=f"https://{name}.example.invalid",
    )
    key = identity.load_private_key()
    mail = f"{name}.muse@example.invalid"
    return store, identity, card, key, mail


def _pair_bob_with_alice(
    tmp_path,
    *,
    tier: str = "friend",
    discretion: str = "",
    verified: bool = False,
    now: datetime | None = None,
):
    ts = now or datetime(2026, 11, 26, 15, 0, 0, tzinfo=timezone.utc)
    alice_store, alice_id, _alice_card, _alice_key, alice_mail = _init_peer(tmp_path, "alice")
    _bob_store, _bob_id, bob_card, bob_key, bob_mail = _init_peer(tmp_path, "bob")

    pairing = PairingManager(alice_store, alice_id)
    minted = pairing.mint_code(now=ts)
    conf = sign_mail_envelope(
        bob_key,
        sender_mail=bob_mail,
        recipient_mail=alice_mail,
        kind="pairing_confirmation",
        payload={"code": minted["code"], "card": bob_card},
        timestamp=ts,
    )
    paired = complete_mail_pairing(
        alice_store,
        alice_id,
        confirmation_envelope=conf,
        sender_mail=bob_mail,
        owner_approved=True,
        tier=tier,
        discretion_profile=discretion,
        now=ts,
    )
    if verified:
        pairing.verify_friend(paired["friend_id"], now=ts)
    return alice_store, alice_id, pairing, paired, bob_card, bob_key, bob_mail, alice_mail


# -- 1. Migration 003 on top of schema v1 ------------------------------------
def test_migration_003_applies_cleanly_over_schema_v1(tmp_path):
    state_dir = tmp_path / "upgrade"
    state_dir.mkdir(mode=0o700)
    db_path = state_dir / "friends.db"

    # Build a v1 database using only 001_initial.sql and seed a pre-existing friend.
    mig_001 = pathlib.Path(migrate.MIGRATIONS_DIR) / "001_initial.sql"
    sql_001 = mig_001.read_text(encoding="utf-8")
    checksum_001 = hashlib.sha256(sql_001.encode("utf-8")).hexdigest()

    conn = sqlite3.connect(str(db_path))
    conn.isolation_level = None
    conn.executescript(
        "CREATE TABLE schema_migrations ("
        "version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL);\n"
        + sql_001
    )
    conn.execute(
        "INSERT INTO schema_migrations (version, checksum, applied_at) VALUES (1, ?, '2026-11-26T00:00:00Z')",
        (checksum_001,),
    )
    conn.execute(
        "INSERT INTO friends (id, public_key, fingerprint, handle, display_name, card_json,"
        " tier, verified, discretion_profile, state, created_at, updated_at)"
        " VALUES ('f1', 'ed25519:AAAA', '0000 0000 0000 0000 0000 0000 0000 0000',"
        " 'legacy', 'Legacy Muse', '{}', 'acquaintance', 0, '', 'active',"
        " '2026-11-26T00:00:00Z', '2026-11-26T00:00:00Z')"
    )
    conn.close()

    # Opening Store applies 003_muse_mail.sql and 004_mail_threads.sql, skipping parked 002.
    store = Store(state_dir, db_path=db_path)
    assert store.schema_version == 4
    versions = [
        r["version"]
        for r in store.conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    ]
    assert versions == [1, 3, 4]

    # Existing friend row survives with mail_address NULL.
    legacy = store.conn.execute("SELECT mail_address FROM friends WHERE id='f1'").fetchone()
    assert legacy["mail_address"] is None

    # Unique non-null mail_address enforced; multiple NULLs allowed.
    store.conn.execute(
        "INSERT INTO friends (id, public_key, fingerprint, handle, display_name, card_json,"
        " mail_address, tier, verified, discretion_profile, state, created_at, updated_at)"
        " VALUES ('f2', 'ed25519:BBBB', '1111 1111 1111 1111 1111 1111 1111 1111',"
        " 'null2', 'Null Two', '{}', NULL, 'acquaintance', 0, '', 'active',"
        " '2026-11-26T00:00:00Z', '2026-11-26T00:00:00Z')"
    )
    store.conn.execute("UPDATE friends SET mail_address='bob.muse@example.invalid' WHERE id='f1'")
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute(
            "UPDATE friends SET mail_address='bob.muse@example.invalid' WHERE id='f2'"
        )

    # Parked 002 tables must not exist.
    tables = {
        r["name"]
        for r in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "friend_capability_pins" in tables
    assert "idempotency_keys" not in tables


# -- 2. Signed incoming friend card / mail envelope verification --------------
def test_verify_incoming_mail_accepts_genuine_and_rejects_mismatches(tmp_path):
    ts = datetime(2026, 11, 26, 15, 0, 0, tzinfo=timezone.utc)
    alice_store, _alice_id, pairing, paired, bob_card, bob_key, bob_mail, alice_mail = (
        _pair_bob_with_alice(tmp_path, now=ts)
    )
    _eve_store, _eve_id, eve_card, eve_key, eve_mail = _init_peer(tmp_path, "eve")

    # Genuine signed mail envelope -> accept.
    genuine_env = sign_mail_envelope(
        bob_key,
        sender_mail=bob_mail,
        recipient_mail=alice_mail,
        kind="message",
        payload={"subject": "Hi", "body": "Hello from Bob"},
        timestamp=ts,
    )
    res_env = verify_incoming_mail(alice_store, sender_mail=bob_mail, envelope=genuine_env)
    assert res_env["accepted"] is True
    assert res_env["code"] == "ok"
    assert res_env["friend_id"] == paired["friend_id"]

    # Genuine signed friend card -> accept.
    res_card = verify_incoming_mail(alice_store, sender_mail=bob_mail, card=bob_card)
    assert res_card["accepted"] is True
    assert res_card["code"] == "ok"

    # Tampered envelope payload -> reject invalid_signature.
    tampered_env = dict(genuine_env, payload={"subject": "Hi", "body": "Tampered"})
    res_tampered_env = verify_incoming_mail(alice_store, sender_mail=bob_mail, envelope=tampered_env)
    assert res_tampered_env["accepted"] is False
    assert res_tampered_env["code"] == "invalid_signature"

    # Tampered friend card -> reject invalid_signature.
    tampered_card = dict(bob_card, display_name="Mallory")
    res_tampered_card = verify_incoming_mail(alice_store, sender_mail=bob_mail, card=tampered_card)
    assert res_tampered_card["accepted"] is False
    assert res_tampered_card["code"] == "invalid_signature"

    # Wrong transport sender for Bob's signed card -> reject sender_mismatch.
    res_wrong_sender = verify_incoming_mail(alice_store, sender_mail=eve_mail, card=bob_card)
    assert res_wrong_sender["accepted"] is False
    assert res_wrong_sender["code"] == "sender_mismatch"

    # Envelope sender_mail disagrees with transport sender -> reject sender_mismatch.
    res_hdr_mismatch = verify_incoming_mail(alice_store, sender_mail=eve_mail, envelope=genuine_env)
    assert res_hdr_mismatch["accepted"] is False
    assert res_hdr_mismatch["code"] == "sender_mismatch"

    # Wrong key (Eve signs an envelope claiming Bob's mail_address) -> reject key_mismatch.
    impersonated_env = sign_mail_envelope(
        eve_key,
        sender_mail=bob_mail,
        recipient_mail=alice_mail,
        kind="message",
        payload={"body": "Not really Bob"},
        timestamp=ts,
    )
    res_wrong_key = verify_incoming_mail(alice_store, sender_mail=bob_mail, envelope=impersonated_env)
    assert res_wrong_key["accepted"] is False
    assert res_wrong_key["code"] == "key_mismatch"

    # Wrong key on card checked against Bob's sender_mail -> reject key_mismatch.
    res_wrong_card_key = verify_incoming_mail(alice_store, sender_mail=bob_mail, card=eve_card)
    assert res_wrong_card_key["accepted"] is False
    assert res_wrong_card_key["code"] == "key_mismatch"

    # Revoked friend -> reject friend_not_active.
    pairing.revoke_friend(paired["friend_id"], now=ts)
    res_revoked = verify_incoming_mail(alice_store, sender_mail=bob_mail, envelope=genuine_env)
    assert res_revoked["accepted"] is False
    assert res_revoked["code"] == "friend_not_active"


# -- 3. Mail-confirmed pairing completion & refusals --------------------------
def test_mail_pairing_completion_happy_path_and_refusals(tmp_path):
    ts = datetime(2026, 11, 26, 15, 0, 0, tzinfo=timezone.utc)
    alice_store, alice_id, _alice_card, _alice_key, alice_mail = _init_peer(tmp_path, "alice")
    _bob_store, _bob_id, bob_card, bob_key, bob_mail = _init_peer(tmp_path, "bob")
    pairing = PairingManager(alice_store, alice_id)

    minted = pairing.mint_code(now=ts)
    good_env = sign_mail_envelope(
        bob_key,
        sender_mail=bob_mail,
        recipient_mail=alice_mail,
        kind="pairing_confirmation",
        payload={"code": minted["code"], "card": bob_card},
        timestamp=ts,
    )

    # 1. Refused without local owner approval; code stays minted, no friend created.
    with pytest.raises(FriendsError) as exc:
        complete_mail_pairing(
            alice_store,
            alice_id,
            confirmation_envelope=good_env,
            sender_mail=bob_mail,
            owner_approved=False,
            now=ts,
        )
    assert exc.value.code == "owner_approval_required"
    assert pairing.list_friends() == []

    # 2. Code mismatch increments attempts; 5 mismatches exhaust the code.
    for i in range(MAX_CODE_ATTEMPTS):
        bad_env = sign_mail_envelope(
            bob_key,
            sender_mail=bob_mail,
            recipient_mail=alice_mail,
            kind="pairing_confirmation",
            payload={"code": f"1111-222{i + 1}", "card": bob_card},
            timestamp=ts,
        )
        with pytest.raises(FriendsError) as exc:
            complete_mail_pairing(
                alice_store,
                alice_id,
                confirmation_envelope=bad_env,
                sender_mail=bob_mail,
                owner_approved=True,
                code_id=minted["code_id"],
                now=ts,
            )
        assert exc.value.code == "code_mismatch"

    # Now even the real code fails with pairing_exhausted.
    with pytest.raises(FriendsError) as exc:
        complete_mail_pairing(
            alice_store,
            alice_id,
            confirmation_envelope=good_env,
            sender_mail=bob_mail,
            owner_approved=True,
            code_id=minted["code_id"],
            now=ts,
        )
    assert exc.value.code == "pairing_exhausted"

    # 3. Expired code (> 15 minutes) is refused with pairing_expired.
    minted_exp = pairing.mint_code(now=ts)
    exp_env = sign_mail_envelope(
        bob_key,
        sender_mail=bob_mail,
        recipient_mail=alice_mail,
        kind="pairing_confirmation",
        payload={"code": minted_exp["code"], "card": bob_card},
        timestamp=ts + timedelta(seconds=CODE_TTL_S + 1),
    )
    with pytest.raises(FriendsError) as exc:
        complete_mail_pairing(
            alice_store,
            alice_id,
            confirmation_envelope=exp_env,
            sender_mail=bob_mail,
            owner_approved=True,
            code_id=minted_exp["code_id"],
            now=ts + timedelta(seconds=CODE_TTL_S + 1),
        )
    assert exc.value.code == "pairing_expired"

    # 4. Happy path completes pairing and binds mail_address + key + tier + discretion.
    live = pairing.mint_code(now=ts)
    live_env = sign_mail_envelope(
        bob_key,
        sender_mail=bob_mail,
        recipient_mail=alice_mail,
        kind="pairing_confirmation",
        payload={"code": live["code"].lower().replace("-", ""), "card": bob_card},
        timestamp=ts,
    )
    res = complete_mail_pairing(
        alice_store,
        alice_id,
        confirmation_envelope=live_env,
        sender_mail=bob_mail,
        owner_approved=True,
        tier="friend",
        discretion_profile="topics:music,books",
        now=ts,
    )
    assert res["status"] == "paired"
    assert res["mail_address"] == bob_mail
    assert res["public_key"] == bob_card["public_key"]
    assert res["tier"] == "friend"

    # Reusing the consumed code is refused.
    with pytest.raises(FriendsError) as exc:
        complete_mail_pairing(
            alice_store,
            alice_id,
            confirmation_envelope=live_env,
            sender_mail=bob_mail,
            owner_approved=True,
            code_id=live["code_id"],
            now=ts,
        )
    assert exc.value.code == "invalid_state"

    # Pin capability bundle revision hashes on the paired friend.
    pin1 = pin_capability_bundle(
        alice_store,
        friend_id=res["friend_id"],
        bundle_name="weather-lookup",
        revision_hash="sha256:0123456789abcdef0123456789abcdef",
        direction="inbound",
        now=ts,
    )
    assert pin1["bundle_name"] == "weather-lookup"
    # Updating same (friend, bundle, direction) updates revision hash in place.
    pin2 = pin_capability_bundle(
        alice_store,
        friend_id=res["friend_id"],
        bundle_name="weather-lookup",
        revision_hash="sha256:fedcba9876543210fedcba9876543210",
        direction="inbound",
        now=ts,
    )
    assert pin2["pin_id"] == pin1["pin_id"]
    pins = list_capability_pins(alice_store, friend_id=res["friend_id"])
    assert len(pins) == 1
    assert pins[0]["revision_hash"] == "sha256:fedcba9876543210fedcba9876543210"


# -- 4. Policy matrix across tiers and discretion profiles --------------------
@pytest.mark.parametrize(
    "tier,verified,discretion,kwargs,expected_decision",
    [
        # Acquaintance tier
        ("acquaintance", False, "", {"action": "send_message"}, "allow"),
        ("acquaintance", False, "", {"action": "act_on_request", "request_kind": "question"}, "allow"),
        ("acquaintance", False, "", {"action": "act_on_request", "request_kind": "question", "sensitive": True}, "needs_owner_approval"),
        ("acquaintance", False, "", {"action": "act_on_request", "request_kind": "command"}, "deny"),
        ("acquaintance", False, "", {"action": "act_on_request", "request_kind": "delegation"}, "deny"),
        ("acquaintance", False, "", {"action": "share_capability_bundle"}, "deny"),
        # Friend tier
        ("friend", False, "", {"action": "send_message"}, "allow"),
        ("friend", False, "", {"action": "act_on_request", "request_kind": "command"}, "allow"),
        ("friend", False, "", {"action": "act_on_request", "request_kind": "command", "external_side_effects": True}, "needs_owner_approval"),
        ("friend", False, "", {"action": "act_on_request", "request_kind": "delegation"}, "needs_owner_approval"),
        ("friend", False, "allow:delegation", {"action": "act_on_request", "request_kind": "delegation"}, "allow"),
        ("friend", False, "", {"action": "share_capability_bundle"}, "needs_owner_approval"),
        ("friend", False, "allow:share_capability_bundle", {"action": "share_capability_bundle"}, "allow"),
        # Inner tier (unverified vs verified safety number)
        ("inner", False, "", {"action": "act_on_request", "request_kind": "delegation"}, "allow"),
        ("inner", False, "", {"action": "act_on_request", "request_kind": "delegation", "external_side_effects": True}, "needs_owner_approval"),
        ("inner", True, "", {"action": "act_on_request", "request_kind": "delegation", "external_side_effects": True}, "allow"),
        ("inner", False, "", {"action": "share_capability_bundle"}, "allow"),
        ("inner", False, "", {"action": "share_capability_bundle", "external_side_effects": True}, "needs_owner_approval"),
        ("inner", True, "", {"action": "share_capability_bundle", "external_side_effects": True}, "allow"),
        # Discretion rules & deny-leaning defaults (§7.2)
        ("inner", True, "", {"action": "send_message", "touches_private_data": True}, "deny"),
        ("inner", True, "allow:private_data", {"action": "send_message", "touches_private_data": True}, "allow"),
        ("friend", False, "", {"action": "send_message", "topics": ["finances"]}, "deny"),
        ("friend", False, "allow:finances", {"action": "send_message", "topics": ["finances"]}, "allow"),
        ("inner", True, "deny:all", {"action": "send_message"}, "deny"),
        ("inner", True, "escalate:all", {"action": "send_message"}, "needs_owner_approval"),
        ("friend", False, "deny:travel", {"action": "send_message", "topics": ["travel"]}, "deny"),
        ("friend", False, "escalate:calendar", {"action": "act_on_request", "request_kind": "question", "topics": ["calendar"]}, "needs_owner_approval"),
        ("friend", False, "topics:music,books", {"action": "send_message", "topics": ["music"]}, "allow"),
        ("friend", False, "topics:music,books", {"action": "send_message", "topics": ["work"]}, "needs_owner_approval"),
    ],
)
def test_policy_matrix(tmp_path, tier, verified, discretion, kwargs, expected_decision):
    alice_store, _alice_id, _pairing, paired, _bob_card, _bob_key, _bob_mail, _alice_mail = (
        _pair_bob_with_alice(tmp_path, tier=tier, discretion=discretion, verified=verified)
    )
    res = evaluate_policy(alice_store, friend_id=paired["friend_id"], **kwargs)
    assert res["decision"] == expected_decision
    assert res["reason"]


def test_policy_denies_revoked_and_unknown_friends(tmp_path):
    alice_store, _alice_id, pairing, paired, _bob_card, _bob_key, bob_mail, _alice_mail = (
        _pair_bob_with_alice(tmp_path, tier="inner", verified=True)
    )
    assert evaluate_policy(alice_store, mail_address="nobody@example.invalid", action="send_message")["decision"] == "deny"

    pairing.revoke_friend(paired["friend_id"])
    res = evaluate_policy(alice_store, mail_address=bob_mail, action="send_message")
    assert res["decision"] == "deny"
    assert res["code"] == "friend_revoked"


# -- 5. Local CLI end-to-end --------------------------------------------------
def test_cli_mail_pairing_verify_pin_and_policy(tmp_path, capsys):
    alice_dir = tmp_path / "alice"
    bob_dir = tmp_path / "bob"
    bob_mail = "bob.muse@example.invalid"
    alice_mail = "alice.muse@example.invalid"

    assert run_cli(["--state-dir", str(alice_dir), "--json", "identity", "init", "--handle", "alice", "--display-name", "Alice's Muse", "--url", "https://alice.example.invalid"]) == 0
    capsys.readouterr()
    assert run_cli(["--state-dir", str(bob_dir), "--json", "identity", "init", "--handle", "bob", "--display-name", "Bob's Muse", "--url", "https://bob.example.invalid"]) == 0
    bob_init = json.loads(capsys.readouterr().out)

    # Alice mints a pairing code.
    assert run_cli(["--state-dir", str(alice_dir), "--json", "pair", "mint"]) == 0
    minted = json.loads(capsys.readouterr().out)

    # Bob signs a pairing_confirmation mail envelope via CLI.
    payload_file = tmp_path / "pair_payload.json"
    payload_file.write_text(
        json.dumps({"code": minted["code"], "card": bob_init["card"]}),
        encoding="utf-8",
    )
    conf_file = tmp_path / "conf_env.json"
    assert (
        run_cli(
            [
                "--state-dir",
                str(bob_dir),
                "mail",
                "sign",
                "--sender-mail",
                bob_mail,
                "--recipient-mail",
                alice_mail,
                "--kind",
                "pairing_confirmation",
                "--payload",
                f"@{payload_file}",
                "--out",
                str(conf_file),
            ]
        )
        == 0
    )
    capsys.readouterr()

    # Without --owner-approve, CLI refuses.
    assert (
        run_cli(
            [
                "--state-dir",
                str(alice_dir),
                "mail",
                "complete-pairing",
                "--sender-mail",
                bob_mail,
                "--envelope",
                str(conf_file),
            ]
        )
        == 1
    )
    assert "owner_approval_required" in capsys.readouterr().err

    # With --owner-approve, CLI completes pairing.
    assert (
        run_cli(
            [
                "--state-dir",
                str(alice_dir),
                "--json",
                "mail",
                "complete-pairing",
                "--sender-mail",
                bob_mail,
                "--envelope",
                str(conf_file),
                "--owner-approve",
                "--tier",
                "friend",
                "--discretion",
                "topics:music",
            ]
        )
        == 0
    )
    paired = json.loads(capsys.readouterr().out)
    friend_id = paired["friend_id"]

    # Verify Bob's signed envelope via CLI.
    assert (
        run_cli(
            [
                "--state-dir",
                str(alice_dir),
                "--json",
                "mail",
                "verify",
                "--sender-mail",
                bob_mail,
                "--envelope",
                str(conf_file),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["accepted"] is True

    # Pin capability bundle via CLI and list it.
    assert (
        run_cli(
            [
                "--state-dir",
                str(alice_dir),
                "--json",
                "friends",
                "pin",
                friend_id,
                "--bundle",
                "calendar-read",
                "--revision",
                "sha256:abcdef0123456789abcdef0123456789",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert run_cli(["--state-dir", str(alice_dir), "--json", "friends", "pins", friend_id]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 1

    # Policy check via CLI.
    assert (
        run_cli(
            [
                "--state-dir",
                str(alice_dir),
                "--json",
                "policy",
                "check",
                "--mail",
                bob_mail,
                "--action",
                "send_message",
                "--topic",
                "music",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["decision"] == "allow"

    assert (
        run_cli(
            [
                "--state-dir",
                str(alice_dir),
                "--json",
                "policy",
                "check",
                "--mail",
                bob_mail,
                "--action",
                "send_message",
                "--topic",
                "work",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["decision"] == "needs_owner_approval"