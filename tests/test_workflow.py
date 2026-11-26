"""Tests for Muse Mail workflow integration: intake, outbound policy gate,
signed capability bundles with pin checks, thread mirroring, migration 004,
and local CLI subcommands."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sqlite3
from datetime import datetime, timezone

import pytest

from musefriends import migrate
from musefriends.bundles import (
    compute_bundle_revision_hash,
    load_files_from_directory,
    package_capability_bundle,
    verify_capability_bundle,
)
from musefriends.cli import run_cli
from musefriends.errors import FriendsError
from musefriends.identity import IdentityManager
from musefriends.mail import (
    complete_mail_pairing,
    pin_capability_bundle,
    sign_mail_envelope,
)
from musefriends.pairing import PairingManager
from musefriends.store import Store
from musefriends.workflow import (
    check_mail_outbound,
    evaluate_mail_intake,
    get_standing_channel,
    link_mail_thread,
    lookup_mail_thread,
    mirror_mail_to_mcp,
)


class FakeMuseMcpClient:
    """In-memory stub for local muse-mcp thread operations."""

    def __init__(self):
        self.created: list[dict] = []
        self.posted: list[dict] = []
        self._seq = 0

    def create_thread(self, title: str, body: str | None = None, **kwargs) -> dict:
        self._seq += 1
        tid = f"mcp-thread-{self._seq}"
        rec = {"thread_id": tid, "title": title, "body": body, "kwargs": kwargs}
        self.created.append(rec)
        return {"thread_id": tid, "request_seq": 1}

    def post_message(self, thread_id: str, body: str, **kwargs) -> dict:
        rec = {"thread_id": thread_id, "body": body, "kwargs": kwargs}
        self.posted.append(rec)
        return {"thread_id": thread_id, "seq": len(self.posted) + 1}


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


def _pair_friend(
    tmp_path,
    *,
    peer: str = "bob",
    tier: str = "friend",
    discretion: str = "",
    verified: bool = False,
):
    ts = datetime(2026, 11, 26, 16, 0, 0, tzinfo=timezone.utc)
    alice_store, alice_id, alice_card, alice_key, alice_mail = _init_peer(tmp_path, "alice")
    _peer_store, _peer_id, peer_card, peer_key, peer_mail = _init_peer(tmp_path, peer)

    pairing = PairingManager(alice_store, alice_id)
    minted = pairing.mint_code(now=ts)
    conf = sign_mail_envelope(
        peer_key,
        sender_mail=peer_mail,
        recipient_mail=alice_mail,
        kind="pairing_confirmation",
        payload={"code": minted["code"], "card": peer_card},
        timestamp=ts,
    )
    paired = complete_mail_pairing(
        alice_store,
        alice_id,
        confirmation_envelope=conf,
        sender_mail=peer_mail,
        owner_approved=True,
        tier=tier,
        discretion_profile=discretion,
        now=ts,
    )
    if verified:
        pairing.verify_friend(paired["friend_id"], now=ts)
    return {
        "ts": ts,
        "alice_store": alice_store,
        "alice_id": alice_id,
        "alice_card": alice_card,
        "alice_key": alice_key,
        "alice_mail": alice_mail,
        "pairing": pairing,
        "paired": paired,
        "peer_card": peer_card,
        "peer_key": peer_key,
        "peer_mail": peer_mail,
    }


# -- 1. Migration 004 applies cleanly over schema v3 --------------------------
def test_migration_004_applies_cleanly_over_schema_v3(tmp_path):
    state_dir = tmp_path / "upgrade_v3"
    state_dir.mkdir(mode=0o700)
    db_path = state_dir / "friends.db"

    conn = sqlite3.connect(str(db_path))
    conn.isolation_level = None
    conn.execute(
        "CREATE TABLE schema_migrations ("
        "version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    for ver, filename in ((1, "001_initial.sql"), (3, "003_muse_mail.sql")):
        sql = (pathlib.Path(migrate.MIGRATIONS_DIR) / filename).read_text(encoding="utf-8")
        digest = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        conn.executescript(sql)
        conn.execute(
            "INSERT INTO schema_migrations (version, checksum, applied_at) VALUES (?, ?, '2026-11-26T00:00:00Z')",
            (ver, digest),
        )
    conn.close()

    store = Store(state_dir, db_path=db_path)
    assert store.schema_version == 4
    versions = [
        r["version"]
        for r in store.conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    ]
    assert versions == [1, 3, 4]
    tables = {
        r["name"]
        for r in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "mail_thread_links" in tables
    assert "idempotency_keys" not in tables


# -- 2. Intake helper ---------------------------------------------------------
def test_intake_verified_friend_happy_path_and_thread_link(tmp_path):
    ctx = _pair_friend(tmp_path, tier="friend", discretion="topics:music,books")
    store = ctx["alice_store"]
    fid = ctx["paired"]["friend_id"]

    link_mail_thread(
        store,
        friend_id=fid,
        mail_thread_id="mail-thr-100",
        mcp_thread_id="mcp-chan-1",
        thread_class="channel",
        subject="Standing channel",
        now=ctx["ts"],
    )

    env = sign_mail_envelope(
        ctx["peer_key"],
        sender_mail=ctx["peer_mail"],
        recipient_mail=ctx["alice_mail"],
        kind="message",
        payload={"subject": "Album rec?", "body": "Any new jazz records?"},
        timestamp=ctx["ts"],
    )
    att_file = tmp_path / "msg_env.json"
    att_file.write_text(json.dumps(env), encoding="utf-8")

    verdict = evaluate_mail_intake(
        store,
        from_address=ctx["peer_mail"],
        subject="Album rec?",
        body="Any new jazz records?",
        attachments=[att_file],
        mail_thread_id="mail-thr-100",
        topics=["music"],
    )
    assert verdict["sender_status"] == "verified_friend"
    assert verdict["verdict"] == "allow"
    assert verdict["code"] == "ok"
    assert verdict["friend"]["tier"] == "friend"
    assert "answer_question" in verdict["permitted_actions"]
    assert "run_command" in verdict["permitted_actions"]
    assert verdict["thread_link"]["mcp_thread_id"] == "mcp-chan-1"

    # Outside established topics escalates to owner approval.
    esc = evaluate_mail_intake(
        store,
        from_address=ctx["peer_mail"],
        subject="Taxes",
        body="Can you check my invoice?",
        attachments=[att_file],
        topics=["work"],
    )
    assert esc["sender_status"] == "verified_friend"
    assert esc["verdict"] == "needs_owner_approval"
    assert esc["code"] == "outside_established_topics"


def test_intake_unknown_sender_unsigned_and_tampered_envelope(tmp_path):
    ctx = _pair_friend(tmp_path, tier="friend")
    store = ctx["alice_store"]

    # Unknown sender -> unknown_sender / deny.
    unk = evaluate_mail_intake(
        store,
        from_address="stranger@example.invalid",
        subject="Hi",
        body="Hello?",
    )
    assert unk["sender_status"] == "unknown_sender"
    assert unk["verdict"] == "deny"
    assert unk["permitted_actions"] == []

    # Known friend, unsigned mail -> unverified / needs_owner_approval.
    unsigned = evaluate_mail_intake(
        store,
        from_address=ctx["peer_mail"],
        subject="Plain mail",
        body="No signature attached",
    )
    assert unsigned["sender_status"] == "unverified"
    assert unsigned["verdict"] == "needs_owner_approval"
    assert unsigned["code"] == "unsigned_mail"

    # Tampered envelope -> unverified / deny (invalid_signature).
    env = sign_mail_envelope(
        ctx["peer_key"],
        sender_mail=ctx["peer_mail"],
        recipient_mail=ctx["alice_mail"],
        kind="message",
        payload={"body": "original"},
        timestamp=ctx["ts"],
    )
    env["payload"]["body"] = "tampered"
    bad_file = tmp_path / "tampered.json"
    bad_file.write_text(json.dumps(env), encoding="utf-8")

    tampered = evaluate_mail_intake(
        store,
        from_address=ctx["peer_mail"],
        subject="Tampered",
        body="Tampered",
        attachments=[bad_file],
    )
    assert tampered["sender_status"] == "unverified"
    assert tampered["verdict"] == "deny"
    assert tampered["code"] == "invalid_signature"

    # Revoked friend -> friend_revoked / deny.
    ctx["pairing"].revoke_friend(ctx["paired"]["friend_id"], now=ctx["ts"])
    rev = evaluate_mail_intake(
        store,
        from_address=ctx["peer_mail"],
        subject="After revoke",
        body="Hello?",
    )
    assert rev["sender_status"] == "friend_revoked"
    assert rev["verdict"] == "deny"


# -- 3. Capability bundles: pack, verify, pin match & mismatch ----------------
def test_capability_bundle_pack_verify_and_pin_states(tmp_path):
    ctx = _pair_friend(tmp_path, tier="friend")
    store = ctx["alice_store"]
    fid = ctx["paired"]["friend_id"]

    bundle_dir = tmp_path / "weather_skill"
    bundle_dir.mkdir()
    (bundle_dir / "SKILL.md").write_text("# Weather\nFetch local forecast.\n", encoding="utf-8")
    (bundle_dir / "manifest.json").write_text('{"name":"weather-lookup"}\n', encoding="utf-8")

    files = load_files_from_directory(bundle_dir)
    bundle_env = package_capability_bundle(
        ctx["peer_key"],
        sender_mail=ctx["peer_mail"],
        recipient_mail=ctx["alice_mail"],
        bundle_name="weather-lookup",
        bundle_kind="skill",
        files=files,
        timestamp=ctx["ts"],
    )
    rev1 = bundle_env["payload"]["revision_hash"]
    assert rev1 == compute_bundle_revision_hash("weather-lookup", files, bundle_kind="skill")

    # 1. Unpinned bundle -> rejected with bundle_not_pinned & needs_owner_pin=True.
    v_unpinned = verify_capability_bundle(
        store, sender_mail=ctx["peer_mail"], envelope=bundle_env
    )
    assert v_unpinned["accepted"] is False
    assert v_unpinned["code"] == "bundle_not_pinned"
    assert v_unpinned["needs_owner_pin"] is True
    assert v_unpinned["revision_hash"] == rev1

    # Intake also surfaces needs_owner_approval with bundle_not_pinned.
    att = tmp_path / "bundle_v1.json"
    att.write_text(json.dumps(bundle_env), encoding="utf-8")
    intake_unpinned = evaluate_mail_intake(
        store,
        from_address=ctx["peer_mail"],
        subject="Sharing weather skill",
        body="Attached.",
        attachments=[att],
    )
    assert intake_unpinned["sender_status"] == "verified_friend"
    assert intake_unpinned["verdict"] == "needs_owner_approval"
    assert intake_unpinned["code"] == "bundle_not_pinned"

    # 2. Owner pins rev1 -> bundle verify & intake both accept.
    pin_capability_bundle(
        store,
        friend_id=fid,
        bundle_name="weather-lookup",
        revision_hash=rev1,
        direction="inbound",
        now=ctx["ts"],
    )
    v_ok = verify_capability_bundle(
        store, sender_mail=ctx["peer_mail"], envelope=bundle_env
    )
    assert v_ok["accepted"] is True
    assert v_ok["code"] == "ok"
    assert v_ok["pinned_revision_hash"] == rev1

    intake_ok = evaluate_mail_intake(
        store,
        from_address=ctx["peer_mail"],
        subject="Sharing weather skill",
        body="Attached.",
        attachments=[att],
    )
    assert intake_ok["verdict"] == "allow"
    assert "accept_capability_bundle" in intake_ok["permitted_actions"]

    # 3. Peer sends updated v2 bundle -> rejected with pin_mismatch & needs_owner_pin=True.
    files_v2 = dict(files, **{"SKILL.md": "# Weather v2\nUpdated forecast.\n"})
    bundle_v2 = package_capability_bundle(
        ctx["peer_key"],
        sender_mail=ctx["peer_mail"],
        recipient_mail=ctx["alice_mail"],
        bundle_name="weather-lookup",
        bundle_kind="skill",
        files=files_v2,
        timestamp=ctx["ts"],
    )
    v_mismatch = verify_capability_bundle(
        store, sender_mail=ctx["peer_mail"], envelope=bundle_v2
    )
    assert v_mismatch["accepted"] is False
    assert v_mismatch["code"] == "pin_mismatch"
    assert v_mismatch["needs_owner_pin"] is True
    assert v_mismatch["pinned_revision_hash"] == rev1
    assert v_mismatch["revision_hash"] == bundle_v2["payload"]["revision_hash"]

    # 4. Path traversal inside bundle files is rejected.
    with pytest.raises(FriendsError) as exc:
        compute_bundle_revision_hash("evil", {"../escape.txt": "boom"})
    assert exc.value.code == "invalid_bundle"


# -- 4. Outbound policy gate --------------------------------------------------
def test_outbound_allow_deny_and_needs_approval(tmp_path):
    ctx = _pair_friend(tmp_path, tier="friend", discretion="topics:music")
    store = ctx["alice_store"]
    fid = ctx["paired"]["friend_id"]

    pin_capability_bundle(
        store,
        friend_id=fid,
        bundle_name="playlist-share",
        revision_hash="sha256:0123456789abcdef0123456789abcdef",
        direction="outbound",
        now=ctx["ts"],
    )

    # Allow: on-topic message.
    r_allow = check_mail_outbound(
        store,
        mail_address=ctx["peer_mail"],
        kind="message",
        subject="Jazz recs",
        topics=["music"],
    )
    assert r_allow["decision"] == "allow"
    assert r_allow["mail_address"] == ctx["peer_mail"]

    # Needs owner approval: friend-tier capability bundle share (not opted in).
    r_esc = check_mail_outbound(
        store,
        mail_address=ctx["peer_mail"],
        kind="capability_bundle",
        bundle_name="playlist-share",
    )
    assert r_esc["decision"] == "needs_owner_approval"
    assert r_esc["pinned_outbound_revision"] == "sha256:0123456789abcdef0123456789abcdef"

    # Deny: private data.
    r_deny = check_mail_outbound(
        store,
        mail_address=ctx["peer_mail"],
        kind="message",
        touches_private_data=True,
    )
    assert r_deny["decision"] == "deny"
    assert r_deny["code"] == "discretion_private_data"

    # Deny: unknown recipient.
    r_unk = check_mail_outbound(
        store,
        mail_address="unknown@example.invalid",
        kind="message",
    )
    assert r_unk["decision"] == "deny"
    assert r_unk["code"] == "unknown_friend"


# -- 5. Thread mirroring with stub muse-mcp client ----------------------------
def test_thread_link_lookup_and_mirror_channel_vs_task(tmp_path):
    ctx = _pair_friend(tmp_path, tier="friend")
    store = ctx["alice_store"]
    fid = ctx["paired"]["friend_id"]
    fake_mcp = FakeMuseMcpClient()

    # First channel mail creates a standing muse-mcp channel thread.
    m1 = mirror_mail_to_mcp(
        store,
        friend_id=fid,
        mail_thread_id="mail-thr-1",
        mcp_client=fake_mcp,
        subject="Hello",
        body="First message",
        thread_class="channel",
        now=ctx["ts"],
    )
    assert m1["created"] is True
    assert m1["thread_class"] == "channel"
    chan_mcp_id = m1["mcp_thread_id"]
    assert len(fake_mcp.created) == 1

    # A second mail thread for the same friend reuses the standing channel thread.
    m2 = mirror_mail_to_mcp(
        store,
        friend_id=fid,
        mail_thread_id="mail-thr-2",
        mcp_client=fake_mcp,
        subject="Another subject",
        body="Follow-up in new email thread",
        thread_class="channel",
        now=ctx["ts"],
    )
    assert m2["created"] is False
    assert m2["mcp_thread_id"] == chan_mcp_id
    assert len(fake_mcp.created) == 1
    assert len(fake_mcp.posted) == 1
    assert fake_mcp.posted[0]["thread_id"] == chan_mcp_id

    # A discrete task thread spawns a separate muse-mcp thread alongside the channel.
    t1 = mirror_mail_to_mcp(
        store,
        friend_id=fid,
        mail_thread_id="mail-task-1",
        mcp_client=fake_mcp,
        subject="Book dinner",
        body="Please book a table",
        thread_class="task",
        now=ctx["ts"],
    )
    assert t1["created"] is True
    assert t1["thread_class"] == "task"
    assert t1["mcp_thread_id"] != chan_mcp_id
    assert len(fake_mcp.created) == 2

    # Lookup helpers by mail_thread_id, mcp_thread_id, friend_id, and thread_class.
    assert lookup_mail_thread(store, mail_thread_id="mail-thr-1")[0]["mcp_thread_id"] == chan_mcp_id
    assert len(lookup_mail_thread(store, mcp_thread_id=chan_mcp_id)) == 2
    assert len(lookup_mail_thread(store, friend_id=fid, thread_class="task")) == 1
    assert get_standing_channel(store, friend_id=fid)["mcp_thread_id"] == chan_mcp_id


# -- 6. CLI end-to-end: bundle pack/verify, intake, outbound, threads ---------
def test_cli_workflow_end_to_end(tmp_path, capsys):
    alice_dir = tmp_path / "alice"
    bob_dir = tmp_path / "bob"
    alice_mail = "alice.muse@example.invalid"
    bob_mail = "bob.muse@example.invalid"

    assert run_cli(["--state-dir", str(alice_dir), "--json", "identity", "init", "--handle", "alice", "--display-name", "Alice's Muse", "--url", "https://alice.example.invalid"]) == 0
    capsys.readouterr()
    assert run_cli(["--state-dir", str(bob_dir), "--json", "identity", "init", "--handle", "bob", "--display-name", "Bob's Muse", "--url", "https://bob.example.invalid"]) == 0
    bob_init = json.loads(capsys.readouterr().out)

    # Pair Bob with Alice via mail confirmation.
    assert run_cli(["--state-dir", str(alice_dir), "--json", "pair", "mint"]) == 0
    minted = json.loads(capsys.readouterr().out)
    payload_path = tmp_path / "pair.json"
    payload_path.write_text(json.dumps({"code": minted["code"], "card": bob_init["card"]}), encoding="utf-8")
    conf_path = tmp_path / "conf.json"
    assert run_cli(["--state-dir", str(bob_dir), "mail", "sign", "--sender-mail", bob_mail, "--kind", "pairing_confirmation", "--payload", f"@{payload_path}", "--out", str(conf_path)]) == 0
    capsys.readouterr()
    assert run_cli(["--state-dir", str(alice_dir), "--json", "mail", "complete-pairing", "--sender-mail", bob_mail, "--envelope", str(conf_path), "--owner-approve", "--tier", "friend"]) == 0
    fid = json.loads(capsys.readouterr().out)["friend_id"]

    # Bob packs a capability bundle via CLI.
    bdir = tmp_path / "demo_bundle"
    bdir.mkdir()
    (bdir / "SKILL.md").write_text("# Demo skill\n", encoding="utf-8")
    bfile = tmp_path / "demo_bundle_env.json"
    assert run_cli(["--state-dir", str(bob_dir), "--json", "bundle", "pack", "--sender-mail", bob_mail, "--recipient-mail", alice_mail, "--bundle", "demo-skill", "--dir", str(bdir), "--out", str(bfile)]) == 0
    packed = json.loads(capsys.readouterr().out)
    rev = packed["revision_hash"]

    # Alice verifies before pinning -> exit 1 (bundle_not_pinned).
    assert run_cli(["--state-dir", str(alice_dir), "--json", "bundle", "verify", "--sender-mail", bob_mail, "--envelope", str(bfile)]) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "bundle_not_pinned"

    # Alice pins revision -> verify returns exit 0.
    assert run_cli(["--state-dir", str(alice_dir), "--json", "friends", "pin", fid, "--bundle", "demo-skill", "--revision", rev]) == 0
    capsys.readouterr()
    assert run_cli(["--state-dir", str(alice_dir), "--json", "bundle", "verify", "--sender-mail", bob_mail, "--envelope", str(bfile)]) == 0
    assert json.loads(capsys.readouterr().out)["accepted"] is True

    # Link and lookup a thread via CLI.
    assert run_cli(["--state-dir", str(alice_dir), "--json", "threads", "link", "--friend-id", fid, "--mail-thread-id", "m-42", "--mcp-thread-id", "mcp-42", "--class", "channel", "--subject", "Standing"]) == 0
    capsys.readouterr()
    assert run_cli(["--state-dir", str(alice_dir), "--json", "threads", "lookup", "--mail-thread-id", "m-42"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["mcp_thread_id"] == "mcp-42"

    # Intake via CLI includes thread_link and allows pinned bundle.
    assert run_cli(["--state-dir", str(alice_dir), "--json", "mail", "intake", "--from", bob_mail, "--subject", "Bundle", "--body", "Here it is", "--mail-thread-id", "m-42", "--attachment", str(bfile)]) == 0
    intake_out = json.loads(capsys.readouterr().out)
    assert intake_out["sender_status"] == "verified_friend"
    assert intake_out["verdict"] == "allow"
    assert intake_out["thread_link"]["mcp_thread_id"] == "mcp-42"

    # Outbound via CLI.
    assert run_cli(["--state-dir", str(alice_dir), "--json", "mail", "outbound", "--mail", bob_mail, "--kind", "message", "--subject", "Thanks"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "allow"


# -- 7. Regressions found by the end-to-end drill (scripts/mail_drill.py) ----
def test_intake_fails_closed_when_declared_attachment_is_unreadable(tmp_path):
    """An attachment path the Muse cannot read may hold the signature: deny, do not ignore."""
    ctx = _pair_friend(tmp_path, tier="friend")
    store = ctx["alice_store"]

    missing = evaluate_mail_intake(
        store,
        from_address=ctx["peer_mail"],
        subject="Jazz?",
        body="Any new records?",
        attachments=[tmp_path / "attachment-that-does-not-exist.json"],
    )
    assert missing["verdict"] == "deny"
    assert missing["code"] == "attachment_unreadable"
    assert missing["attachments"][0]["artifact_type"] == "unreadable"
    assert missing["permitted_actions"] == []

    # Non-UTF-8 bytes are equally unreadable, and equally fail closed.
    binary = tmp_path / "attachment.bin"
    binary.write_bytes(b"\xff\xfe\x00\x01")
    unreadable = evaluate_mail_intake(
        store,
        from_address=ctx["peer_mail"],
        subject="Jazz?",
        body="Any new records?",
        attachments=[binary],
    )
    assert unreadable["verdict"] == "deny"
    assert unreadable["code"] == "attachment_unreadable"

    # A readable non-protocol attachment is still merely ignored.
    plain = tmp_path / "notes.txt"
    plain.write_text("just a note\n", encoding="utf-8")
    ignored = evaluate_mail_intake(
        store,
        from_address=ctx["peer_mail"],
        subject="Jazz?",
        body="Any new records?",
        attachments=[plain],
    )
    assert ignored["verdict"] == "needs_owner_approval"
    assert ignored["code"] == "unsigned_mail"
    assert ignored["attachments"][0]["code"] == "ignored"


def test_intake_never_returns_another_friends_thread_link(tmp_path):
    """A mail thread id linked to one friend must not resolve for another friend."""
    ts = datetime(2026, 11, 26, 16, 0, 0, tzinfo=timezone.utc)
    alice_store, alice_id, _alice_card, _alice_key, alice_mail = _init_peer(tmp_path, "alice")
    pairing = PairingManager(alice_store, alice_id)

    def pair(peer: str) -> tuple[dict, dict, object]:
        peer_store, _peer_id, peer_card, peer_key, peer_mail = _init_peer(tmp_path, peer)
        minted = pairing.mint_code(now=ts)
        conf = sign_mail_envelope(
            peer_key,
            sender_mail=peer_mail,
            recipient_mail=alice_mail,
            kind="pairing_confirmation",
            payload={"code": minted["code"], "card": peer_card},
            timestamp=ts,
        )
        paired = complete_mail_pairing(
            alice_store,
            alice_id,
            confirmation_envelope=conf,
            sender_mail=peer_mail,
            owner_approved=True,
            tier="friend",
            now=ts,
        )
        return paired, peer_card, peer_key

    bob, _bob_card, bob_key = pair("bob")
    carol, _carol_card, carol_key = pair("carol")
    link_mail_thread(
        alice_store,
        friend_id=bob["friend_id"],
        mail_thread_id="bob-thread-1",
        mcp_thread_id="bob-mcp-1",
        thread_class="channel",
        now=ts,
    )

    carol_env = sign_mail_envelope(
        carol_key,
        sender_mail="carol.muse@example.invalid",
        recipient_mail=alice_mail,
        kind="message",
        payload={"body": "Hi"},
        timestamp=ts,
    )
    # Carol's mail claiming Bob's thread id must not receive Bob's local thread.
    verdict = evaluate_mail_intake(
        alice_store,
        from_address="carol.muse@example.invalid",
        subject="Hi",
        body="Hi",
        attachments=[carol_env],
        mail_thread_id="bob-thread-1",
    )
    assert verdict["friend"]["friend_id"] == carol["friend_id"]
    assert verdict["thread_link"] is None

    # The same thread id does resolve for Bob.
    bob_env = sign_mail_envelope(
        bob_key,
        sender_mail="bob.muse@example.invalid",
        recipient_mail=alice_mail,
        kind="message",
        payload={"body": "Hi"},
        timestamp=ts,
    )
    bob_verdict = evaluate_mail_intake(
        alice_store,
        from_address="bob.muse@example.invalid",
        subject="Hi",
        body="Hi",
        attachments=[bob_env],
        mail_thread_id="bob-thread-1",
    )
    assert bob_verdict["thread_link"]["mcp_thread_id"] == "bob-mcp-1"


def test_outbound_bundle_check_requires_a_bundle_name(tmp_path):
    ctx = _pair_friend(tmp_path, tier="friend")
    with pytest.raises(FriendsError) as exc:
        check_mail_outbound(
            ctx["alice_store"],
            mail_address=ctx["peer_mail"],
            kind="capability_bundle",
        )
    assert exc.value.code == "invalid_request"


def test_cli_reports_unwritable_output_paths(tmp_path, capsys):
    alice_dir = tmp_path / "alice"
    assert run_cli(["--state-dir", str(alice_dir), "identity", "init", "--handle", "alice",
                    "--display-name", "Alice's Muse", "--url", "https://alice.example.invalid"]) == 0
    capsys.readouterr()

    bad_out = tmp_path / "no-such-dir" / "card.json"
    assert run_cli(["--state-dir", str(alice_dir), "card", "export", "--out", str(bad_out)]) == 1
    assert "output_unwritable" in capsys.readouterr().err

    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    (bundle_dir / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
    assert run_cli(["--state-dir", str(alice_dir), "bundle", "pack", "--sender-mail",
                    "alice.muse@example.invalid", "--bundle", "demo", "--dir", str(bundle_dir),
                    "--out", str(tmp_path / "missing" / "b.json")]) == 1
    assert "output_unwritable" in capsys.readouterr().err


def test_mail_drill_script_passes_end_to_end(tmp_path):
    """The documented two-identity CLI drill must keep passing."""
    import subprocess
    import sys

    root = pathlib.Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "mail_drill.py"),
            "--workdir",
            str(tmp_path / "drill"),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, f"drill failed:\n{proc.stdout}\n{proc.stderr}"
    assert "DRILL PASSED" in proc.stdout