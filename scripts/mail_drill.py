#!/usr/bin/env python3
"""End-to-end acceptance drill for the Muse Mail workflow.

Drives the real `muse-friends` CLI as a subprocess with two throwaway local
identities: one owner (alice) and one remote friend (bob). No network, no mail
is sent; every artifact is a crafted local file.

Steps exercised:
  1.  Identity generation for both sides (0600 keys, signed cards).
  2.  Friend-card exchange and verification (`card export` / `card import`).
  3.  Pairing-code mint, signed mail confirmation, intake triage of the
      confirmation, and mail-confirmed pairing with owner approval.
  4.  Inbound capability bundle: unpinned rejection, owner pin, then accept.
  5.  Mail intake verdicts for a verified friend (allow / escalation).
  6.  Policy checks on sample outbound content (allow / needs approval / deny).
  7.  Outbound gate before sending (message, bundle, private data).
  8.  Standing channel thread mirroring into a local muse-mcp thread (stub
      client) plus CLI `threads link` / `threads lookup`.

Exit status 0 means the whole workflow passed; 1 means a step failed.
Run: .venv/bin/python scripts/mail_drill.py [--keep] [--workdir DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

ALICE_MAIL = "alice.muse@example.invalid"
BOB_MAIL = "bob.muse@example.invalid"

STEPS: list[tuple[str, str]] = []


class DrillFailure(Exception):
    pass


def run(state_dir: Path, *args: str, expect: int = 0) -> dict | str:
    """Invoke the real CLI in a subprocess and return parsed JSON output."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    env["MUSE_FRIENDS_STATE_DIR"] = str(state_dir)
    env.pop("PYTHONSTARTUP", None)
    cmd = [sys.executable, "-m", "musefriends.cli", "--state-dir", str(state_dir), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    printable = " ".join(a if " " not in a else json.dumps(a) for a in args)
    if proc.returncode != expect:
        raise DrillFailure(
            f"`muse-friends {printable}` exited {proc.returncode}, expected {expect}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    STEPS.append(("ok", f"muse-friends {printable} -> exit {proc.returncode}"))
    out = proc.stdout.strip()
    if not out:
        return ""
    try:
        return json.loads(out)
    except ValueError:
        return out


def step(name: str, detail: str) -> None:
    STEPS.append(("step", name))
    print(f"\n== {name}\n   {detail}")


def check(condition: bool, message: str) -> None:
    if not condition:
        raise DrillFailure(message)
    STEPS.append(("assert", message))


def json_file(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class StubMuseMcp:
    """Local stand-in for a muse-mcp client: records threads and messages."""

    def __init__(self) -> None:
        self.threads: list[dict] = []
        self.messages: list[dict] = []

    def create_thread(self, title: str, body: str | None = None, **kwargs) -> dict:
        thread_id = f"mcp-thread-{len(self.threads) + 1}"
        self.threads.append({"thread_id": thread_id, "title": title, "body": body})
        return {"thread_id": thread_id, "request_seq": 1}

    def post_message(self, thread_id: str, body: str, **kwargs) -> dict:
        self.messages.append({"thread_id": thread_id, "body": body})
        return {"thread_id": thread_id, "seq": len(self.messages) + 1}


def drill(workdir: Path) -> None:
    alice = workdir / "alice"
    bob = workdir / "bob"
    alice.mkdir(mode=0o700, parents=True)
    bob.mkdir(mode=0o700, parents=True)

    # 1. Identities ---------------------------------------------------------
    step("1. identities", "generate throwaway Ed25519 identities for both sides")
    alice_id = run(alice, "--json", "identity", "init", "--handle", "alice",
                   "--display-name", "Alice's Muse", "--url", "https://alice.example.invalid")
    bob_id = run(bob, "--json", "identity", "init", "--handle", "bob",
                 "--display-name", "Bob's Muse", "--url", "https://bob.example.invalid")
    assert isinstance(alice_id, dict) and isinstance(bob_id, dict)
    key_mode = oct((alice / "identity.ed25519.pem").stat().st_mode & 0o777)
    check(key_mode == "0o600", f"private key mode is {key_mode}")
    check(alice_id["card"]["public_key"] != bob_id["card"]["public_key"], "keys differ")
    check(len(alice_id["fingerprint"].split()) == 8, "safety number is 8 groups")

    # 2. Friend-card exchange ----------------------------------------------
    step("2. card exchange", "bob exports a signed card; alice verifies it on import")
    bob_card_path = workdir / "bob-card.json"
    run(bob, "card", "export", "--out", str(bob_card_path))
    imported = run(alice, "--json", "card", "import", str(bob_card_path))
    assert isinstance(imported, dict)
    check(imported["card"]["public_key"] == bob_id["card"]["public_key"], "imported key matches bob")
    check(imported["fingerprint"] == bob_id["fingerprint"], "imported fingerprint matches bob")

    tampered_path = json_file(
        workdir / "bob-card-tampered.json",
        {**bob_id["card"], "display_name": "Impostor"},
    )
    run(alice, "card", "import", str(tampered_path), expect=1)
    check(True, "tampered card rejected by `card import` (exit 1)")

    # 3. Mail-confirmed pairing --------------------------------------------
    step("3. pairing", "alice mints a code; bob confirms by signed mail; alice approves")
    minted = run(alice, "--json", "pair", "mint")
    assert isinstance(minted, dict)
    check(len(minted["code"]) == 9 and minted["code"][4] == "-", f"code shape {minted['code']}")

    confirm_payload = json_file(
        workdir / "pair-confirm-payload.json",
        {"code": minted["code"], "card": bob_id["card"]},
    )
    confirm_env = workdir / "pair-confirm-envelope.json"
    run(bob, "mail", "sign", "--sender-mail", BOB_MAIL, "--recipient-mail", ALICE_MAIL,
        "--kind", "pairing_confirmation", "--payload", f"@{confirm_payload}",
        "--out", str(confirm_env))
    signed = json.loads(confirm_env.read_text(encoding="utf-8"))
    check(signed["kind"] == "pairing_confirmation", "confirmation envelope is signed")

    # Intake triage: an unpaired sender's confirmation is not friend traffic yet.
    triage = run(alice, "--json", "mail", "intake", "--from", BOB_MAIL,
                 "--subject", "Pairing confirmation", "--body", "Here is my card and code.",
                 "--attachment", str(confirm_env))
    assert isinstance(triage, dict)
    check(triage["sender_status"] == "unknown_sender", f"intake triage: {triage['sender_status']}")
    check(triage["verdict"] == "deny", "intake denies unknown sender (pairing is a separate path)")

    # Refused without owner approval, then approved.
    run(alice, "mail", "complete-pairing", "--sender-mail", BOB_MAIL,
        "--envelope", str(confirm_env), expect=1)
    check(True, "pairing refused without --owner-approve (exit 1)")

    paired = run(alice, "--json", "mail", "complete-pairing", "--sender-mail", BOB_MAIL,
                 "--envelope", str(confirm_env), "--owner-approve", "--tier", "friend",
                 "--discretion", "topics:music,books")
    assert isinstance(paired, dict)
    check(paired["status"] == "paired", "pairing completed")
    check(paired["mail_address"] == BOB_MAIL, "friend record bound to bob's mail address")
    check(paired["public_key"] == bob_id["card"]["public_key"], "friend record bound to bob's key")
    check(paired["tier"] == "friend", "tier bound at approval")
    friend_id = paired["friend_id"]

    friends = run(alice, "--json", "friends", "list")
    assert isinstance(friends, list)
    check(len(friends) == 1 and friends[0]["verified"] is False, "one unverified friend listed")

    # 4. Inbound capability bundle + pin -----------------------------------
    step("4. capability bundle", "bob packs a signed bundle; alice verifies, pins, re-verifies")
    bundle_dir = workdir / "bob-skill"
    bundle_dir.mkdir()
    (bundle_dir / "SKILL.md").write_text("# Jazz picks\nSuggest records.\n", encoding="utf-8")
    (bundle_dir / "manifest.json").write_text('{"name": "jazz-picks"}\n', encoding="utf-8")
    bundle_env = workdir / "jazz-picks-envelope.json"
    packed = run(bob, "--json", "bundle", "pack", "--sender-mail", BOB_MAIL,
                 "--recipient-mail", ALICE_MAIL, "--bundle", "jazz-picks",
                 "--kind", "skill", "--dir", str(bundle_dir), "--out", str(bundle_env))
    assert isinstance(packed, dict)
    revision = packed["revision_hash"]
    check(revision.startswith("sha256:"), f"revision hash {revision}")

    unpinned = run(alice, "--json", "bundle", "verify", "--sender-mail", BOB_MAIL,
                   "--envelope", str(bundle_env), expect=1)
    assert isinstance(unpinned, dict)
    check(unpinned["code"] == "bundle_not_pinned", "unpinned bundle rejected")
    check(unpinned["needs_owner_pin"] is True, "rejection asks the owner to pin")

    run(alice, "--json", "friends", "pin", friend_id, "--bundle", "jazz-picks",
        "--revision", revision, "--direction", "inbound")
    verified = run(alice, "--json", "bundle", "verify", "--sender-mail", BOB_MAIL,
                   "--envelope", str(bundle_env))
    assert isinstance(verified, dict)
    check(verified["accepted"] is True and verified["code"] == "ok", "pinned bundle accepted")
    check(verified["pinned_revision_hash"] == revision, "accept reports the pinned revision")

    # 5. Incoming mail intake verdicts -------------------------------------
    step("5. intake", "verified friend mail: allow on-topic, escalate off-topic")
    msg_env = workdir / "bob-message-envelope.json"
    msg_payload = json_file(workdir / "bob-message-payload.json",
                            {"subject": "Jazz?", "body": "Any new records?"})
    run(bob, "mail", "sign", "--sender-mail", BOB_MAIL, "--recipient-mail", ALICE_MAIL,
        "--kind", "message", "--payload", f"@{msg_payload}", "--out", str(msg_env))

    allowed = run(alice, "--json", "mail", "intake", "--from", BOB_MAIL,
                  "--subject", "Jazz?", "--body", "Any new records?",
                  "--attachment", str(msg_env), "--topic", "music")
    assert isinstance(allowed, dict)
    check(allowed["sender_status"] == "verified_friend", "sender verified as friend")
    check(allowed["verdict"] == "allow", f"on-topic mail allowed ({allowed['code']})")
    check("answer_question" in allowed["permitted_actions"], "question answering permitted")
    check("delegate" not in allowed["permitted_actions"], "delegation not permitted for friend tier")

    escalated = run(alice, "--json", "mail", "intake", "--from", BOB_MAIL,
                    "--subject", "Invoices", "--body", "Check my invoices",
                    "--attachment", str(msg_env), "--topic", "work")
    assert isinstance(escalated, dict)
    check(escalated["verdict"] == "needs_owner_approval", "off-topic mail escalates")
    check(escalated["code"] == "outside_established_topics", f"escalation reason {escalated['code']}")

    bundle_intake = run(alice, "--json", "mail", "intake", "--from", BOB_MAIL,
                        "--subject", "Shared skill", "--body", "Attached.",
                        "--attachment", str(bundle_env))
    assert isinstance(bundle_intake, dict)
    check(bundle_intake["verdict"] == "allow", "pinned bundle accepted at intake")
    check("accept_capability_bundle" in bundle_intake["permitted_actions"],
          "intake permits accepting the bundle")

    # 6. Policy checks on sample outbound content --------------------------
    step("6. policy", "sample outbound content: allow / needs approval / deny")
    p_allow = run(alice, "--json", "policy", "check", "--mail", BOB_MAIL,
                  "--action", "send_message", "--topic", "music")
    p_esc = run(alice, "--json", "policy", "check", "--mail", BOB_MAIL,
                "--action", "send_message", "--topic", "work")
    p_deny = run(alice, "--json", "policy", "check", "--mail", BOB_MAIL,
                 "--action", "send_message", "--private-data")
    assert isinstance(p_allow, dict) and isinstance(p_esc, dict) and isinstance(p_deny, dict)
    check(p_allow["decision"] == "allow", "on-topic message allowed")
    check(p_esc["decision"] == "needs_owner_approval", "off-topic message escalates")
    check(p_deny["decision"] == "deny" and p_deny["code"] == "discretion_private_data",
          "private data denied")

    # 7. Outbound gate -----------------------------------------------------
    step("7. outbound gate", "pre-send checks for message, bundle, private data")
    g_msg = run(alice, "--json", "mail", "outbound", "--mail", BOB_MAIL,
                "--kind", "message", "--subject", "New jazz", "--topic", "music")
    g_bundle = run(alice, "--json", "mail", "outbound", "--mail", BOB_MAIL,
                   "--kind", "capability_bundle", "--bundle", "jazz-picks")
    g_private = run(alice, "--json", "mail", "outbound", "--mail", BOB_MAIL,
                    "--kind", "message", "--private-data")
    assert isinstance(g_msg, dict) and isinstance(g_bundle, dict) and isinstance(g_private, dict)
    check(g_msg["decision"] == "allow", "outbound message allowed")
    check(g_bundle["decision"] == "needs_owner_approval",
          f"friend-tier bundle share escalates ({g_bundle['code']})")
    check(g_private["decision"] == "deny", "outbound private data denied")

    run(alice, "--json", "friends", "pin", friend_id, "--bundle", "jazz-picks",
        "--revision", revision, "--direction", "outbound")
    g_bundle_pinned = run(alice, "--json", "mail", "outbound", "--mail", BOB_MAIL,
                          "--kind", "capability_bundle", "--bundle", "jazz-picks")
    assert isinstance(g_bundle_pinned, dict)
    check(g_bundle_pinned["pinned_outbound_revision"] == revision,
          "outbound gate reports the pinned outbound revision")

    # 8. Thread mirroring --------------------------------------------------
    step("8. threads", "mirror a standing channel thread into a local muse-mcp thread")
    from musefriends.store import Store
    from musefriends.workflow import (
        get_standing_channel,
        lookup_mail_thread,
        mirror_mail_to_mcp,
    )

    store = Store(alice)
    stub = StubMuseMcp()
    first = mirror_mail_to_mcp(
        store, friend_id=friend_id, mail_thread_id="mail-thread-1",
        mcp_client=stub, subject="Jazz?", body="Any new records?", thread_class="channel",
    )
    check(first["created"] is True, "first mail thread created a muse-mcp thread")
    channel_thread = first["mcp_thread_id"]

    second = mirror_mail_to_mcp(
        store, friend_id=friend_id, mail_thread_id="mail-thread-2",
        mcp_client=stub, subject="Books?", body="Any book recs?", thread_class="channel",
    )
    check(second["created"] is False and second["mcp_thread_id"] == channel_thread,
          "second mail thread reused the standing channel thread")
    check(len(stub.threads) == 1, "only one muse-mcp thread exists for the channel")
    check(stub.messages[-1]["thread_id"] == channel_thread, "follow-up posted into the channel")
    check(get_standing_channel(store, friend_id=friend_id)["mcp_thread_id"] == channel_thread,
          "standing channel lookup resolves")

    task = mirror_mail_to_mcp(
        store, friend_id=friend_id, mail_thread_id="mail-task-1",
        mcp_client=stub, subject="Book dinner", body="Please book a table",
        thread_class="task",
    )
    check(task["created"] is True and task["mcp_thread_id"] != channel_thread,
          "task thread spawned alongside the channel")

    linked = run(alice, "--json", "threads", "link", "--friend-id", friend_id,
                 "--mail-thread-id", "mail-thread-9", "--mcp-thread-id", channel_thread,
                 "--class", "channel", "--subject", "Standing channel")
    assert isinstance(linked, dict)
    found = run(alice, "--json", "threads", "lookup", "--mail-thread-id", "mail-thread-9")
    assert isinstance(found, list)
    check(len(found) == 1 and found[0]["mcp_thread_id"] == channel_thread,
          "CLI thread link/lookup round-trips")
    check(len(lookup_mail_thread(store, friend_id=friend_id, thread_class="channel")) == 3,
          "all channel mail threads map to the one standing thread")
    store.close()

    # 9. Revocation closes the door ---------------------------------------
    step("9. revocation", "unfriending ends mail trust immediately")
    run(alice, "--json", "friends", "revoke", friend_id)
    revoked = run(alice, "--json", "mail", "intake", "--from", BOB_MAIL,
                  "--subject", "Jazz?", "--body", "Still there?",
                  "--attachment", str(msg_env))
    assert isinstance(revoked, dict)
    check(revoked["verdict"] == "deny", "revoked friend's mail is denied")
    check(revoked["sender_status"] == "friend_revoked", f"status {revoked['sender_status']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Muse Mail workflow end-to-end drill")
    parser.add_argument("--keep", action="store_true", help="keep the drill work directory")
    parser.add_argument("--workdir", default=None, help="use this work directory")
    args = parser.parse_args(argv)

    if args.workdir:
        workdir = Path(args.workdir).expanduser().resolve()
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        base = ROOT / ".pytest_cache" / "drill"
        base.mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix="mail-drill-", dir=base))

    print(f"drill workdir: {workdir}")
    try:
        drill(workdir)
    except DrillFailure as exc:
        print(f"\nDRILL FAILED\n{exc}", file=sys.stderr)
        print(f"workdir kept for inspection: {workdir}", file=sys.stderr)
        return 1

    checks = sum(1 for kind, _ in STEPS if kind == "assert")
    steps = sum(1 for kind, _ in STEPS if kind == "step")
    print(f"\nDRILL PASSED: {steps} stages, {checks} assertions")
    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)
    else:
        print(f"workdir kept: {workdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
