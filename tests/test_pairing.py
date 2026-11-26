"""Tests for bounded pairing-code flow and local CLI owner approval."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

from starlette.testclient import TestClient

from musefriends.app import create_app
from musefriends.cli import run_cli
from musefriends.identity import IdentityManager, sign_http_request
from musefriends.pairing import CODE_ALPHABET, CODE_TTL_S, MAX_CODE_ATTEMPTS
from musefriends.store import Store


def _make_requester(tmp_path, name: str = "bob"):
    store = Store(tmp_path / name)
    identity = IdentityManager(store)
    card = identity.init_identity(
        handle=name,
        display_name=f"{name.title()}'s Muse",
        url=f"https://{name}.example.invalid",
    )
    key = identity.load_private_key()
    return card, key


def _signed_pair_request(
    client: TestClient,
    *,
    code: str,
    requester_card: dict,
    requester_key,
    now: datetime,
    nonce: str | None = None,
    override_headers: dict[str, str] | None = None,
):
    path = "/friends/v1/request"
    body = json.dumps({"code": code, "card": requester_card}).encode("utf-8")
    headers = sign_http_request(
        requester_key,
        "POST",
        path,
        body,
        timestamp=int(now.timestamp()),
        nonce=nonce or secrets.token_hex(16),
    )
    headers["Content-Type"] = "application/json"
    if override_headers:
        headers.update(override_headers)
    return client.post(path, content=body, headers=headers)


def test_pairing_code_format_hashing_and_single_outstanding(tmp_path):
    now = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
    app = create_app(tmp_path / "alice", clock=lambda: now)
    app.state.identity.init_identity(
        handle="alice",
        display_name="Alice's Muse",
        url="https://alice.example.invalid",
    )

    first = app.state.pairing.mint_code(now=now)
    code1 = first["code"]
    assert len(code1) == 9 and code1[4] == "-"
    raw1 = code1.replace("-", "")
    assert len(raw1) == 8
    assert all(c in CODE_ALPHABET for c in raw1)
    assert first["expires_at"] == "2026-11-26T12:15:00Z"
    assert "https://alice.example.invalid/friends/v1/card" in first["share_text"]

    # Plaintext code must never appear in pairing_codes or audit tables.
    conn = app.state.store.conn
    rows = conn.execute("SELECT * FROM pairing_codes").fetchall()
    assert len(rows) == 1
    assert code1 not in str(dict(rows[0]))
    assert raw1 not in str(dict(rows[0]))
    audit_rows = conn.execute("SELECT * FROM audit").fetchall()
    assert all(code1 not in (r["detail_json"] or "") for r in audit_rows)

    # Minting a second code invalidates the first.
    second = app.state.pairing.mint_code(now=now + timedelta(seconds=10))
    assert second["code_id"] != first["code_id"]
    first_row = conn.execute(
        "SELECT state FROM pairing_codes WHERE id=?", (first["code_id"],)
    ).fetchone()
    assert first_row["state"] == "invalidated"


def test_pairing_happy_path_and_cli_approval(tmp_path, capsys):
    now = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
    alice_dir = tmp_path / "alice"
    app = create_app(alice_dir, clock=lambda: now)
    app.state.identity.init_identity(
        handle="alice",
        display_name="Alice's Muse",
        url="https://alice.example.invalid",
    )
    bob_card, bob_key = _make_requester(tmp_path, "bob")

    minted = app.state.pairing.mint_code(now=now)

    with TestClient(app) as client:
        # Submit with lowercase / unhyphenated code to verify normalization.
        resp = _signed_pair_request(
            client,
            code=minted["code"].replace("-", "").lower(),
            requester_card=bob_card,
            requester_key=bob_key,
            now=now,
        )
        assert resp.status_code == 202
        req_id = resp.json()["request_id"]
        assert resp.json()["status"] == "pending"

        # Single-use: reusing the exact same code fails with uniform error.
        reuse = _signed_pair_request(
            client,
            code=minted["code"],
            requester_card=bob_card,
            requester_key=bob_key,
            now=now + timedelta(seconds=1),
        )
        assert reuse.status_code == 400
        assert reuse.json() == {
            "error": "pairing_unavailable",
            "message": "pairing unavailable",
        }

        # Before owner approval, no friend exists yet.
        assert app.state.pairing.list_friends() == []

    # Owner inspects pending request via local CLI and approves with tier=friend.
    assert run_cli(["--state-dir", str(alice_dir), "--json", "pair", "list", "--state", "pending"]) == 0
    pending = json.loads(capsys.readouterr().out)
    assert len(pending) == 1
    assert pending[0]["request_id"] == req_id
    assert pending[0]["claimed_handle"] == "bob"

    assert (
        run_cli(
            [
                "--state-dir",
                str(alice_dir),
                "--json",
                "pair",
                "approve",
                req_id,
                "--tier",
                "friend",
                "--discretion",
                "No private finances.",
            ]
        )
        == 0
    )
    approved = json.loads(capsys.readouterr().out)
    assert approved["status"] == "approved"
    assert approved["tier"] == "friend"
    assert approved["verified"] is False
    friend_id = approved["friend_id"]

    # Double-approve fails with invalid_state.
    assert run_cli(["--state-dir", str(alice_dir), "pair", "approve", req_id]) == 1
    assert "invalid_state" in capsys.readouterr().err

    # Safety-number verification and revocation via CLI.
    assert run_cli(["--state-dir", str(alice_dir), "--json", "friends", "verify", friend_id]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True

    assert run_cli(["--state-dir", str(alice_dir), "--json", "friends", "revoke", friend_id]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "revoked"

    assert run_cli(["--state-dir", str(alice_dir), "--json", "friends", "list"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_pairing_denial_creates_no_friend(tmp_path, capsys):
    now = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
    alice_dir = tmp_path / "alice"
    app = create_app(alice_dir, clock=lambda: now)
    app.state.identity.init_identity(
        handle="alice",
        display_name="Alice's Muse",
        url="https://alice.example.invalid",
    )
    bob_card, bob_key = _make_requester(tmp_path, "bob")
    minted = app.state.pairing.mint_code(now=now)

    with TestClient(app) as client:
        resp = _signed_pair_request(
            client,
            code=minted["code"],
            requester_card=bob_card,
            requester_key=bob_key,
            now=now,
        )
        assert resp.status_code == 202
        req_id = resp.json()["request_id"]

    assert run_cli(["--state-dir", str(alice_dir), "--json", "pair", "deny", req_id, "--note", "unknown"]) == 0
    assert json.loads(capsys.readouterr().out) == {"request_id": req_id, "status": "denied"}

    assert run_cli(["--state-dir", str(alice_dir), "--json", "friends", "list", "--all"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_pairing_expiry_attempt_cap_and_uniform_errors(tmp_path):
    clock = [datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)]
    app = create_app(tmp_path / "alice", clock=lambda: clock[0])
    app.state.identity.init_identity(
        handle="alice",
        display_name="Alice's Muse",
        url="https://alice.example.invalid",
    )
    bob_card, bob_key = _make_requester(tmp_path, "bob")

    expected_err = {"error": "pairing_unavailable", "message": "pairing unavailable"}

    with TestClient(app) as client:
        # 1. Unknown code (no code minted yet)
        r_unknown = _signed_pair_request(
            client,
            code="AAAA-BBBB",
            requester_card=bob_card,
            requester_key=bob_key,
            now=clock[0],
        )
        assert r_unknown.status_code == 400
        assert r_unknown.json() == expected_err

        # 2. Expired code (past 15-minute TTL)
        exp_code = app.state.pairing.mint_code(now=clock[0])["code"]
        clock[0] = clock[0] + timedelta(seconds=CODE_TTL_S + 1)
        r_expired = _signed_pair_request(
            client,
            code=exp_code,
            requester_card=bob_card,
            requester_key=bob_key,
            now=clock[0],
        )
        assert r_expired.status_code == 400
        assert r_expired.json() == expected_err

        # 3. 5-attempt cap exhausts the active code; even the real code fails on #6.
        live = app.state.pairing.mint_code(now=clock[0])
        for i in range(MAX_CODE_ATTEMPTS):
            wrong = _signed_pair_request(
                client,
                code=f"1111-222{i + 1}",
                requester_card=bob_card,
                requester_key=bob_key,
                now=clock[0],
            )
            assert wrong.status_code == 400
            assert wrong.json() == expected_err

        r_exhausted = _signed_pair_request(
            client,
            code=live["code"],
            requester_card=bob_card,
            requester_key=bob_key,
            now=clock[0],
        )
        assert r_exhausted.status_code == 400
        assert r_exhausted.json() == expected_err

        row = app.state.store.conn.execute(
            "SELECT state, attempts FROM pairing_codes WHERE id=?", (live["code_id"],)
        ).fetchone()
        assert row["state"] == "exhausted"
        assert row["attempts"] == MAX_CODE_ATTEMPTS


def test_pairing_request_signature_replay_and_rate_limit(tmp_path):
    now = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
    app = create_app(tmp_path / "alice", rate_limit_per_min=5, clock=lambda: now)
    app.state.identity.init_identity(
        handle="alice",
        display_name="Alice's Muse",
        url="https://alice.example.invalid",
    )
    bob_card, bob_key = _make_requester(tmp_path, "bob")
    minted = app.state.pairing.mint_code(now=now)

    with TestClient(app) as client:
        # Bad signature -> 401 unauthorized
        r_bad_sig = _signed_pair_request(
            client,
            code=minted["code"],
            requester_card=bob_card,
            requester_key=bob_key,
            now=now,
            override_headers={"X-Muse-Friend-Signature": "AAAA"},
        )
        assert r_bad_sig.status_code == 401
        assert r_bad_sig.json()["error"] == "unauthorized"

        # Stale timestamp (> 120s) -> 401 unauthorized
        r_stale = _signed_pair_request(
            client,
            code=minted["code"],
            requester_card=bob_card,
            requester_key=bob_key,
            now=now - timedelta(seconds=121),
        )
        assert r_stale.status_code == 401
        assert r_stale.json()["error"] == "unauthorized"

        # Replayed nonce -> 401 unauthorized
        reused_nonce = "fixed-nonce-123456"
        r_ok = _signed_pair_request(
            client,
            code=minted["code"],
            requester_card=bob_card,
            requester_key=bob_key,
            now=now,
            nonce=reused_nonce,
        )
        assert r_ok.status_code == 202

        r_replay = _signed_pair_request(
            client,
            code=minted["code"],
            requester_card=bob_card,
            requester_key=bob_key,
            now=now,
            nonce=reused_nonce,
        )
        assert r_replay.status_code == 401
        assert r_replay.json()["error"] == "unauthorized"

        # 5th call hits limit cap; 6th call returns 429 rate_limited.
        _signed_pair_request(
            client,
            code="AAAA-BBBB",
            requester_card=bob_card,
            requester_key=bob_key,
            now=now,
        )
        r_limited = _signed_pair_request(
            client,
            code="AAAA-BBBB",
            requester_card=bob_card,
            requester_key=bob_key,
            now=now,
        )
        assert r_limited.status_code == 429
        assert r_limited.json()["error"] == "rate_limited"
