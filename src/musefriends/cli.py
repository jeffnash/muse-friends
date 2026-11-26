"""Local owner CLI for muse-friends (identity, friend cards, pairing approval)."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

from .bundles import (
    KNOWN_BUNDLE_KINDS,
    load_files_from_directory,
    package_capability_bundle,
    verify_capability_bundle,
)
from .errors import FriendsError
from .identity import IdentityManager, key_fingerprint
from .mail import (
    KNOWN_ENVELOPE_KINDS,
    KNOWN_PIN_DIRECTIONS,
    complete_mail_pairing,
    list_capability_pins,
    pin_capability_bundle,
    sign_mail_envelope,
    verify_incoming_mail,
)
from .pairing import DEFAULT_TIER, KNOWN_TIERS, PairingManager
from .policy import KNOWN_ACTIONS, KNOWN_REQUEST_KINDS, evaluate_policy
from .store import Store
from .workflow import (
    KNOWN_OUTBOUND_KINDS,
    KNOWN_THREAD_CLASSES,
    check_mail_outbound,
    evaluate_mail_intake,
    link_mail_thread,
    lookup_mail_thread,
)


def _emit(data: object, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
    elif isinstance(data, str):
        print(data)
    else:
        print(json.dumps(data, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="muse-friends",
        description="Local owner CLI for muse-friendsd",
    )
    parser.add_argument(
        "--state-dir",
        default=os.environ.get("MUSE_FRIENDS_STATE_DIR", "data"),
        help="Daemon state directory (default: $MUSE_FRIENDS_STATE_DIR or ./data)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output machine-readable JSON",
    )

    sub = parser.add_subparsers(dest="group", required=True)

    # identity
    p_id = sub.add_parser("identity", help="Manage local Ed25519 identity")
    id_sub = p_id.add_subparsers(dest="cmd", required=True)
    p_id_init = id_sub.add_parser("init", help="Generate Ed25519 keypair and signed friend card")
    p_id_init.add_argument("--handle", required=True)
    p_id_init.add_argument("--display-name", required=True)
    p_id_init.add_argument("--url", required=True)
    p_id_init.add_argument("--friend-api", default=None)
    p_id_init.add_argument("--overwrite", action="store_true")
    id_sub.add_parser("show", help="Show local identity and safety number")

    # card
    p_card = sub.add_parser("card", help="Export or verify/import friend cards")
    card_sub = p_card.add_subparsers(dest="cmd", required=True)
    p_card_export = card_sub.add_parser("export", help="Export signed friend card JSON")
    p_card_export.add_argument("--out", default=None, help="Write card JSON to file")
    p_card_import = card_sub.add_parser("import", help="Verify and inspect an external friend card")
    p_card_import.add_argument("path", help="Path to friend card JSON file (or '-' for stdin)")

    # pair
    p_pair = sub.add_parser("pair", help="Mint pairing codes and approve/deny requests")
    pair_sub = p_pair.add_subparsers(dest="cmd", required=True)
    pair_sub.add_parser("mint", help="Mint a single-use pairing code (15m TTL)")
    p_pair_list = pair_sub.add_parser("list", help="List friend requests")
    p_pair_list.add_argument(
        "--state",
        choices=("pending", "approved", "denied"),
        default=None,
    )
    p_pair_approve = pair_sub.add_parser("approve", help="Approve a pending friend request")
    p_pair_approve.add_argument("request_id")
    p_pair_approve.add_argument("--tier", choices=KNOWN_TIERS, default=DEFAULT_TIER)
    p_pair_approve.add_argument("--discretion", default="")
    p_pair_approve.add_argument("--note", default=None)
    p_pair_deny = pair_sub.add_parser("deny", help="Deny a pending friend request")
    p_pair_deny.add_argument("request_id")
    p_pair_deny.add_argument("--note", default=None)

    # friends
    p_friends = sub.add_parser("friends", help="Inspect, verify, pin, or revoke approved friends")
    fr_sub = p_friends.add_subparsers(dest="cmd", required=True)
    p_fr_list = fr_sub.add_parser("list", help="List friends")
    p_fr_list.add_argument("--all", action="store_true", dest="include_revoked")
    p_fr_verify = fr_sub.add_parser("verify", help="Mark a friend's safety number verified")
    p_fr_verify.add_argument("friend_id")
    p_fr_revoke = fr_sub.add_parser("revoke", help="Unfriend / revoke a friend immediately")
    p_fr_revoke.add_argument("friend_id")
    p_fr_pin = fr_sub.add_parser("pin", help="Pin a signed capability-bundle revision hash for a friend")
    p_fr_pin.add_argument("friend_id")
    p_fr_pin.add_argument("--bundle", required=True, dest="bundle_name")
    p_fr_pin.add_argument("--revision", required=True, dest="revision_hash")
    p_fr_pin.add_argument("--direction", choices=KNOWN_PIN_DIRECTIONS, default="inbound")
    p_fr_pin.add_argument("--note", default=None)
    p_fr_pins = fr_sub.add_parser("pins", help="List pinned capability-bundle revisions for a friend")
    p_fr_pins.add_argument("friend_id")

    # mail
    p_mail = sub.add_parser("mail", help="Muse Mail trust verification and mail-confirmed pairing")
    mail_sub = p_mail.add_subparsers(dest="cmd", required=True)
    p_mail_sign = mail_sub.add_parser("sign", help="Sign a Muse Mail envelope with local identity")
    p_mail_sign.add_argument("--sender-mail", required=True)
    p_mail_sign.add_argument("--kind", choices=KNOWN_ENVELOPE_KINDS, default="message")
    p_mail_sign.add_argument("--payload", required=True, help="JSON object string or @path")
    p_mail_sign.add_argument("--recipient-mail", default=None)
    p_mail_sign.add_argument("--out", default=None)

    p_mail_verify = mail_sub.add_parser(
        "verify",
        help="Verify a signed incoming friend card or mail envelope against a friend record",
    )
    p_mail_verify.add_argument("--sender-mail", required=True)
    verify_src = p_mail_verify.add_mutually_exclusive_group(required=True)
    verify_src.add_argument("--envelope", help="Path to signed mail envelope JSON (or '-')")
    verify_src.add_argument("--card", help="Path to signed friend card JSON (or '-')")
    p_mail_verify.add_argument("--friend-id", default=None)

    p_mail_pair = mail_sub.add_parser(
        "complete-pairing",
        help="Complete a mail-confirmed pairing with local owner approval",
    )
    p_mail_pair.add_argument("--sender-mail", required=True)
    p_mail_pair.add_argument("--envelope", required=True, help="Path to signed confirmation envelope JSON (or '-')")
    p_mail_pair.add_argument("--code-id", default=None)
    p_mail_pair.add_argument("--owner-approve", action="store_true", dest="owner_approve")
    p_mail_pair.add_argument("--tier", choices=KNOWN_TIERS, default=DEFAULT_TIER)
    p_mail_pair.add_argument("--discretion", default="")
    p_mail_pair.add_argument("--note", default=None)

    p_mail_intake = mail_sub.add_parser(
        "intake",
        help="Evaluate an incoming Muse Mail message against registry, signatures, pins, and policy",
    )
    p_mail_intake.add_argument("--from", required=True, dest="from_address")
    p_mail_intake.add_argument("--subject", default="")
    p_mail_intake.add_argument("--body", default="")
    p_mail_intake.add_argument("--mail-thread-id", default=None)
    p_mail_intake.add_argument("--attachment", action="append", default=[], dest="attachments")
    p_mail_intake.add_argument("--request-kind", choices=KNOWN_REQUEST_KINDS, default=None)
    p_mail_intake.add_argument("--topic", action="append", default=[], dest="topics")
    p_mail_intake.add_argument("--private-data", action="store_true", dest="touches_private_data")
    p_mail_intake.add_argument("--external-side-effects", action="store_true", dest="external_side_effects")
    p_mail_intake.add_argument("--sensitive", action="store_true")

    p_mail_outbound = mail_sub.add_parser(
        "outbound",
        help="Pre-send policy check for outgoing friend mail or capability bundles",
    )
    out_target = p_mail_outbound.add_mutually_exclusive_group(required=True)
    out_target.add_argument("--friend-id", default=None)
    out_target.add_argument("--mail", default=None, dest="mail_address")
    p_mail_outbound.add_argument("--kind", choices=KNOWN_OUTBOUND_KINDS, default="message")
    p_mail_outbound.add_argument("--subject", default="")
    p_mail_outbound.add_argument("--bundle", default=None, dest="bundle_name")
    p_mail_outbound.add_argument("--topic", action="append", default=[], dest="topics")
    p_mail_outbound.add_argument("--private-data", action="store_true", dest="touches_private_data")
    p_mail_outbound.add_argument("--external-side-effects", action="store_true", dest="external_side_effects")
    p_mail_outbound.add_argument("--sensitive", action="store_true")

    # bundle
    p_bundle = sub.add_parser("bundle", help="Package and verify signed capability bundles over Muse Mail")
    bnd_sub = p_bundle.add_subparsers(dest="cmd", required=True)
    p_bnd_pack = bnd_sub.add_parser("pack", help="Package and sign a directory as a capability-bundle envelope")
    p_bnd_pack.add_argument("--sender-mail", required=True)
    p_bnd_pack.add_argument("--recipient-mail", default=None)
    p_bnd_pack.add_argument("--bundle", required=True, dest="bundle_name")
    p_bnd_pack.add_argument("--kind", choices=KNOWN_BUNDLE_KINDS, default="skill", dest="bundle_kind")
    p_bnd_pack.add_argument("--dir", required=True, dest="bundle_dir")
    p_bnd_pack.add_argument("--metadata", default=None, help="Optional JSON object or @path")
    p_bnd_pack.add_argument("--out", default=None)

    p_bnd_verify = bnd_sub.add_parser(
        "verify",
        help="Verify a signed capability-bundle envelope against friend registry and revision pins",
    )
    p_bnd_verify.add_argument("--sender-mail", required=True)
    p_bnd_verify.add_argument("--envelope", required=True, help="Path to signed bundle envelope JSON (or '-')")
    p_bnd_verify.add_argument("--friend-id", default=None)
    p_bnd_verify.add_argument("--direction", choices=KNOWN_PIN_DIRECTIONS, default="inbound")

    # threads
    p_threads = sub.add_parser("threads", help="Map Muse Mail threads to local muse-mcp channel/task threads")
    thr_sub = p_threads.add_subparsers(dest="cmd", required=True)
    p_thr_link = thr_sub.add_parser("link", help="Record or update a mail <-> muse-mcp thread link")
    p_thr_link.add_argument("--friend-id", required=True)
    p_thr_link.add_argument("--mail-thread-id", required=True)
    p_thr_link.add_argument("--mcp-thread-id", required=True)
    p_thr_link.add_argument("--class", choices=KNOWN_THREAD_CLASSES, default="channel", dest="thread_class")
    p_thr_link.add_argument("--subject", default="")

    p_thr_lookup = thr_sub.add_parser("lookup", help="Look up mail <-> muse-mcp thread mappings")
    p_thr_lookup.add_argument("--mail-thread-id", default=None)
    p_thr_lookup.add_argument("--mcp-thread-id", default=None)
    p_thr_lookup.add_argument("--friend-id", default=None)
    p_thr_lookup.add_argument("--class", choices=KNOWN_THREAD_CLASSES, default=None, dest="thread_class")

    # policy
    p_policy = sub.add_parser("policy", help="Evaluate per-friend tier and discretion policy")
    pol_sub = p_policy.add_subparsers(dest="cmd", required=True)
    p_pol_check = pol_sub.add_parser("check", help="Check allow / deny / needs_owner_approval for a friend action")
    pol_target = p_pol_check.add_mutually_exclusive_group(required=True)
    pol_target.add_argument("--friend-id", default=None)
    pol_target.add_argument("--mail", default=None, dest="mail_address")
    p_pol_check.add_argument("--action", choices=KNOWN_ACTIONS, required=True)
    p_pol_check.add_argument("--request-kind", choices=KNOWN_REQUEST_KINDS, default="question")
    p_pol_check.add_argument("--topic", action="append", default=[], dest="topics")
    p_pol_check.add_argument("--private-data", action="store_true", dest="touches_private_data")
    p_pol_check.add_argument("--external-side-effects", action="store_true", dest="external_side_effects")
    p_pol_check.add_argument("--sensitive", action="store_true")

    return parser


def _load_json_arg(path_or_stdin: str) -> dict:
    raw = (
        sys.stdin.read()
        if path_or_stdin == "-"
        else pathlib.Path(path_or_stdin).read_text(encoding="utf-8")
    )
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise FriendsError("invalid_json", f"invalid JSON input: {path_or_stdin}") from exc
    if not isinstance(data, dict):
        raise FriendsError("invalid_json", "JSON input must be an object")
    return data


def _write_output(path: str, text: str) -> None:
    """Write a CLI output file, reporting filesystem failures as clean errors."""
    try:
        pathlib.Path(path).write_text(text, encoding="utf-8")
    except OSError as exc:
        raise FriendsError(
            "output_unwritable", f"cannot write {path}: {exc.strerror or exc}"
        ) from exc


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store = Store(args.state_dir)
    identity = IdentityManager(store)
    pairing = PairingManager(store, identity)
    try:
        if args.group == "identity":
            if args.cmd == "init":
                card = identity.init_identity(
                    handle=args.handle,
                    display_name=args.display_name,
                    url=args.url,
                    friend_api=args.friend_api,
                    overwrite=args.overwrite,
                )
                out = {
                    "card": card,
                    "fingerprint": key_fingerprint(card["public_key"]),
                }
                _emit(out, as_json=args.as_json)
            elif args.cmd == "show":
                card = identity.current_card()
                out = {
                    "card": card,
                    "fingerprint": key_fingerprint(card["public_key"]),
                }
                _emit(out, as_json=args.as_json)

        elif args.group == "card":
            if args.cmd == "export":
                text = identity.export_card_json()
                if args.out:
                    _write_output(args.out, text + "\n")
                    _emit({"exported": args.out}, as_json=args.as_json)
                else:
                    print(text)
            elif args.cmd == "import":
                raw = (
                    sys.stdin.read()
                    if args.path == "-"
                    else pathlib.Path(args.path).read_text(encoding="utf-8")
                )
                result = identity.import_card(raw)
                if args.as_json:
                    _emit(result, as_json=True)
                else:
                    c = result["card"]
                    print(f"Verified friend card (claimed identity):")
                    print(f"  claimed handle:       {c['handle']}")
                    print(f"  claimed display_name: {c['display_name']}")
                    print(f"  friend_api:           {c['friend_api']}")
                    print(f"  safety number:        {result['fingerprint']}")

        elif args.group == "pair":
            if args.cmd == "mint":
                minted = pairing.mint_code()
                if args.as_json:
                    _emit(minted, as_json=True)
                else:
                    print(minted["share_text"])
                    print(f"expires_at: {minted['expires_at']}")
            elif args.cmd == "list":
                reqs = pairing.list_requests(state=args.state)
                if args.as_json:
                    _emit(reqs, as_json=True)
                elif not reqs:
                    print("No friend requests.")
                else:
                    for r in reqs:
                        print(
                            f"{r['request_id']}  [{r['state']}]  "
                            f"claimed='{r['claimed_display_name']}' ({r['claimed_handle']})  "
                            f"fp={r['requester_fingerprint']}"
                        )
            elif args.cmd == "approve":
                res = pairing.approve_request(
                    args.request_id,
                    tier=args.tier,
                    discretion_profile=args.discretion,
                    note=args.note,
                )
                _emit(res, as_json=args.as_json)
            elif args.cmd == "deny":
                res = pairing.deny_request(args.request_id, note=args.note)
                _emit(res, as_json=args.as_json)

        elif args.group == "friends":
            if args.cmd == "list":
                friends = pairing.list_friends(include_revoked=args.include_revoked)
                if args.as_json:
                    _emit(friends, as_json=True)
                elif not friends:
                    print("No friends.")
                else:
                    for f in friends:
                        v = "verified" if f["verified"] else "unverified"
                        print(
                            f"{f['friend_id']}  [{f['state']}]  tier={f['tier']} ({v})  "
                            f"{f['display_name']} ({f['handle']})  fp={f['fingerprint']}"
                        )
            elif args.cmd == "verify":
                res = pairing.verify_friend(args.friend_id)
                _emit(res, as_json=args.as_json)
            elif args.cmd == "revoke":
                res = pairing.revoke_friend(args.friend_id)
                _emit(res, as_json=args.as_json)
            elif args.cmd == "pin":
                res = pin_capability_bundle(
                    store,
                    friend_id=args.friend_id,
                    bundle_name=args.bundle_name,
                    revision_hash=args.revision_hash,
                    direction=args.direction,
                    note=args.note,
                )
                _emit(res, as_json=args.as_json)
            elif args.cmd == "pins":
                pins = list_capability_pins(store, friend_id=args.friend_id)
                if args.as_json:
                    _emit(pins, as_json=True)
                elif not pins:
                    print("No pinned capability bundles.")
                else:
                    for p in pins:
                        print(
                            f"{p['bundle_name']}  [{p['direction']}]  "
                            f"rev={p['revision_hash']}  pinned_at={p['pinned_at']}"
                        )

        elif args.group == "mail":
            if args.cmd == "sign":
                payload_spec = args.payload
                if payload_spec.startswith("@"):
                    payload_obj = _load_json_arg(payload_spec[1:])
                else:
                    try:
                        payload_obj = json.loads(payload_spec)
                    except ValueError as exc:
                        raise FriendsError("invalid_json", "--payload must be valid JSON") from exc
                env = sign_mail_envelope(
                    identity.load_private_key(),
                    sender_mail=args.sender_mail,
                    payload=payload_obj,
                    kind=args.kind,
                    recipient_mail=args.recipient_mail,
                )
                text = json.dumps(env, indent=2, sort_keys=True)
                if args.out:
                    _write_output(args.out, text + "\n")
                    _emit({"written": args.out}, as_json=args.as_json)
                else:
                    print(text)
            elif args.cmd == "verify":
                envelope = _load_json_arg(args.envelope) if args.envelope else None
                card = _load_json_arg(args.card) if args.card else None
                res = verify_incoming_mail(
                    store,
                    sender_mail=args.sender_mail,
                    envelope=envelope,
                    card=card,
                    friend_id=args.friend_id,
                )
                if args.as_json:
                    _emit(res, as_json=True)
                else:
                    verdict = "ACCEPT" if res["accepted"] else "REJECT"
                    print(f"{verdict} [{res['code']}]: {res['reason']}")
                return 0 if res["accepted"] else 1
            elif args.cmd == "complete-pairing":
                env = _load_json_arg(args.envelope)
                res = complete_mail_pairing(
                    store,
                    identity,
                    confirmation_envelope=env,
                    sender_mail=args.sender_mail,
                    owner_approved=args.owner_approve,
                    code_id=args.code_id,
                    tier=args.tier,
                    discretion_profile=args.discretion,
                    note=args.note,
                )
                _emit(res, as_json=args.as_json)
            elif args.cmd == "intake":
                res = evaluate_mail_intake(
                    store,
                    from_address=args.from_address,
                    subject=args.subject,
                    body=args.body,
                    attachments=args.attachments,
                    mail_thread_id=args.mail_thread_id,
                    request_kind=args.request_kind,
                    topics=args.topics,
                    touches_private_data=args.touches_private_data,
                    external_side_effects=args.external_side_effects,
                    sensitive=args.sensitive,
                )
                if args.as_json:
                    _emit(res, as_json=True)
                else:
                    print(
                        f"{res['sender_status']} -> {res['verdict']} [{res['code']}]: {res['reason']}"
                    )
            elif args.cmd == "outbound":
                res = check_mail_outbound(
                    store,
                    friend_id=args.friend_id,
                    mail_address=args.mail_address,
                    kind=args.kind,
                    subject=args.subject,
                    bundle_name=args.bundle_name,
                    topics=args.topics,
                    touches_private_data=args.touches_private_data,
                    external_side_effects=args.external_side_effects,
                    sensitive=args.sensitive,
                )
                if args.as_json:
                    _emit(res, as_json=True)
                else:
                    print(f"{res['decision']} [{res['code']}]: {res['reason']}")

        elif args.group == "bundle":
            if args.cmd == "pack":
                files = load_files_from_directory(args.bundle_dir)
                metadata = None
                if args.metadata is not None:
                    if args.metadata.startswith("@"):
                        metadata = _load_json_arg(args.metadata[1:])
                    else:
                        try:
                            metadata = json.loads(args.metadata)
                        except ValueError as exc:
                            raise FriendsError("invalid_json", "--metadata must be valid JSON") from exc
                env = package_capability_bundle(
                    identity.load_private_key(),
                    sender_mail=args.sender_mail,
                    recipient_mail=args.recipient_mail,
                    bundle_name=args.bundle_name,
                    bundle_kind=args.bundle_kind,
                    files=files,
                    metadata=metadata,
                )
                text = json.dumps(env, indent=2, sort_keys=True)
                if args.out:
                    _write_output(args.out, text + "\n")
                    _emit(
                        {
                            "written": args.out,
                            "bundle_name": args.bundle_name,
                            "revision_hash": env["payload"]["revision_hash"],
                        },
                        as_json=args.as_json,
                    )
                else:
                    print(text)
            elif args.cmd == "verify":
                env = _load_json_arg(args.envelope)
                res = verify_capability_bundle(
                    store,
                    sender_mail=args.sender_mail,
                    envelope=env,
                    friend_id=args.friend_id,
                    direction=args.direction,
                )
                if args.as_json:
                    _emit(res, as_json=True)
                else:
                    verdict = "ACCEPT" if res["accepted"] else "REJECT"
                    print(f"{verdict} [{res['code']}]: {res['reason']}")
                return 0 if res["accepted"] else 1

        elif args.group == "threads":
            if args.cmd == "link":
                res = link_mail_thread(
                    store,
                    friend_id=args.friend_id,
                    mail_thread_id=args.mail_thread_id,
                    mcp_thread_id=args.mcp_thread_id,
                    thread_class=args.thread_class,
                    subject=args.subject,
                )
                _emit(res, as_json=args.as_json)
            elif args.cmd == "lookup":
                rows = lookup_mail_thread(
                    store,
                    mail_thread_id=args.mail_thread_id,
                    mcp_thread_id=args.mcp_thread_id,
                    friend_id=args.friend_id,
                    thread_class=args.thread_class,
                )
                if args.as_json:
                    _emit(rows, as_json=True)
                elif not rows:
                    print("No linked threads.")
                else:
                    for r in rows:
                        print(
                            f"{r['mail_thread_id']} <-> {r['mcp_thread_id']}  "
                            f"[{r['thread_class']}/{r['state']}]  friend={r['friend_id']}"
                        )

        elif args.group == "policy":
            if args.cmd == "check":
                res = evaluate_policy(
                    store,
                    action=args.action,
                    friend_id=args.friend_id,
                    mail_address=args.mail_address,
                    request_kind=args.request_kind,
                    topics=args.topics,
                    touches_private_data=args.touches_private_data,
                    external_side_effects=args.external_side_effects,
                    sensitive=args.sensitive,
                )
                if args.as_json:
                    _emit(res, as_json=True)
                else:
                    print(f"{res['decision']} [{res['code']}]: {res['reason']}")
        return 0
    except FriendsError as exc:
        print(f"error [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1
    finally:
        store.close()


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
