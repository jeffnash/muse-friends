# Start here: install muse-friends

Give this file (and the repo it lives in) to the Muse who should gain muse-friends. muse-friends is the trust and policy layer that lets a Muse work with other people's Muses over Muse Mail: verified identity, owner-approved pairing, and per-friend sharing rules.

Read this whole prompt before running anything. Most failures below have already happened to someone; the checks exist so they do not happen to you.

## Prerequisites, checked not assumed

- **A Muse Mail address for this Muse.** Without one there is nothing to bind an identity to. Check by sending or reading mail through the Muse Mail connector. If this Muse has no Muse Mail address, stop and tell the owner; do not substitute a regular email address, the verification model depends on Muse Mail.
- **Python 3.11 or newer.** Check: `python3 --version`. The package uses `pyproject.toml` with a src layout; it will not import from a bare checkout without installation (see the install trap below).
- **A friend whose Muse also installs muse-friends.** Pairing takes two. Installing solo is fine (identity plus drill), but set the owner's expectation: nothing pairs until the other side exists.

## Step 1: install, then prove it with the drill

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python scripts/mail_drill.py   # must end with: DRILL PASSED: 9 stages, 46 assertions
.venv/bin/python -m pytest -q            # must be all green
```

- **Install trap:** running the CLI from the checkout without installing fails with `ModuleNotFoundError: No module named 'musefriends'`. That is the src layout, not a broken repo. Either `pip install -e .` (preferred) or prefix commands with `PYTHONPATH=src`.
- **Drill failure triage.** The drill prints the stage that failed. A failure in card exchange or verification usually means a cryptography dependency problem in the venv (rebuild it from scratch before debugging code). A failure in bundle pinning or intake is a real behavior problem: stop, keep the drill's work directory (`--keep`), and report the stage and assertion to the owner. Never edit source to make the drill pass during an install; if the drill fails on a clean checkout at the pinned commit, that is a finding to report, not to patch over.
- **Pytest warning:** one Starlette/httpx deprecation warning is pre-existing and harmless. Any other warning or failure is not.

## Step 2: create this Muse's identity

- Pick the state directory first and use it consistently: pass `--state-dir <path>` on every command or set `MUSE_FRIENDS_STATE_DIR`. **The single most common operating mistake is running commands against two different state directories** and concluding that friends or the identity "disappeared". They did not; you are looking at a different store. The directory must be mode 0700 and outside any git checkout.
- Create it: `muse-friends identity init --handle <handle> --display-name "<the name friends should see>"`. Ask the owner for the handle and display name; do not invent a persona for them.
- Show the owner the fingerprint and safety number (`muse-friends identity show`) and record nothing about the private key anywhere. The key file never leaves the state directory: never paste it into mail, chat, a commit, or a log.
- **If an identity already exists, stop.** `identity init --overwrite` archives the old card and creates a NEW key. Every existing pairing silently stops verifying, because friends pinned the old key, and signed key-rotation statements are specified but NOT implemented yet, so there is no graceful path. Overwriting an established identity is an owner decision with consequences stated out loud, never a troubleshooting step.

## Step 3: pair with a friend (owner approves every step)

Pairing is a choreography between two Muses and two owners, and the pairing code expires 15 minutes after it is minted. **Mint the code only when both sides are ready to complete the exchange in one sitting.**

1. One side mints: `muse-friends pair mint`. If the code expires mid-exchange, mint a fresh one; an expired code fails closed and tells you nothing about the other side's state.
2. Exchange signed friend cards over Muse Mail. muse-friends does not send mail: you send it with your Muse Mail tools, attaching the output of `muse-friends card export`, signed with `muse-friends mail sign`. Tell the receiving Muse exactly which attachment is the card; a card pasted as message text with mangled whitespace will not verify.
3. Verify what arrived before trusting anything in it: `muse-friends mail verify`, and inspect with `muse-friends card import`.
4. **Verification failure triage**, in the order it actually happens:
   - *Clock skew.* Signed envelopes carry timestamps with a ±120 second replay window. If both machines' clocks differ by more than that, verification fails on every message. Check the clocks before suspecting keys.
   - *Wrong state directory* (see Step 2). Verify you are reading the store that holds the friend record.
   - *The friend re-created their identity* after you received their card. Their new key invalidates the old card; ask them to re-export.
   - *Address mismatch.* The friend record binds a specific Muse Mail address to the key. Mail from a different address, even with a valid signature, is a different (unpaired) sender.
5. Each owner approves on their own side and chooses the friend's trust tier and discretion profile: `muse-friends pair approve`. Tier and profile are the owner's values decision; propose, never decide. Start conservative (acquaintance) when the owner is unsure; tiers can be raised later with approval, and an over-broad profile cannot un-send what already went out.
6. Complete over mail: `muse-friends mail complete-pairing`. Then confirm both directions: `muse-friends friends list` on both sides should show the pairing with the same safety number.
7. Compare safety numbers out of band (a call, a message on another channel) and mark it done: `muse-friends friends verify`. A pairing whose safety numbers were never compared is provisionally trusted at best; say so in your report if the owners skipped it.

## Step 4: operate

- Follow `docs/MAIL_WORKFLOW.md` for friend traffic. Run `muse-friends mail intake` on every inbound friend message and act only on its verdict. `needs_owner_approval` means exactly that: escalate, do not act autonomously. Run `muse-friends mail outbound` before sending anything to a friend; a gate refusal is the discretion profile working, not an error to route around.
- Capability bundles: accept one only after it verifies, then pin the revision (`muse-friends friends pin`). A changed bundle fails verification until the owner re-pins. Never re-pin on the friend's say-so alone; the owner approves content changes from another Muse the same way they approve code from a stranger.
- Never raise a tier, widen a discretion profile, or complete a pairing without the owner's explicit approval in the moment. A standing "you handle my friends" is not approval for a specific new friend.
- Revocation is immediate and one-sided: `muse-friends friends revoke`. Use it the moment the owner asks, and confirm afterwards that intake now treats that sender as a stranger.

## Report to the owner

- The drill result line and the pytest count, verbatim.
- The identity fingerprint and safety number, and where the state directory lives.
- For each pairing: the friend's handle, the tier and discretion profile the owner chose, whether safety numbers were compared out of band, and anything that failed verification along the way.
- What is NOT done, stated plainly: no pairing yet, rotation unimplemented, or the drill was never run against a real Muse Mail account (the local drill uses crafted messages; the platform mailbox path is a separate, later test).

## Done means

The drill passes on the installed code, the identity exists in a mode-0700 state directory, and either at least one pairing has completed with both owners' approval and matching safety numbers, or the owner chose to stop after the drill.
