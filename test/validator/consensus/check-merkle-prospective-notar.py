#!/usr/bin/env python3
"""Run the prospective-notarization Merkle actor test and judge its outcome.

The test binary controls certificate arrival and prints what it established before it
triggered resolution. This script decides pass or fail from that transcript, not from the
exit code alone: an abort, a timeout or a broken fixture must never pass as the outcome
being asserted.

Expectations:
  green    exact-ancestor resolver: waits on P, then resolves to state n+1
  bounded  exact-ancestor resolver, P unobtainable: bounded notready refusal
  control  NotarCert(P) installed before resolution: state n+1 (either resolver)
  gate     the hold is misaimed, and the harness must refuse to run the scenario
  red      skip-shortcut resolver: aborts applying C's update to state n-1
  peer-green  two nodes, NotarCert(P) only on the peer, real Consensus leader path:
              the window starts on state n+1 after P is fetched from the peer
  peer-red    the same ordering against the skip-shortcut resolver: N/N-1 abort,
              P never requested
  sibling     two observers, siblings P and P' notarized at one height, FinalizeCert(C)
              on P's branch: both finalize P and never P', and both resolve C to the same
              block and state n+1 even with P' resolved and cached first
  sibling-red the sibling-substituting resolver: aborts applying C's update to P''s state
  anchor      two observers, P finalized while its manager anchor is delayed: the first
              resolves C by reconstruction, the second from P's anchor after release; both
              reach the same block and state n+1 and neither reads the older anchor A
  anchor-red  the resolver that falls back to the start state while the anchor is late:
              aborts applying C's update to the zerostate

The red expectations run the binary built against the test-only mutant resolver
(make-state-resolver-mutant.py), with the mutation selected through the environment; every
other expectation must run the production build. Each binary reports which it is.
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys


def cell_hash(tag: int, seqno: int) -> str:
    # An ordinary cell holding a 32-bit tag and seqno. Its representation hash is
    # sha256(d1 d2 data); d1 = 0 refs, d2 = 8 whole bytes.
    data = tag.to_bytes(4, "big") + seqno.to_bytes(4, "big")
    return hashlib.sha256(bytes([0, 16]) + data).hexdigest()


def state_hash(seqno: int) -> str:
    # gen_shard_state(seqno)
    return cell_hash(0xABCDABCD, seqno)


def sibling_state_hash(seqno: int) -> str:
    # gen_sibling_state(seqno): the state of the sibling P' at the same height
    return cell_hash(0x51B11A6E, seqno)


MODES = {
    "green": "hold-release",
    "bounded": "hold-refuse",
    "control": "no-hold",
    "gate": "hold-wrong-slot",
    "red": "hold-release",
    "peer-green": "peer-consensus",
    "peer-red": "peer-consensus",
    "sibling": "sibling",
    "sibling-red": "sibling",
    "anchor": "delayed-anchor",
    "anchor-red": "delayed-anchor",
}

# Expectations that run against the mutant resolver, and the mutation each one selects.
MUTANTS = {
    "red": "skip-shortcut",
    "peer-red": "skip-shortcut",
    "sibling-red": "sibling",
    "anchor-red": "stale-anchor",
}
MUTANT_ENV = "TOS_TEST_STATE_RESOLVER_MUTANT"


def fail(n: int, run: int, reason: str, transcript: str) -> None:
    sys.stdout.write(transcript[-8000:])
    print(f"\nMERKLE_PROSPECTIVE_NOTAR_CHECK_FAILED n={n} run={run}: {reason}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: bool, n: int, run: int, reason: str, transcript: str) -> None:
    if not condition:
        fail(n, run, reason, transcript)


def merkle_abort(expected_old: str, applied_to: str) -> str:
    return (
        f"invalid merkle update: expected old value hash = {expected_old}, "
        f"applied to value with hash = {applied_to}"
    )


def check_once(binary: str, expect: str, n: int, run: int, timeout: float) -> None:
    env = dict(os.environ)
    env.pop(MUTANT_ENV, None)
    if expect in MUTANTS:
        env[MUTANT_ENV] = MUTANTS[expect]
    try:
        proc = subprocess.run(
            [binary, MODES[expect], str(n)],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        out = (
            (exc.stdout or b"").decode(errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        fail(n, run, f"timed out after {timeout}s", out)
    text = proc.stdout + proc.stderr
    lower = text.lower()

    if expect in MUTANTS:
        build = f"MERKLE_ACTOR_BUILD resolver=mutant mutant={MUTANTS[expect]}"
        require(build in text, n, run, "red control did not run the mutant resolver", text)
        require(
            f"MERKLE_ACTOR_MUTANT_FIRED kind={MUTANTS[expect]}" in text,
            n,
            run,
            "the mutation never fired: the red control did not exercise it",
            text,
        )
    else:
        require(
            "MERKLE_ACTOR_BUILD resolver=production" in text,
            n,
            run,
            "this expectation must run the production resolver",
            text,
        )

    chain = re.search(
        r"MERKLE_ACTOR_CHAIN n=(\d+) .* P=\{slot=(\d+), hash=([0-9A-Fa-f]{64})\} "
        r"C=\{slot=(\d+), hash=[0-9A-Fa-f]{64}\} C_block=(\S+)",
        text,
    )
    require(
        chain is not None and int(chain.group(1)) == n, n, run, "no chain line for this n", text
    )
    p_slot, p_hash, c_block = chain.group(2), chain.group(3).lower(), chain.group(5)
    c_window = int(chain.group(4)) + 1
    p_request = re.compile(
        r"MERKLE_ACTOR_OVERLAY_REQUEST id=\{slot=" + p_slot + r", hash=" + p_hash + r"\}",
        re.IGNORECASE,
    )
    merkle_error = "invalid merkle update" in lower

    if expect.startswith("peer-"):
        check_peer(proc.returncode, text, expect, n, run, p_request, c_block, c_window)
        return
    if expect.startswith("sibling"):
        check_sibling(proc.returncode, text, expect, n, run, p_hash, c_block)
        return
    if expect.startswith("anchor"):
        check_anchor(proc.returncode, text, expect, n, run, c_block)
        return

    if expect == "gate":
        require(proc.returncode != 0, n, run, "misaimed gate run exited 0", text)
        require(
            "MERKLE_ACTOR_PRECONDITION_FAILED: NotarCert(P) write was not held" in text,
            n,
            run,
            "misaimed gate was not detected by the harness",
            text,
        )
        require(
            "MERKLE_ACTOR_TRIGGER" not in text,
            n,
            run,
            "resolution was triggered without the hold",
            text,
        )
        return

    pre = re.search(
        r"MERKLE_ACTOR_PRECONDITION leader_window=\d+ base=C leader=local "
        r"skip_cert_P_slot=installed notar_cert_C=installed notar_cert_P=(\S+) misbehavior=0",
        text,
    )
    require(pre is not None, n, run, "preconditions were not established", text)
    expected_p = "installed" if expect == "control" else "held_prospective"
    require(
        pre.group(1) == expected_p,
        n,
        run,
        f"NotarCert(P) was {pre.group(1)}, not {expected_p}",
        text,
    )
    require(
        "MERKLE_ACTOR_TRIGGER ResolveState(C)" in text,
        n,
        run,
        "resolution was never triggered",
        text,
    )
    expect_line = f"expected_old={state_hash(n)} applied_to={state_hash(n - 1)}"
    require(expect_line in lower, n, run, "binary and checker disagree on the state hashes", text)

    if expect == "red":
        require(proc.returncode != 0, n, run, "skip-shortcut resolver did not fail", text)
        pair = (
            f"invalid merkle update: expected old value hash = {state_hash(n)}, "
            f"applied to value with hash = {state_hash(n - 1)}"
        )
        require(pair in lower, n, run, "abort is not the N/N-1 Merkle mismatch", text)
        require(
            f"candidate block id = {c_block}".lower() in lower,
            n,
            run,
            "the failing update is not C's",
            text,
        )
        require(
            p_request.search(text) is None,
            n,
            run,
            "P was requested: the shortcut was not what failed",
            text,
        )
        require(
            "MERKLE_ACTOR_GATE_RELEASED" not in text,
            n,
            run,
            "failure happened after the hold ended",
            text,
        )
        return

    require(proc.returncode == 0, n, run, f"exit code {proc.returncode}", text)
    require(not merkle_error, n, run, "a Merkle update was applied to the wrong base", text)
    if expect == "green":
        require(
            p_request.search(text) is not None,
            n,
            run,
            "the exact ancestor P was never requested",
            text,
        )
        require(
            "MERKLE_ACTOR_WAITING_ON_EXACT_ANCESTOR" in text,
            n,
            run,
            "resolution did not wait on P",
            text,
        )
        waited = text.index("MERKLE_ACTOR_WAITING_ON_EXACT_ANCESTOR")
        released = text.find("MERKLE_ACTOR_GATE_RELEASED")
        require(
            released > waited, n, run, "the hold ended before resolution was seen waiting", text
        )
        require(
            f"MERKLE_ACTOR_GREEN state={state_hash(n + 1)}".lower() in lower,
            n,
            run,
            "resolved state is not n+1",
            text,
        )
    elif expect == "bounded":
        require(
            p_request.search(text) is not None,
            n,
            run,
            "the exact ancestor P was never requested",
            text,
        )
        require(
            "MERKLE_ACTOR_GREEN_BOUNDED" in text and "cannot resolve exact ancestor" in text,
            n,
            run,
            "no bounded exact-ancestor refusal",
            text,
        )
    elif expect == "control":
        require(
            f"MERKLE_ACTOR_CONTROL_OK state={state_hash(n + 1)}".lower() in lower,
            n,
            run,
            "control run did not resolve to state n+1",
            text,
        )


def check_peer(
    returncode: int,
    text: str,
    expect: str,
    n: int,
    run: int,
    p_request,
    c_block: str,
    c_window: int,
) -> None:
    lower = text.lower()
    require(
        re.search(
            r"MERKLE_ACTOR_PEER_PRECONDITION peer_serves_notar_P=yes target_notar_cert_P=absent "
            r"skip_run=[1-9]\d*",
            text,
        )
        is not None,
        n,
        run,
        "peer-only preconditions not established",
        text,
    )
    require(
        "MERKLE_ACTOR_TRIGGER NotarCert(C) -> Consensus::start_generation(C)" in text,
        n,
        run,
        "the leader path was never triggered",
        text,
    )
    expect_line = f"expected_old={state_hash(n)} applied_to={state_hash(n - 1)}"
    require(expect_line in lower, n, run, "binary and checker disagree on the state hashes", text)
    merkle_error = "invalid merkle update" in lower
    if expect == "peer-red":
        require(returncode != 0, n, run, "skip-shortcut resolver did not fail", text)
        pair = (
            f"invalid merkle update: expected old value hash = {state_hash(n)}, "
            f"applied to value with hash = {state_hash(n - 1)}"
        )
        require(pair in lower, n, run, "abort is not the N/N-1 Merkle mismatch", text)
        require(
            f"candidate block id = {c_block}".lower() in lower,
            n,
            run,
            "the failing update is not C's",
            text,
        )
        require(
            p_request.search(text) is None,
            n,
            run,
            "P was requested: the shortcut was not what failed",
            text,
        )
        # Earlier windows led by the same node start normally; the one opened on C must not.
        require(
            f"MERKLE_ACTOR_WINDOW_STARTED start_slot={c_window} " not in text,
            n,
            run,
            "the leader window on C started",
            text,
        )
        return
    require(returncode == 0, n, run, f"exit code {returncode}", text)
    require(not merkle_error, n, run, "a Merkle update was applied to the wrong base", text)
    require(
        p_request.search(text) is not None, n, run, "the exact ancestor P was never requested", text
    )
    require(
        "MERKLE_ACTOR_PEER_SERVED_NOTAR" in text, n, run, "the peer never served NotarCert(P)", text
    )
    require(
        f"MERKLE_ACTOR_PEER_GREEN state={state_hash(n + 1)} next_seqno={n + 2}".lower() in lower,
        n,
        run,
        "the leader window did not start on state n+1",
        text,
    )


def resolved_lines(text: str) -> list:
    return re.findall(r"MERKLE_ACTOR_RESOLVED node=(\d+) block=(\S+) state=([0-9A-Fa-f]{64})", text)


def require_two_observers_agree(text: str, n: int, run: int, c_block: str) -> list:
    resolved = resolved_lines(text)
    require(len(resolved) == 2, n, run, f"{len(resolved)} observers resolved C, not 2", text)
    require(resolved[0][0] != resolved[1][0], n, run, "the same node resolved C twice", text)
    for node, block, state in resolved:
        require(block == c_block, n, run, f"node {node} resolved block {block}, not C", text)
        require(
            state.lower() == state_hash(n + 1),
            n,
            run,
            f"node {node} resolved state {state}, not n+1",
            text,
        )
    return resolved


def check_sibling(
    returncode: int, text: str, expect: str, n: int, run: int, p_hash: str, c_block: str
) -> None:
    lower = text.lower()
    siblings = re.search(
        r"MERKLE_ACTOR_SIBLINGS n=(\d+) .* P=\{slot=(\d+), hash=([0-9A-Fa-f]{64})\} "
        r"P_sibling=\{slot=(\d+), hash=([0-9A-Fa-f]{64})\} P_block=(\S+) P_sibling_block=(\S+)",
        text,
    )
    require(siblings is not None and int(siblings.group(1)) == n, n, run, "no sibling line", text)
    p_slot, p_line_hash = int(siblings.group(2)), siblings.group(3).lower()
    s_slot, s_hash = int(siblings.group(4)), siblings.group(5).lower()
    p_block, s_block = siblings.group(6), siblings.group(7)
    require(p_line_hash == p_hash, n, run, "the sibling line names a different P", text)
    require(s_slot + 1 == p_slot and s_hash != p_hash, n, run, "P' is not P's sibling", text)
    require(
        p_block.split(":")[0] == s_block.split(":")[0] and p_block != s_block,
        n,
        run,
        "P and P' are not distinct blocks at one height",
        text,
    )
    orders = re.findall(
        r"MERKLE_ACTOR_SIBLING_PRECONDITION node=(\d+) order=(\S+) notar_cert_P_sibling=installed "
        r"notar_cert_P=installed notar_cert_C=installed final_cert_C=installed finalized_P=yes "
        r"finalized_P_sibling=no misbehavior=0",
        text,
    )
    require(
        sorted(order for _, order in orders) == ["sibling-first", "sibling-late"],
        n,
        run,
        "sibling preconditions were not established on both observers",
        text,
    )
    expect_line = (
        f"MERKLE_ACTOR_EXPECT wrong_branch_would_fail_with expected_old={state_hash(n)} "
        f"applied_to={sibling_state_hash(n)}"
    )
    require(
        expect_line.lower() in lower,
        n,
        run,
        "binary and checker disagree on the state hashes",
        text,
    )
    finalized = re.findall(
        r"MERKLE_ACTOR_FINALIZED node=(\d+) id=\{slot=\d+, hash=([0-9A-Fa-f]{64})\}", text
    )
    for node, _ in orders:
        hashes = {h.lower() for who, h in finalized if who == node}
        require(p_hash in hashes, n, run, f"node {node} never finalized P", text)
        require(s_hash not in hashes, n, run, f"node {node} finalized the sibling P'", text)
    require(
        f"MERKLE_ACTOR_SIBLING_STATE node={orders[0][0]} state={sibling_state_hash(n)}".lower()
        in lower,
        n,
        run,
        "the sibling P' was not resolved to its own state first",
        text,
    )
    if expect == "sibling-red":
        require(returncode != 0, n, run, "the sibling-substituting resolver did not fail", text)
        require(
            merkle_abort(state_hash(n), sibling_state_hash(n)) in lower,
            n,
            run,
            "abort is not C's update applied to the sibling's state",
            text,
        )
        require(
            f"candidate block id = {c_block}".lower() in lower,
            n,
            run,
            "the failing update is not C's",
            text,
        )
        require("MERKLE_ACTOR_SIBLING_GREEN" not in text, n, run, "the red control passed", text)
        return
    require(returncode == 0, n, run, f"exit code {returncode}", text)
    require("invalid merkle update" not in lower, n, run, "a Merkle update was misapplied", text)
    require_two_observers_agree(text, n, run, c_block)
    require(
        f"MERKLE_ACTOR_SIBLING_GREEN state={state_hash(n + 1)} block={c_block} observers=2 match=yes".lower()
        in lower,
        n,
        run,
        "the observers did not agree on C",
        text,
    )


def check_anchor(returncode: int, text: str, expect: str, n: int, run: int, c_block: str) -> None:
    lower = text.lower()
    blocks = re.search(r"MERKLE_ACTOR_BLOCKS A_block=(\S+) P_block=(\S+)", text)
    require(blocks is not None, n, run, "no block line", text)
    a_block, p_block = blocks.group(1), blocks.group(2)
    nodes = re.findall(
        r"MERKLE_ACTOR_ANCHOR_PRECONDITION node=(\d+) finalized_P=yes finalized_C=no "
        r"anchor_P=delayed anchor_A=available misbehavior=0",
        text,
    )
    require(
        len(nodes) == 2 and nodes[0] != nodes[1],
        n,
        run,
        "anchor preconditions were not established on both observers",
        text,
    )
    first, second = nodes
    expect_line = (
        f"MERKLE_ACTOR_EXPECT stale_anchor_would_fail_with expected_old={state_hash(n)} "
        f"applied_to={state_hash(0)}"
    )
    require(
        expect_line.lower() in lower,
        n,
        run,
        "binary and checker disagree on the state hashes",
        text,
    )
    trigger = text.find(f"MERKLE_ACTOR_TRIGGER ResolveState(C) node={first} anchor_P=delayed")
    require(trigger >= 0, n, run, "resolution with the anchor delayed was never triggered", text)
    refused = text.find(f"MERKLE_ACTOR_MANAGER_STATE node={first} block={p_block} served=no")
    require(refused > trigger, n, run, "P's delayed anchor was never asked for and refused", text)
    require(
        re.search(r"MERKLE_ACTOR_MANAGER_STATE node=\d+ block=" + re.escape(a_block) + " ", text)
        is None,
        n,
        run,
        "a manager was asked for the older anchor A",
        text,
    )
    if expect == "anchor-red":
        require(returncode != 0, n, run, "the stale-anchor resolver did not fail", text)
        require(
            merkle_abort(state_hash(n), state_hash(0)) in lower,
            n,
            run,
            "abort is not C's update applied to the start state",
            text,
        )
        require(
            f"candidate block id = {c_block}".lower() in lower,
            n,
            run,
            "the failing update is not C's",
            text,
        )
        require("MERKLE_ACTOR_ANCHOR_GREEN" not in text, n, run, "the red control passed", text)
        return
    require(returncode == 0, n, run, f"exit code {returncode}", text)
    require("invalid merkle update" not in lower, n, run, "a Merkle update was misapplied", text)
    resolved = require_two_observers_agree(text, n, run, c_block)
    require(resolved[0][0] == first and resolved[1][0] == second, n, run, "observer order", text)
    released = text.find("MERKLE_ACTOR_ANCHOR_RELEASED")
    second_trigger = text.find(
        f"MERKLE_ACTOR_TRIGGER ResolveState(C) node={second} anchor_P=released"
    )
    require(0 <= released < second_trigger, n, run, "the anchor was not released first", text)
    second_reads = re.findall(
        rf"MERKLE_ACTOR_MANAGER_STATE node={second} block=(\S+) served=(\S+)", text
    )
    require(
        second_reads == [(p_block, "yes")],
        n,
        run,
        f"the second observer did not resolve from P's anchor alone: {second_reads}",
        text,
    )
    require(
        f"MERKLE_ACTOR_ANCHOR_GREEN state={state_hash(n + 1)} block={c_block} observers=2 match=yes".lower()
        in lower,
        n,
        run,
        "the observers did not agree on C",
        text,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("expect", choices=sorted(MODES))
    parser.add_argument("--n", type=int, action="append", required=True)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()
    # The hash the whole judgement rests on, checked against the retained incident logs.
    assert state_hash(5).upper().startswith("C8D1E14F") and state_hash(4).upper().startswith(
        "92345EFB"
    )
    assert state_hash(23).upper().startswith("69A2DC37") and state_hash(22).upper().startswith(
        "19088211"
    )
    for n in args.n:
        for run in range(1, args.runs + 1):
            check_once(args.binary, args.expect, n, run, args.timeout)
    print(f"MERKLE_PROSPECTIVE_NOTAR_OK expect={args.expect} n={args.n} runs={args.runs}")


if __name__ == "__main__":
    main()
