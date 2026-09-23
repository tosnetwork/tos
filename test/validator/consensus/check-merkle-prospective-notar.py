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
"""

import argparse
import hashlib
import re
import subprocess
import sys


def state_hash(seqno: int) -> str:
    # gen_shard_state(seqno): an ordinary cell holding the 32-bit tag 0xabcdabcd and seqno.
    # Its representation hash is sha256(d1 d2 data); d1 = 0 refs, d2 = 8 whole bytes.
    data = (0xABCDABCD).to_bytes(4, "big") + seqno.to_bytes(4, "big")
    return hashlib.sha256(bytes([0, 16]) + data).hexdigest()


MODES = {
    "green": "hold-release",
    "bounded": "hold-refuse",
    "control": "no-hold",
    "gate": "hold-wrong-slot",
    "red": "hold-release",
}


def fail(n: int, run: int, reason: str, transcript: str) -> None:
    sys.stdout.write(transcript[-8000:])
    print(f"\nMERKLE_PROSPECTIVE_NOTAR_CHECK_FAILED n={n} run={run}: {reason}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: bool, n: int, run: int, reason: str, transcript: str) -> None:
    if not condition:
        fail(n, run, reason, transcript)


def check_once(binary: str, expect: str, n: int, run: int, timeout: float) -> None:
    try:
        proc = subprocess.run([binary, MODES[expect], str(n)], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        fail(n, run, f"timed out after {timeout}s", out)
    text = proc.stdout + proc.stderr
    lower = text.lower()

    chain = re.search(r"MERKLE_ACTOR_CHAIN n=(\d+) .* P=\{slot=(\d+), hash=([0-9A-Fa-f]{64})\} "
                      r"C=\{slot=\d+, hash=[0-9A-Fa-f]{64}\} C_block=(\S+)", text)
    require(chain is not None and int(chain.group(1)) == n, n, run, "no chain line for this n", text)
    p_slot, p_hash, c_block = chain.group(2), chain.group(3).lower(), chain.group(4)
    p_request = re.compile(r"MERKLE_ACTOR_OVERLAY_REQUEST id=\{slot=" + p_slot + r", hash=" + p_hash + r"\}",
                           re.IGNORECASE)
    merkle_error = "invalid merkle update" in lower

    if expect == "gate":
        require(proc.returncode != 0, n, run, "misaimed gate run exited 0", text)
        require("MERKLE_ACTOR_PRECONDITION_FAILED: NotarCert(P) write was not held" in text, n, run,
                "misaimed gate was not detected by the harness", text)
        require("MERKLE_ACTOR_TRIGGER" not in text, n, run, "resolution was triggered without the hold", text)
        return

    pre = re.search(r"MERKLE_ACTOR_PRECONDITION leader_window=\d+ base=C leader=local "
                    r"skip_cert_P_slot=installed notar_cert_C=installed notar_cert_P=(\S+) misbehavior=0", text)
    require(pre is not None, n, run, "preconditions were not established", text)
    expected_p = "installed" if expect == "control" else "held_prospective"
    require(pre.group(1) == expected_p, n, run, f"NotarCert(P) was {pre.group(1)}, not {expected_p}", text)
    require("MERKLE_ACTOR_TRIGGER ResolveState(C)" in text, n, run, "resolution was never triggered", text)
    expect_line = f"expected_old={state_hash(n)} applied_to={state_hash(n - 1)}"
    require(expect_line in lower, n, run, "binary and checker disagree on the state hashes", text)

    if expect == "red":
        require(proc.returncode != 0, n, run, "skip-shortcut resolver did not fail", text)
        pair = (f"invalid merkle update: expected old value hash = {state_hash(n)}, "
                f"applied to value with hash = {state_hash(n - 1)}")
        require(pair in lower, n, run, "abort is not the N/N-1 Merkle mismatch", text)
        require(f"candidate block id = {c_block}".lower() in lower, n, run,
                "the failing update is not C's", text)
        require(p_request.search(text) is None, n, run, "P was requested: the shortcut was not what failed", text)
        require("MERKLE_ACTOR_GATE_RELEASED" not in text, n, run, "failure happened after the hold ended", text)
        return

    require(proc.returncode == 0, n, run, f"exit code {proc.returncode}", text)
    require(not merkle_error, n, run, "a Merkle update was applied to the wrong base", text)
    if expect == "green":
        require(p_request.search(text) is not None, n, run, "the exact ancestor P was never requested", text)
        require("MERKLE_ACTOR_WAITING_ON_EXACT_ANCESTOR" in text, n, run, "resolution did not wait on P", text)
        waited = text.index("MERKLE_ACTOR_WAITING_ON_EXACT_ANCESTOR")
        released = text.find("MERKLE_ACTOR_GATE_RELEASED")
        require(released > waited, n, run, "the hold ended before resolution was seen waiting", text)
        require(f"MERKLE_ACTOR_GREEN state={state_hash(n + 1)}".lower() in lower, n, run,
                "resolved state is not n+1", text)
    elif expect == "bounded":
        require(p_request.search(text) is not None, n, run, "the exact ancestor P was never requested", text)
        require("MERKLE_ACTOR_GREEN_BOUNDED" in text and "cannot resolve exact ancestor" in text, n, run,
                "no bounded exact-ancestor refusal", text)
    elif expect == "control":
        require(f"MERKLE_ACTOR_CONTROL_OK state={state_hash(n + 1)}".lower() in lower, n, run,
                "control run did not resolve to state n+1", text)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("expect", choices=sorted(MODES))
    parser.add_argument("--n", type=int, action="append", required=True)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()
    # The hash the whole judgement rests on, checked against the retained incident logs.
    assert state_hash(5).upper().startswith("C8D1E14F") and state_hash(4).upper().startswith("92345EFB")
    assert state_hash(23).upper().startswith("69A2DC37") and state_hash(22).upper().startswith("19088211")
    for n in args.n:
        for run in range(1, args.runs + 1):
            check_once(args.binary, args.expect, n, run, args.timeout)
    print(f"MERKLE_PROSPECTIVE_NOTAR_OK expect={args.expect} n={args.n} runs={args.runs}")


if __name__ == "__main__":
    main()
