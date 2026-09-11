#!/usr/bin/env python3
"""Regression tests for the live-rejoin verdict thresholds.

These drive the REAL verify_live_rejoin / _node_mc_seqno from
scripts/validator-election-stage-a.py (bound from the source module, never a
transcription -- so the test tracks the code, not a copy). Only the external
dependencies are test doubles: the reference tip, the target's own JSON-RPC, node
stop/run, the log, and the retry timer. The production predicates run unchanged.

The cases are the counterexamples an independent reviewer built against the first
(too-loose) version of this verdict. Two of them USED TO pass and must now fail:

  chain_freezes_after_downtime        -- reference and target both stop advancing
                                         after the catch-up point; "re-read the
                                         same tip" is not "the chain advanced".
  target_replays_preexisting_height_only -- the target was already ahead of the
                                         reference and never advances past its own
                                         pre-stop tip.

If either of these is reported "passed" again, the tracking baselines have
regressed to seqno >= a re-read tip and the verdict is vacuous once more. The
cleanup cases must report NOT_EXERCISED, not passed, when no real durable erase
happened on the target before the restart. The controls fix the genuinely-enforced
edges (skip restart, fatal log, peers never advance).

Run: uv run python test/integration/test_live_rejoin_thresholds.py
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "scripts" / "validator-election-stage-a.py"


def _load_real_module():
    spec = importlib.util.spec_from_file_location("vestage_under_test", SOURCE)
    module = importlib.util.module_from_spec(spec)
    # dataclass processing needs the module registered before exec.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VESTAGE = _load_real_module()
REAL = VESTAGE.ValidatorElectionRehearsal


class _Sequence:
    """Returns each value once, then repeats the last (a node keeps reporting its
    latest tip until a new block arrives)."""

    def __init__(self, values):
        self.values = list(values)
        self.pos = 0

    def next(self) -> int:
        value = self.values[min(self.pos, len(self.values) - 1)]
        self.pos += 1
        return value


class _Node:
    def __init__(self, log_path: Path, restart_enabled: bool):
        self.log_path = log_path
        self.running = True
        self.restart_enabled = restart_enabled

    async def stop(self):
        self.running = False

    async def run(self, options):
        self.running = self.restart_enabled


class Fixture:
    """A `self` for the real methods: real verify_live_rejoin / _node_mc_seqno bound
    below, everything they reach is a double."""

    def __init__(self, name, ref_tips, target_tips, *, armed=True, log="", restart=True, fork=False, fork_after=None):
        self.run_dir = Path(tempfile.mkdtemp(prefix=f"rejoin_{name}_"))
        self.experiment = SimpleNamespace(rpc_addresses=[f"127.0.0.1:{8111 + i}" for i in range(4)])
        self.enable_consensus_cleanup = armed
        self._reference = _Sequence(ref_tips)
        self._target = _Sequence(target_tips)
        self._fork = fork  # target diverges at every height
        self._fork_after = fork_after  # target shares prefix up to this height, diverges above it
        self.live_rejoin_result = None
        self.events = []
        self.rpc_calls = []
        self.mc_info_calls = []
        self.nodes = []
        for i in range(4):
            log_path = self.run_dir / f"node{i + 1}.log"
            log_path.write_text(log)
            self.nodes.append(_Node(log_path, restart if i == 3 else True))

    # Synthetic transport for the REAL _node_mc_seqno / _node_mc_block_id (monkeypatched).
    def rpc(self, address, method, params=None):
        self.rpc_calls.append((address, method))
        target = self.experiment.rpc_addresses[3]
        if method == "getMasterchainInfo":
            # Only the TARGET's own tip is read via JSON-RPC; the reference tip uses the
            # lite-client double. So every getMasterchainInfo must hit the target endpoint.
            self.mc_info_calls.append(address)
            assert address == target, f"getMasterchainInfo queried non-target endpoint {address}"
            if not self.nodes[3].running:
                raise ConnectionError("synthetic target RPC refused: node stopped")
            return {"result": {"last": {"seqno": self._target.next()}}}
        if method == "getBlockHeader":
            # Queried on BOTH the reference (node 0) and the target for same-height agreement.
            seqno = params["seqno"]
            # fork: target diverges at every height. fork_after: target shares the canonical
            # prefix up to and including that height, then diverges above it (a fork after a
            # shared during-downtime height -- agreement at the early height would miss it).
            diverges = address == target and (
                self._fork or (self._fork_after is not None and seqno > self._fork_after)
            )
            if diverges:
                root, file = f"TARGETFORK@{seqno}", f"TARGETFORK@{seqno}"
            else:
                root, file = f"canonical-root@{seqno}", f"canonical-file@{seqno}"
            return {"result": {"id": {"seqno": seqno, "root_hash": root, "file_hash": file}}}
        raise AssertionError(f"unexpected method {method}")

    async def masterchain_seqno(self) -> int:
        return self._reference.next()

    def validator_start_options(self, index):
        return {"index": index, "cleanup": self.enable_consensus_cleanup}

    def event(self, name, **fields):
        self.events.append({"name": name, **fields})

    async def retry(self, call, *, timeout, interval, description, predicate=bool):
        """Bounded deterministic stand-in for the real timer: the production predicate
        runs on every observation; failure raises TimeoutError like the real retry."""
        last_error = None
        for _ in range(4):
            try:
                value = await call()
                if predicate(value):
                    return value
            except ConnectionError as exc:
                last_error = str(exc)
        raise TimeoutError(f"{description}: synthetic poll exhausted; {last_error}")


# Bind the REAL methods under test onto the fixture (identity from the source module).
Fixture.verify_live_rejoin = REAL.verify_live_rejoin
Fixture._node_mc_seqno = REAL._node_mc_seqno
Fixture._node_mc_block_id = REAL._node_mc_block_id


async def _run(name, ref_tips, target_tips, *, armed=True, log="", restart=True, fork=False, fork_after=None):
    fixture = Fixture(name, ref_tips, target_tips, armed=armed, log=log, restart=restart, fork=fork, fork_after=fork_after)
    VESTAGE.json_rpc_call = fixture.rpc
    try:
        result = await fixture.verify_live_rejoin()
        # Every masterchain tip read via JSON-RPC must have targeted the node under test.
        assert all(addr == fixture.experiment.rpc_addresses[3] for addr in fixture.mc_info_calls)
        return ("passed" if result["verdict"] == "passed" else "failed", result)
    except Exception as exc:  # TimeoutError / AssertionError are the failure signals
        return (type(exc).__name__, {"error": str(exc)})


PASSLOG = "VALCLEANUP pass gc_seqno=0 pending=0 reserved=0\n" * 3
ERASELOG = PASSLOG + "VALCLEANUP erase_ack session=abcd generation=1 attempt=1\n"


async def main() -> int:
    failures: list[str] = []

    def check(label, condition, detail):
        status = "ok" if condition else "FAIL"
        print(f"[{status}] {label}: {detail}")
        if not condition:
            failures.append(f"{label}: {detail}")

    # 1. Positive control: real reported pattern -> passes; no erase -> NOT_EXERCISED.
    outcome, res = await _run("control_reported_height_pattern", [27, 33, 49], [27, 35, 55], log=PASSLOG)
    check("control_reported_height_pattern", outcome == "passed", outcome)
    check(
        "control_reported_height_pattern.post_cleanup NOT_EXERCISED",
        res.get("post_cleanup_recovery") == "NOT_EXERCISED",
        res.get("post_cleanup_recovery"),
    )

    # 2. Reviewer counterexample: chain freezes after catch-up. MUST now fail.
    outcome, res = await _run("chain_freezes_after_downtime", [27, 33, 33], [27, 33, 33], log=PASSLOG)
    check(
        "chain_freezes_after_downtime rejected (was: passed)",
        outcome == "TimeoutError",
        f"{outcome}: {res.get('error', res)}",
    )

    # 3. Reviewer counterexample: target already ahead, never progresses. MUST now fail.
    outcome, res = await _run("target_replays_preexisting_height_only", [27, 33, 49], [60, 60, 60], log=PASSLOG)
    check(
        "target_replays_preexisting_height_only rejected (was: passed)",
        outcome == "TimeoutError",
        f"{outcome}: {res.get('error', res)}",
    )

    # 4/5. Cleanup off / armed-but-idle: generic sync PASSES but post-cleanup NOT_EXERCISED.
    for name, armed in (("cleanup_disabled_and_never_runs", False), ("cleanup_armed_but_never_runs", True)):
        outcome, res = await _run(name, [27, 33, 49], [27, 35, 55], armed=armed, log="")
        check(f"{name} sync passes", outcome == "passed", outcome)
        check(
            f"{name} post_cleanup NOT_EXERCISED",
            res.get("post_cleanup_recovery") == "NOT_EXERCISED",
            res.get("post_cleanup_recovery"),
        )

    # 6. Post-cleanup recovery IS asserted when a real durable erase preceded the restart.
    outcome, res = await _run("post_cleanup_recovery_exercised", [27, 33, 49], [27, 35, 55], log=ERASELOG)
    check("post_cleanup_recovery_exercised sync passes", outcome == "passed", outcome)
    check(
        "post_cleanup_recovery_exercised post_cleanup passed",
        res.get("post_cleanup_recovery") == "passed",
        res.get("post_cleanup_recovery"),
    )

    # 6b. Target advances by seqno but on a DIVERGENT chain at every height: block-id
    # disagreement must reject it (a seqno-only check would have passed this).
    outcome, res = await _run("target_on_divergent_chain", [27, 33, 49], [27, 35, 55], log=PASSLOG, fork=True)
    check(
        "target_on_divergent_chain rejected by block-id agreement",
        outcome == "AssertionError" and "block-id disagreement" in res.get("error", ""),
        f"{outcome}: {res.get('error', res)}",
    )

    # 6c. Target shares the canonical chain THROUGH the during-downtime height (33) but forks
    # ABOVE it, so it disagrees at fresh_tip (49). Comparing only at the early height would
    # accept this; comparing at fresh_tip must reject it. This is the reviewer's narrow P2.
    outcome, res = await _run(
        "fork_after_shared_downtime_height", [27, 33, 49], [27, 35, 55], log=PASSLOG, fork_after=33,
    )
    check(
        "fork_after_shared_downtime_height rejected at fresh_tip",
        outcome == "AssertionError" and "block-id disagreement" in res.get("error", "") and "seqno 49" in res.get("error", ""),
        f"{outcome}: {res.get('error', res)}",
    )

    # 7. Controls that must stay red.
    outcome, res = await _run("control_restart_skipped", [27, 33, 49], [27, 35, 55], restart=False)
    check("control_restart_skipped times out", outcome == "TimeoutError", outcome)

    outcome, res = await _run("control_fatal_after_restart", [27, 33, 49], [27, 35, 55], log="FATAL synthetic failure\n")
    check("control_fatal_after_restart rejected", outcome == "AssertionError", outcome)

    outcome, res = await _run("control_peers_do_not_advance", [27, 27, 27], [27, 35, 55])
    check("control_peers_do_not_advance times out", outcome == "TimeoutError", outcome)

    print()
    if failures:
        print(f"FAIL: {len(failures)} threshold regression(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("PASS: live-rejoin thresholds reject every insufficient-evidence counterexample")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
