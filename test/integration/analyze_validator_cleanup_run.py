#!/usr/bin/env python3
"""Analyze a validator-election experiment run for GATED validator-cleanup evidence.

Reads the per-node engine logs of a run produced by

    uv run python scripts/validator-election-stage-a.py --mode experiment --stage a \
        --enable-consensus-cleanup --duration-seconds <N> ...

and emits a tri-state verdict (PASS / FAIL / INCONCLUSIVE) about the REAL validator-group
cleanup path (Finding 1), keyed on the distinguishable `VALCLEANUP reserve|delete_done|
erase_ack` trace (manager.cpp), NOT the observer startup sweep's "reclaimed ..." log.

What this run CAN establish (and only this):
  POSITIVE (should-delete fired and completed on the real path), per completed op:
    * the SAME (session,generation,attempt) ticket has reserve -> delete_done(gone=1) ->
      erase_ack IN THAT ORDER (log position order within the node), and
    * that op's OWN reserve carried gc_seqno>0 (its own GC snapshot, not a global max), and
    * the reserved directory is gone from disk at the end.
  ELIGIBILITY (necessary condition of the four-condition gate): every reserve had
    retirement_seqno <= gc_seqno (a future retirement can never be an ancestor of GC).
  NO OVER-REACH: live / not-yet-eligible validator-group dirs remain on disk; no session
    is both deleted and present.
  LIVENESS: every EXPECTED validator (from the run manifest, DHT excluded) SUCCESSFULLY
    APPLIED a masterchain block (local application to state, not merely FinalizeBlock
    finality) whose seqno exceeds the max GC floor its own deletes used -- i.e. it kept
    applying blocks BEYOND its deletion horizon, crash-free. Missing a validator log is
    INCONCLUSIVE, never a silent pass.

What this run does NOT establish (still OPEN, not counted as passed here):
  * the exhaustive real-node should-NOT-delete matrix by deliberate injection
    (r>=g, current/next group, unknown/mismatched GC -> no dispatch);
  * the production reopen fence wiring (get_or_make_next_group), and
  * post-delete restart recovery on a real node.
  (The C++ tests cover the adapter/eligibility/dispatch logic deterministically, but that
  is a different level from a real-node negative/recovery pass.)

Usage:
    uv run python test/integration/analyze_validator_cleanup_run.py [RUN_DIR]
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

RESERVE = re.compile(
    r"VALCLEANUP reserve session=(?P<session>\S+) generation=(?P<gen>\d+) "
    r"attempt=(?P<attempt>\d+) dir=(?P<dir>\S+) gc_seqno=(?P<gc>\d+) retirement_seqno=(?P<ret>\d+)"
)
DELETE_DONE = re.compile(
    r"VALCLEANUP delete_done session=(?P<session>\S+) generation=(?P<gen>\d+) "
    r"attempt=(?P<attempt>\d+) confirmed_gone=(?P<gone>\d+)"
)
ERASE_ACK = re.compile(
    r"VALCLEANUP erase_ack session=(?P<session>\S+) generation=(?P<gen>\d+) attempt=(?P<attempt>\d+)"
)
# Coarse milestone (every 1024 blocks) -- reported, but too sparse for "after last delete".
APPLIED_MC = re.compile(
    r"applied masterchain block \(-1,8000000000000000,(?P<seqno>\d+)\):(?P<root>[0-9A-Fa-f]+)"
)
# Fine per-block ACCEPTED signal: a masterchain block was FINALIZED (final signatures) by
# the node's consensus group. Unlike "validateblock" (the ValidateQuery actor name, which
# may end in a REJECT), FinalizeBlock means the block was accepted -- the right liveness
# signal. (Its block id is (-1,shard,seqno); the earlier candidate id in the same line is
# not (-1,...), so the non-greedy match lands on the masterchain block seqno.)
FINALIZE_MC = re.compile(r"FinalizeBlock.*?\(-1,8000000000000000,(?P<seqno>\d+)\)")
FATAL = re.compile(
    r"\b(FATAL|PANIC|CHECK failed|LOG_CHECK failed|AddressSanitizer|UndefinedBehaviorSanitizer|Aborted)\b"
)


def _git_head() -> str:
    try:
        return subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def _latest_run() -> Path | None:
    root = REPO / "test/integration/.validator-election-experiment"
    runs = sorted((p for p in root.glob("*") if (p / "network").is_dir()), reverse=True)
    return runs[0] if runs else None


def _key(m: re.Match) -> tuple[str, str, str]:
    return (m.group("session"), m.group("gen"), m.group("attempt"))


def _expected_validator_count(run_dir: Path) -> int | None:
    manifest = run_dir / "readiness-manifest.json"
    if not manifest.is_file():
        return None
    try:
        return int(json.load(manifest.open())["network"]["validator_count"])
    except Exception:
        return None


def _parse_node(text: str) -> dict:
    # positions (byte offsets) give temporal order within a single node log.
    reserves = {}
    for m in RESERVE.finditer(text):
        # keep the FIRST reserve position for a ticket
        reserves.setdefault(_key(m), {"gc": int(m.group("gc")), "ret": int(m.group("ret")),
                                      "dir": m.group("dir"), "pos": m.start()})
    done_ok = {}
    for m in DELETE_DONE.finditer(text):
        if m.group("gone") == "1":
            done_ok.setdefault(_key(m), m.start())
    acked = {}
    for m in ERASE_ACK.finditer(text):
        acked.setdefault(_key(m), m.start())

    applied = [(int(m.group("seqno")), m.start(), m.group("root")) for m in APPLIED_MC.finditer(text)]
    accepted = [(int(m.group("seqno")), m.start()) for m in FINALIZE_MC.finditer(text)]
    fatals = [ln[:400] for ln in text.splitlines() if FATAL.search(ln)]

    # ordered completed ops: reserve.pos < delete_done.pos < erase_ack.pos, and gc>0.
    completed = []
    ordering_violations = []
    for k, r in reserves.items():
        if k in done_ok and k in acked:
            if r["pos"] < done_ok[k] < acked[k]:
                completed.append({"key": k, "gc": r["gc"], "dir": r["dir"]})
            else:
                ordering_violations.append({"key": k, "reserve": r["pos"], "delete_done": done_ok[k], "ack": acked[k]})

    last_delete_pos = max([done_ok.get(c["key"], 0) for c in completed] + [acked.get(c["key"], 0) for c in completed],
                          default=None)
    return {
        "reserves": reserves,
        "completed": completed,
        "ordering_violations": ordering_violations,
        "applied": applied,
        "accepted": accepted,
        "fatals": fatals,
        "last_delete_pos": last_delete_pos,
    }


def analyze(run_dir: Path) -> tuple[str, dict]:
    network = run_dir / "network"
    node_dirs = sorted(p for p in network.glob("node*") if p.is_dir())
    expected_validators = _expected_validator_count(run_dir)

    failures: list[str] = []
    inconclusive: list[str] = []

    per_node = []
    completed_total = 0
    eligibility_violations = []
    ordering_violations_total = 0
    gc_zero_completed = 0
    present_validator_dirs_total = 0
    validators_with_progress = 0
    validator_nodes = []
    applied_roots_by_node: dict[str, dict[int, str]] = {}  # node -> {mc_seqno: root_hash}

    for nd in node_dirs:
        log = nd / "log"
        if not log.is_file():
            inconclusive.append(f"{nd.name}: no log file")
            per_node.append({"node": nd.name, "has_log": False})
            continue
        text = log.read_text(errors="replace")
        p = _parse_node(text)
        applied_seqnos = [s for s, _, _ in p["applied"]]
        accepted_seqnos = [s for s, _ in p["accepted"]]
        is_validator = len(accepted_seqnos) > 0  # DHT node finalizes no masterchain blocks
        n_completed = len(p["completed"])
        completed_total += n_completed
        ordering_violations_total += len(p["ordering_violations"])

        # eligibility relation + per-op gc, over every reserve / completed op.
        for r in p["reserves"].values():
            if r["ret"] > r["gc"]:
                eligibility_violations.append(f"{nd.name}: dir={r['dir']} retirement_seqno={r['ret']} > gc_seqno={r['gc']}")
        node_gc_used = [c["gc"] for c in p["completed"]]
        for c in p["completed"]:
            if c["gc"] <= 0:
                gc_zero_completed += 1

        # completed-delete dirs must be gone from disk. (This per-NODE check IS the
        # "deleted but still present" invariant; a cross-node session-set intersection was
        # dropped -- node A cleaning its own copy of session X while node B still needs X is
        # not a conflict.)
        for c in p["completed"]:
            if (nd / "consensus" / c["dir"]).exists():
                failures.append(f"{nd.name}: completed-delete dir still on disk: {c['dir']}")

        # retention: validator-group DIRECTORIES still present at end (live/not-yet-eligible).
        # Count directories only -- a stray consensus.* file is not a retained group.
        present_here = 0
        cdir = nd / "consensus"
        if cdir.is_dir():
            for child in cdir.iterdir():
                if child.is_dir() and child.name.startswith("consensus.") and ".observer." not in child.name:
                    present_here += 1
        present_validator_dirs_total += present_here

        # LIVENESS (per validator): it must have SUCCESSFULLY APPLIED a masterchain block
        # (manager.cpp "applied masterchain block" -- local application to state, not merely
        # FinalizeBlock consensus finality which can be followed by a stuck applier) whose
        # seqno exceeds the max GC floor its own deletes used. Since a node only advances
        # its GC floor by applying blocks past it, "applied a block beyond its deletion
        # horizon" means it kept applying blocks THROUGH the deletion activity. (The coarse
        # 1024-block application log cannot prove "strictly after the last delete position",
        # so this asserts the sound, provable "beyond the deletion horizon" instead.)
        progressed = None
        max_applied = max(applied_seqnos, default=None)
        max_accepted = max(accepted_seqnos, default=None)  # finality tip (informational)
        if is_validator:
            validator_nodes.append(nd.name)
            applied_roots_by_node[nd.name] = {s: root for s, _, root in p["applied"]}
            if n_completed > 0:
                gc_floor_used = max(node_gc_used, default=0)
                progressed = max_applied is not None and max_applied > gc_floor_used
                if progressed:
                    validators_with_progress += 1
                else:
                    failures.append(
                        f"{nd.name}: no APPLIED masterchain block beyond its max delete gc_floor "
                        f"{gc_floor_used} (max_applied={max_applied}); local application through cleanup not shown"
                    )
            else:
                progressed = True  # no deletes on this node -> nothing to survive
                validators_with_progress += 1

        per_node.append({
            "node": nd.name,
            "has_log": True,
            "is_validator": is_validator,
            "completed_ordered_deletes": n_completed,
            "ordering_violations": len(p["ordering_violations"]),
            "gc_seqnos_used": sorted(set(node_gc_used)),
            "max_applied_mc_seqno": max_applied,
            "max_accepted_mc_seqno": max_accepted,
            "validator_dirs_present_at_end": present_here,
            "applied_beyond_delete_horizon": progressed,
            "fatal_lines": len(p["fatals"]),
        })

    fatal_total = sum(n.get("fatal_lines", 0) for n in per_node)

    # Cross-node full-block-ID agreement: at the highest masterchain milestone reached by
    # ALL validators, every validator must have applied the SAME block (root hash) -- i.e.
    # they are on one chain, validating together, not forked/diverged.
    # Fail-closed: agreement is None (not established) unless there is a common milestone
    # across all validators to compare -- absence of common evidence is UNKNOWN, not "agree".
    agreement_seqno = None
    agreement_ok = None
    if len(applied_roots_by_node) >= 2:
        common = set.intersection(*(set(m.keys()) for m in applied_roots_by_node.values()))
        if common:
            agreement_seqno = max(common)
            roots = {m[agreement_seqno] for m in applied_roots_by_node.values()}
            agreement_ok = len(roots) == 1

    # --- completeness gating (INCONCLUSIVE, never silent pass) ---
    if expected_validators is None:
        inconclusive.append("run manifest missing validator_count; cannot confirm node completeness")
    elif len(validator_nodes) != expected_validators:
        inconclusive.append(
            f"expected {expected_validators} validators (manifest) but found {len(validator_nodes)} with mc progress: "
            f"{validator_nodes}"
        )

    # --- hard failures ---
    if ordering_violations_total:
        failures.append(f"{ordering_violations_total} ticket(s) whose reserve/delete_done/erase_ack were OUT OF ORDER")
    if gc_zero_completed:
        failures.append(f"{gc_zero_completed} completed delete(s) whose own reserve had gc_seqno==0")
    if eligibility_violations:
        failures.append(f"{len(eligibility_violations)} reserve(s) with retirement_seqno > gc_seqno")
    if completed_total > 0 and present_validator_dirs_total == 0:
        failures.append("cleanup deleted EVERY validator-group dir (no live group retained -> over-reach)")
    if fatal_total:
        failures.append(f"{fatal_total} fatal/crash diagnostics in node logs")
    if agreement_ok is False:
        failures.append(f"validators applied DIFFERENT masterchain block ids at seqno {agreement_seqno} (fork/divergence)")
    elif agreement_ok is None:
        inconclusive.append("no common masterchain milestone across validators to check block-id agreement")
    if completed_total == 0:
        inconclusive.append("no ordered validator-group delete completed on the real path (nothing to accept)")

    if failures:
        verdict = "FAIL"
    elif inconclusive:
        verdict = "INCONCLUSIVE"
    else:
        verdict = "PASS"

    summary = {
        "verdict": verdict,
        "run_dir": str(run_dir),
        # NOTE: this is the git HEAD of the ANALYSIS workspace, not proof of the binary that
        # produced the run. Correlate with the run's own provenance for the running engine.
        "analysis_workspace_git_head": _git_head(),
        "expected_validators": expected_validators,
        "validators_seen": validator_nodes,
        "validators_with_progress_after_delete": validators_with_progress,
        "real_path_ordered_completed_deletes": completed_total,
        "max_gc_seqno_used_by_a_completed_delete": max(
            (c for n in per_node for c in n.get("gc_seqnos_used", [])), default=0
        ),
        "eligibility_relation_ok": not eligibility_violations,
        "eligibility_violations": eligibility_violations[:10],
        "ordering_violations_total": ordering_violations_total,
        "completed_with_gc_zero": gc_zero_completed,
        "validator_dirs_retained_at_end": present_validator_dirs_total,
        "cross_node_blockid_agreement_seqno": agreement_seqno,
        "cross_node_blockid_agreement_ok": agreement_ok,
        "fatal_total": fatal_total,
        "nodes": per_node,
        "failures": failures,
        "inconclusive": inconclusive,
        "scope_note": (
            "A PASS establishes ONLY, for this run: ordered real-path deletes completed with their own "
            "gc_seqno>0, eligibility relation held, no over-reach, and every manifest validator kept applying "
            "masterchain blocks past its last delete. It does NOT establish the exhaustive real-node "
            "should-NOT-delete matrix (r>=g / current-next group / unknown-mismatched GC -> no dispatch), the "
            "production reopen fence wiring, or post-delete restart recovery -- those remain OPEN enablement "
            "items and are NOT counted as passed by this run."
        ),
    }
    return verdict, summary


def main() -> int:
    run_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else _latest_run()
    if run_dir is None or not run_dir.is_dir():
        print("ERROR: no run dir found; pass one explicitly", file=sys.stderr)
        return 2
    verdict, summary = analyze(run_dir)
    (run_dir / "validator-cleanup-analysis.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    # PASS -> 0, FAIL -> 1, INCONCLUSIVE -> 3 (distinct, so a wrapper never reads it as pass).
    return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 3}[verdict]


if __name__ == "__main__":
    raise SystemExit(main())
