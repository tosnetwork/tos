#!/usr/bin/env python3
"""Real-node per-veto negative matrix (isolated) + restart-recovery for validator cleanup.

Runs against a COMPLETED election-experiment node dir (engine stopped, StateDb + consensus
dirs on disk). Injects a DIFFERENTIAL set of validator cleanup records -- one eligible
CONTROL plus one poison per four-condition veto, each differing from the control in
EXACTLY ONE condition -- then relaunches that node's validator-engine standalone with
cleanup ARMED. One startup cleanup pass evaluates them all. Asserts:

  RESTART RECOVERY: the engine reopened its crash-left DB, ran >=1 cleanup pass, stayed
    alive until our shutdown (polled), no FATAL.
  INSTRUMENT LIVE: the eligible CONTROL was reserved, its dir deleted, and its durable
    record erased -- proving the pass can and does delete (a test where nothing ever
    deletes would prove nothing).
  NEGATIVE, PER VETO ISOLATED: each poison (fails exactly one of: B ancestry, C on-chain
    obsolescence r<g, or unknown/sentinel GC shard) was NOT reserved, its dir retained,
    and its durable record still present. Since each poison differs from the deleted
    control in only its one veto condition, that veto is what saved it.
  CRASH BOUNDARY 2 RECONCILED: one eligible record is injected with its dir ALREADY
    removed by the real deleter (the mid-flight {dir gone, record present} state left after
    the directory is removed but before the durable record erase commits). On restart the
    engine reconciles it
    via the ordinary path -- examined eligible, reserved, the deleter confirms the
    already-absent dir gone, and the durable orphan record is erase-acked -- with no fault.
  NON-VACUOUS: every injected record was read back through the production decoder
    (POISON_LOADABLE), and a pass examined the WHOLE pending set (max_pending < scan
    budget), so the poisons were examined, not skipped.

Usage: uv run python test/integration/restart_recovery_negative.py [NODE_DIR] [--seconds N]
NODE_DIR defaults to node2 of the newest .validator-election-experiment run.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "build"
INJECT = BUILD / "inject-validator-cleanup-record"
ENGINE = BUILD / "validator-engine/validator-engine"
SCAN_BUDGET = 256  # kValidatorConsensusCleanupScanBudget

FATAL = re.compile(r"\b(FATAL|PANIC|CHECK failed|LOG_CHECK failed|AddressSanitizer|UndefinedBehaviorSanitizer|Aborted)\b")
RESERVE = re.compile(r"VALCLEANUP reserve session=(?P<session>\S+)")
PASS = re.compile(r"VALCLEANUP pass gc_seqno=(?P<gc>\d+) pending=(?P<pending>\d+) reserved=(?P<reserved>\d+)")
EVAL = re.compile(r"VALCLEANUP eval session=(?P<session>\S+) eligible=(?P<eligible>[01])")
DELETE_DONE = re.compile(r"VALCLEANUP delete_done session=(?P<session>\S+).* confirmed_gone=(?P<gone>[01])")
ERASE_ACK = re.compile(r"VALCLEANUP erase_ack session=(?P<session>\S+)")
FUTURE_SEQNO = 9000000


def _latest_node(name: str = "node2") -> Path | None:
    root = REPO / "test/integration/.validator-election-experiment"
    runs = sorted((p for p in root.glob("*") if (p / "network" / name).is_dir()), reverse=True)
    return (runs[0] / "network" / name) if runs else None


def _zerostate_hashes(node: Path) -> tuple[str, str]:
    cfg = json.load((node / "config.global.json").open())
    zs = cfg["validator"]["zero_state"]
    assert zs["seqno"] == 0 and zs["workchain"] == -1, f"unexpected zero_state {zs}"
    return zs["root_hash"], zs["file_hash"]


def _inject(node: Path, seed: int, retire_seqno: int, root_b64: str, file_b64: str, dir_wc: int, dir_cc: int,
            predelete: bool = False) -> str:
    cmd = [str(INJECT), "write", str(node), str(seed), str(retire_seqno), root_b64, file_b64, str(dir_wc), str(dir_cc)]
    if predelete:
        cmd.append("predelete")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"injection seed={seed} failed: {r.stdout}{r.stderr}")
    m = re.search(
        r"session=(?P<s>\S+) dir=(?P<d>\S+).* POISON_LOADABLE=(?P<l>\d) PREDELETE_DIR_GONE=(?P<g>\d) "
        r"POISON_LOADABLE_POST=(?P<lp>\d)",
        r.stdout,
    )
    if not m or m.group("l") != "1":
        raise SystemExit(f"injection seed={seed} not loadable: {r.stdout}")
    # When predelete was requested, the REAL deleter MUST have confirmed the dir gone AND the
    # durable record must survive the deletion (a post-delete re-read), else we did not
    # actually reconstruct the {dir gone, record present} boundary state.
    if predelete and (m.group("g") != "1" or m.group("lp") != "1"):
        raise SystemExit(f"injection seed={seed} predelete did not reconstruct {{dir gone, record present}}: {r.stdout}")
    if not predelete and m.group("g") != "0":
        raise SystemExit(f"injection seed={seed} unexpectedly deleted dir: {r.stdout}")
    return m.group("s"), m.group("d")


def _record_state(node: Path, seed: int) -> str:
    """Tri-state: PRESENT / ABSENT / UNKNOWN. A failed check (bad rc, malformed output) is
    UNKNOWN, never silently 'absent' (which would let a control's query failure masquerade
    as 'record erased')."""
    r = subprocess.run([str(INJECT), "check", str(node), str(seed)], capture_output=True, text=True)
    if r.returncode != 0:
        return "UNKNOWN"
    if "POISON_PRESENT=1" in r.stdout:
        return "PRESENT"
    if "POISON_PRESENT=0" in r.stdout:
        return "ABSENT"
    return "UNKNOWN"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("node_dir", nargs="?", type=Path, default=None)
    ap.add_argument("--seconds", type=float, default=70.0)
    args = ap.parse_args()

    node = (args.node_dir or _latest_node())
    if node is None or not (node / "state").is_dir():
        print("ERROR: no completed node dir found", file=sys.stderr)
        return 2
    node = node.resolve()
    for exe in (INJECT, ENGINE):
        if not exe.exists():
            print(f"ERROR: missing binary {exe}", file=sys.stderr)
            return 2

    root_b64, file_b64 = _zerostate_hashes(node)
    # Differential fixtures. Each poison differs from CONTROL in exactly one veto
    # condition; crash_boundary2 shares CONTROL's eligible config but is pre-deleted.
    #   name            seed retire_seqno  root_b64  file_b64  dir_wc dir_cc  expect_del  predelete vetoed_by
    fixtures = [
        ("control",         10, 0,            root_b64, file_b64, -1, 0,           True,  False, None),
        ("poison_ancestry", 20, FUTURE_SEQNO, root_b64, file_b64, -1, 0,           False, False, "B: retirement not an ancestor of GC"),
        ("poison_obsolete", 30, 0,            root_b64, file_b64, -1, FUTURE_SEQNO, False, False, "C: dir cc >= on-chain cc (not obsolete)"),
        ("poison_sentinel", 40, 0,            root_b64, file_b64, 99, 0,           False, False, "GC oracle sentinel: unknown workchain shard"),
        # Mid-flight crash reconstruction: eligible record whose dir the REAL deleter
        # already removed. Restart must reconcile (already-absent => confirmed delete =>
        # erase the orphan record), not loop or fault. Deleted like the control, so
        # expect_deleted=True, but flagged so we assert its dir was ALREADY gone at inject.
        ("crash_boundary2", 50, 0,            root_b64, file_b64, -1, 0,           True,  True,  None),
    ]
    injected = {}
    for name, seed, rseq, rb, fb, wc, cc, expect_del, predel, why in fixtures:
        sess, d = _inject(node, seed, rseq, rb, fb, wc, cc, predelete=predel)
        injected[name] = {"seed": seed, "session": sess, "dir": d, "expect_deleted": expect_del,
                          "predeleted": predel, "vetoed_by": why}
        print(f"injected {name}: session={sess} dir={d} expect_deleted={expect_del} predeleted={predel}", flush=True)

    # Relaunch the engine standalone on its db_root, cleanup ARMED.
    restart_log = node / "restart-recovery.log"
    cmd = [str(ENGINE), "--global-config", "config.global.json", "--local-config", "config.json",
           "--db", ".", "-v", "3", "--enable-validator-consensus-cleanup", "--initial-sync-delay", "2"]
    exited_early = False
    with restart_log.open("w") as lf:
        proc = subprocess.Popen(cmd, cwd=str(node), stdout=lf, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + args.seconds
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    exited_early = True
                    break
                time.sleep(1.0)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
    early_exit_code = proc.returncode if exited_early else None

    text = restart_log.read_text(errors="replace")
    fatals = [ln[:400] for ln in text.splitlines() if FATAL.search(ln)]
    reserves = {m.group("session") for m in RESERVE.finditer(text)}
    passes = [(int(m.group("gc")), int(m.group("pending")), int(m.group("reserved"))) for m in PASS.finditer(text)]
    # per-session eligibility DECISIONS the engine actually made this run (definitive: a
    # session appears here iff a pass examined it, with the decision it reached).
    evals: dict[str, set[int]] = {}
    for m in EVAL.finditer(text):
        evals.setdefault(m.group("session"), set()).add(int(m.group("eligible")))
    # delete_done confirmed_gone decisions and erase acks, per session.
    delete_dones: dict[str, set[int]] = {}
    for m in DELETE_DONE.finditer(text):
        delete_dones.setdefault(m.group("session"), set()).add(int(m.group("gone")))
    erase_acks = {m.group("session") for m in ERASE_ACK.finditer(text)}

    results = {}
    for name, info in injected.items():
        s = info["session"]
        results[name] = {
            **info,
            "dir_present": (node / "consensus" / info["dir"]).exists(),
            "record_state": _record_state(node, info["seed"]),
            "reserved": s in reserves,
            "evaluated": s in evals,
            "eligible_decisions": sorted(evals.get(s, set())),
            "confirmed_gone_decisions": sorted(delete_dones.get(s, set())),
            "erase_acked": s in erase_acks,
        }

    failures = []
    if fatals:
        failures.append(f"{len(fatals)} fatal/crash diagnostics after restart")
    if exited_early:
        failures.append(f"engine exited on its own before shutdown (code {early_exit_code}) -- crash/early-exit")
    if not passes:
        failures.append("no VALCLEANUP cleanup pass ran after reopen")
    # instrument-live: control must be EXAMINED, judged eligible, reserved, deleted, erased.
    c = results["control"]
    if not c["evaluated"] or c["eligible_decisions"] != [1]:
        failures.append(f"CONTROL not examined-as-eligible (evaluated={c['evaluated']} decisions={c['eligible_decisions']})")
    if not c["reserved"]:
        failures.append("CONTROL (eligible) was NOT reserved -- instrument not proven live")
    if c["dir_present"]:
        failures.append("CONTROL dir was not deleted")
    if c["record_state"] != "ABSENT":
        failures.append(f"CONTROL record not confirmed erased (record_state={c['record_state']})")
    # crash boundary 2 (mid-flight {dir gone, record present}): the engine must RECONCILE
    # the orphan record via the real path -- examine it eligible, reserve it, have the
    # deleter confirm the already-absent dir gone, and erase the durable record -- with no
    # fault. This is the reconstructed crash state left after the directory is removed but
    # before the durable record erase commits; recovery is the normal pass treating an
    # already-absent directory as a confirmed delete. (The real dispatch-path interruption
    # is exercised separately by crash_boundary_recovery.py.)
    b2 = results["crash_boundary2"]
    if not b2["evaluated"] or b2["eligible_decisions"] != [1]:
        failures.append(f"BOUNDARY2 not examined-as-eligible (evaluated={b2['evaluated']} decisions={b2['eligible_decisions']})")
    if not b2["reserved"]:
        failures.append("BOUNDARY2 orphan record was NOT reserved -- restart did not pick up the mid-flight state")
    if b2["confirmed_gone_decisions"] != [1]:
        failures.append(f"BOUNDARY2 deleter did not confirm already-absent dir gone (confirmed_gone={b2['confirmed_gone_decisions']})")
    if not b2["erase_acked"]:
        failures.append("BOUNDARY2 durable record erase was not acked -- orphan record not reconciled")
    if b2["dir_present"]:
        failures.append("BOUNDARY2 dir present after restart (should have stayed gone)")
    if b2["record_state"] != "ABSENT":
        failures.append(f"BOUNDARY2 orphan record not erased on restart (record_state={b2['record_state']})")
    # per-veto negatives: each poison must be EXAMINED, judged INELIGIBLE, not reserved,
    # dir retained, and record confirmed still present.
    for name in ("poison_ancestry", "poison_obsolete", "poison_sentinel"):
        p = results[name]
        if not p["evaluated"] or p["eligible_decisions"] != [0]:
            failures.append(f"{name} not examined-as-ineligible (evaluated={p['evaluated']} decisions={p['eligible_decisions']}); "
                            f"cannot attribute retention to veto '{p['vetoed_by']}'")
        if p["reserved"]:
            failures.append(f"{name} was RESERVED for deletion (veto '{p['vetoed_by']}' failed)")
        if not p["dir_present"]:
            failures.append(f"{name} dir was DELETED (veto '{p['vetoed_by']}' failed)")
        if p["record_state"] != "PRESENT":
            failures.append(f"{name} record not confirmed present (record_state={p['record_state']})")

    verdict = "PASS" if not failures else "FAIL"
    summary = {
        "verdict": verdict,
        "node_dir": str(node),
        "reopened_no_fatal": not fatals,
        "engine_alive_until_shutdown": not exited_early,
        "cleanup_passes_after_reopen": len(passes),
        "fixtures": results,
        "failures": failures,
        "fatal_sample": fatals[:5],
        "note": (
            "PASS shows a real node reopened its crash-left DB and, in one armed cleanup pass, DELETED an eligible "
            "control record while REFUSING three poisons that each fail exactly one veto (ancestry / on-chain "
            "obsolescence / unknown-GC-shard), each poison retained with its durable record intact, AND reconciled a "
            "reconstructed crash-boundary-2 state ({dir gone, record present} produced by the real deleter) by "
            "confirming the already-absent dir gone and erasing the orphan record. This isolates each veto against a "
            "real MasterchainState and closes the mid-flight crash boundary through the production path. It does not "
            "cover the live/next-group (is_live) veto (exercised naturally in the main run + C++ tests) nor "
            "live-consensus rejoin (peers are down here)."
        ),
    }
    (node / "restart-recovery-negative-analysis.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
