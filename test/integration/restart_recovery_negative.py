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


def _inject(node: Path, seed: int, retire_seqno: int, root_b64: str, file_b64: str, dir_wc: int, dir_cc: int) -> str:
    r = subprocess.run(
        [str(INJECT), "write", str(node), str(seed), str(retire_seqno), root_b64, file_b64, str(dir_wc), str(dir_cc)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise SystemExit(f"injection seed={seed} failed: {r.stdout}{r.stderr}")
    m = re.search(r"session=(?P<s>\S+) dir=(?P<d>\S+).* POISON_LOADABLE=(?P<l>\d)", r.stdout)
    if not m or m.group("l") != "1":
        raise SystemExit(f"injection seed={seed} not loadable: {r.stdout}")
    return m.group("s"), m.group("d")


def _record_present(node: Path, seed: int) -> bool:
    r = subprocess.run([str(INJECT), "check", str(node), str(seed)], capture_output=True, text=True)
    return "POISON_PRESENT=1" in r.stdout


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
    # Differential fixtures. Each differs from CONTROL in exactly one veto condition.
    #   name           seed retire_seqno       dir_wc dir_cc     expect_deleted  vetoed_by
    fixtures = [
        ("control",       10, 0,            root_b64, file_b64, -1, 0,        True,  None),
        ("poison_ancestry", 20, FUTURE_SEQNO, root_b64, file_b64, -1, 0,       False, "B: retirement not an ancestor of GC"),
        ("poison_obsolete", 30, 0,          root_b64, file_b64, -1, FUTURE_SEQNO, False, "C: dir cc >= on-chain cc (not obsolete)"),
        ("poison_sentinel", 40, 0,          root_b64, file_b64, 99, 0,        False, "GC oracle sentinel: unknown workchain shard"),
    ]
    injected = {}
    for name, seed, rseq, rb, fb, wc, cc, expect_del, why in fixtures:
        sess, d = _inject(node, seed, rseq, rb, fb, wc, cc)
        injected[name] = {"seed": seed, "session": sess, "dir": d, "expect_deleted": expect_del, "vetoed_by": why}
        print(f"injected {name}: session={sess} dir={d} expect_deleted={expect_del}", flush=True)

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
    max_pending = max((p for _g, p, _r in passes), default=0)

    # per-fixture disk + record state after the run
    results = {}
    for name, info in injected.items():
        dir_present = (node / "consensus" / info["dir"]).exists()
        rec_present = _record_present(node, info["seed"])
        reserved = info["session"] in reserves
        results[name] = {**info, "dir_present": dir_present, "record_present": rec_present, "reserved": reserved}

    failures = []
    # recovery
    if fatals:
        failures.append(f"{len(fatals)} fatal/crash diagnostics after restart")
    if exited_early:
        failures.append(f"engine exited on its own before shutdown (code {early_exit_code}) -- crash/early-exit")
    if not passes:
        failures.append("no VALCLEANUP cleanup pass ran after reopen")
    if not (0 < max_pending < SCAN_BUDGET):
        failures.append(f"max_pending={max_pending} is 0 or >= scan budget {SCAN_BUDGET} (fixtures may not all be examined)")
    # instrument-live: control must be deleted (reserved + dir gone + record erased)
    c = results["control"]
    if not c["reserved"]:
        failures.append("CONTROL (eligible) was NOT reserved -- the cleanup pass did not act; instrument not proven live")
    if c["dir_present"]:
        failures.append("CONTROL dir was not deleted (instrument not proven to delete anything)")
    if c["record_present"]:
        failures.append("CONTROL record was not erased")
    # per-veto negatives: each poison retained, record present, not reserved
    for name in ("poison_ancestry", "poison_obsolete", "poison_sentinel"):
        p = results[name]
        if p["reserved"]:
            failures.append(f"{name} was RESERVED for deletion (veto '{p['vetoed_by']}' failed)")
        if not p["dir_present"]:
            failures.append(f"{name} dir was DELETED (veto '{p['vetoed_by']}' failed)")
        if not p["record_present"]:
            failures.append(f"{name} record was ERASED (veto '{p['vetoed_by']}' failed)")

    verdict = "PASS" if not failures else "FAIL"
    summary = {
        "verdict": verdict,
        "node_dir": str(node),
        "reopened_no_fatal": not fatals,
        "engine_alive_until_shutdown": not exited_early,
        "cleanup_passes_after_reopen": len(passes),
        "max_pending_seen_in_a_pass": max_pending,
        "scan_budget": SCAN_BUDGET,
        "fixtures": results,
        "failures": failures,
        "fatal_sample": fatals[:5],
        "note": (
            "PASS shows a real node reopened its crash-left DB and, in one armed cleanup pass, DELETED an eligible "
            "control record while REFUSING three poisons that each fail exactly one veto (ancestry / on-chain "
            "obsolescence / unknown-GC-shard), each poison retained with its durable record intact. This isolates "
            "each veto against a real MasterchainState. It does not cover the live/next-group (is_live) veto "
            "(exercised naturally in the main run + C++ tests) nor live-consensus rejoin (peers are down here)."
        ),
    }
    (node / "restart-recovery-negative-analysis.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
