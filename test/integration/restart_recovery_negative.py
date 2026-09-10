#!/usr/bin/env python3
"""Real-node restart-recovery + injection-negative acceptance for validator cleanup.

Runs against a COMPLETED election-experiment node directory (engine already stopped, its
StateDb + consensus dirs on disk with real deletions applied). Does two things in one
standalone relaunch:

  1. NEGATIVE (should-NOT-delete) by injection: writes a deliberately INELIGIBLE cleanup
     record (future/non-ancestor retirement checkpoint + future catchain seqno) and its
     canonical consensus dir into the stopped node's StateDb via
     inject-validator-cleanup-record. The four-condition gate must REFUSE it.

  2. RESTART RECOVERY: relaunches the node's validator-engine on its own db_root with
     cleanup armed. Startup reopens the (crash-left) RocksDB, loads the durable pending
     cleanup records (including the injected poison), and runs one cleanup pass.

Then asserts, from the restart log + disk:
  * RECOVERY: the engine reopened and reached its startup barrier (loaded pending cleanup
    records) with NO FATAL / crash;
  * NEGATIVE: NO `VALCLEANUP reserve session=<poison>` was emitted, and the poison dir is
    still present on disk (the gate refused the ineligible record);
  * SAFETY: any VALCLEANUP reserve that DID occur names a real (non-poison) session (a
    genuinely-eligible leftover), never the poison.

Usage:
    uv run python test/integration/restart_recovery_negative.py [NODE_DIR] [--seconds N]
NODE_DIR defaults to node1 of the newest .validator-election-experiment run.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "build"
INJECT = BUILD / "inject-validator-cleanup-record"
ENGINE = BUILD / "validator-engine/validator-engine"

FATAL = re.compile(
    r"\b(FATAL|PANIC|CHECK failed|LOG_CHECK failed|AddressSanitizer|UndefinedBehaviorSanitizer|Aborted)\b"
)
RESERVE = re.compile(r"VALCLEANUP reserve session=(?P<session>\S+)")
# a cleanup pass actually ran and examined the durable records against a GC snapshot.
PASS = re.compile(r"VALCLEANUP pass gc_seqno=(?P<gc>\d+) pending=(?P<pending>\d+) reserved=(?P<reserved>\d+)")


def _latest_node() -> Path | None:
    root = REPO / "test/integration/.validator-election-experiment"
    runs = sorted((p for p in root.glob("*") if (p / "network/node1").is_dir()), reverse=True)
    return (runs[0] / "network/node1") if runs else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("node_dir", nargs="?", type=Path, default=None)
    ap.add_argument("--seconds", type=float, default=60.0, help="how long to run the relaunched engine")
    args = ap.parse_args()

    node = (args.node_dir or _latest_node())
    if node is None or not (node / "state").is_dir():
        print("ERROR: no completed node dir found (need <run>/network/node1/state)", file=sys.stderr)
        return 2
    node = node.resolve()
    for exe in (INJECT, ENGINE):
        if not exe.exists():
            print(f"ERROR: missing binary {exe}", file=sys.stderr)
            return 2

    # 1) inject the ineligible poison record + dir into the stopped node's StateDb.
    inj = subprocess.run([str(INJECT), str(node)], capture_output=True, text=True)
    if inj.returncode != 0:
        print(f"ERROR: injection failed: {inj.stderr}", file=sys.stderr)
        return 2
    m = re.search(r"INJECTED session=(?P<s>\S+) dir=(?P<d>\S+).* POISON_LOADABLE=(?P<l>\d)", inj.stdout)
    if not m:
        print(f"ERROR: unexpected injector output: {inj.stdout}", file=sys.stderr)
        return 2
    poison_session = m.group("s")
    poison_dir = m.group("d")
    poison_loadable = m.group("l") == "1"
    print(f"injected poison session={poison_session} dir={poison_dir} loadable={poison_loadable}", flush=True)
    poison_path = node / "consensus" / poison_dir
    assert poison_path.exists(), "injector did not create the poison dir"
    SCAN_BUDGET = 256  # kValidatorConsensusCleanupScanBudget in manager.hpp

    # 2) relaunch the engine standalone on its db_root, cleanup ARMED.
    restart_log = node / "restart-recovery.log"
    cmd = [
        str(ENGINE),
        "--global-config", "config.global.json",
        "--local-config", "config.json",
        "--db", ".",
        "-v", "3",
        "--enable-validator-consensus-cleanup",
        "--initial-sync-delay", "2",
    ]
    exited_early = False
    with restart_log.open("w") as lf:
        proc = subprocess.Popen(cmd, cwd=str(node), stdout=lf, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + args.seconds
            while time.monotonic() < deadline:
                if proc.poll() is not None:  # engine exited/crashed ON ITS OWN before shutdown
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

    # 3) post-run: the engine is stopped -> confirm the poison RECORD is STILL durably
    # present (a wrongful cleanup would have erased it on the erase-ack).
    chk = subprocess.run([str(INJECT), "--check", str(node)], capture_output=True, text=True)
    poison_record_present = "POISON_PRESENT=1" in chk.stdout

    text = restart_log.read_text(errors="replace")
    fatals = [ln[:400] for ln in text.splitlines() if FATAL.search(ln)]
    reserves = [m.group("session") for m in RESERVE.finditer(text)]
    passes = [(int(m.group("gc")), int(m.group("pending")), int(m.group("reserved"))) for m in PASS.finditer(text)]
    poison_reserved = poison_session in reserves
    poison_retained = poison_path.exists()
    max_pending = max((p for _gc, p, _res in passes), default=0)
    # A pass ran and examined the WHOLE pending set within one scan budget (so the poison,
    # which is durably loadable, was necessarily examined -- not skipped past a budget).
    pass_examined_all = bool(passes) and 0 < max_pending < SCAN_BUDGET

    failures = []
    if not poison_loadable:
        failures.append("injected poison record is not loadable via the production decoder (test fixture invalid)")
    if fatals:
        failures.append(f"{len(fatals)} fatal/crash diagnostics after restart")
    if exited_early:
        failures.append(f"engine exited on its own before shutdown (code {early_exit_code}) -- crash/early-exit, not recovery")
    if not passes:
        failures.append("no VALCLEANUP cleanup pass ran after reopen (recovery/pass not shown; refusal would be vacuous)")
    elif not pass_examined_all:
        failures.append(f"a pass ran but max_pending={max_pending} is 0 or >= scan budget {SCAN_BUDGET} (poison may not have been examined)")
    if poison_reserved:
        failures.append("the ineligible poison record was RESERVED for deletion (should-NOT-delete violated)")
    if not poison_retained:
        failures.append("the ineligible poison dir was DELETED (should-NOT-delete violated)")
    if not poison_record_present:
        failures.append("the ineligible poison RECORD was erased from StateDb (should-NOT-delete violated)")

    verdict = "PASS" if not failures else "FAIL"
    import json

    summary = {
        "verdict": verdict,
        "node_dir": str(node),
        "poison_session": poison_session,
        "poison_dir": poison_dir,
        "poison_loadable_at_injection": poison_loadable,
        "reopened_no_fatal": not fatals,
        "engine_alive_until_shutdown": not exited_early,
        "cleanup_passes_after_reopen": len(passes),
        "pass_examined_whole_pending_set": pass_examined_all,
        "max_pending_seen_in_a_pass": max_pending,
        "scan_budget": SCAN_BUDGET,
        "poison_reserved": poison_reserved,
        "poison_retained_on_disk": poison_retained,
        "poison_record_present_after_run": poison_record_present,
        "total_reserves_after_restart": len(reserves),
        "reserves_are_all_non_poison": all(s != poison_session for s in reserves),
        "restart_log": str(restart_log),
        "failures": failures,
        "fatal_sample": fatals[:5],
        "note": (
            "PASS shows a real node reopened its crash-left DB, loaded durable cleanup records, "
            "and REFUSED to reserve/delete a deliberately ineligible (future-retirement, future-cc) "
            "record while remaining crash-free. It does not by itself cover rejoining live consensus "
            "(peers are down here) or the full negative matrix."
        ),
    }
    (node / "restart-recovery-negative-analysis.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
