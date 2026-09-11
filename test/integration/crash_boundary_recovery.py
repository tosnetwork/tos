#!/usr/bin/env python3
"""Real crash-boundary reconciliation for validator consensus-DB cleanup.

The predelete fixture (restart_recovery_negative.py) reconstructs {directory gone, durable
record present} by calling the deleter directly. This test is different: it drives the REAL
worker -> manager dispatch path and INTERRUPTS it at the boundary. With the engine launched
under --test-consensus-cleanup-crash-before-erase, the manager exits abruptly the instant
the worker has confirmed a consensus directory removed but before the durable record erase
is dispatched. That abrupt exit leaves {directory gone, record present} -- produced by the
production code at a real crash instant, not by a fixture. A second launch (crash disarmed)
must reconcile it.

Runs against a COMPLETED election node dir whose GC floor has advanced (so an injected
control record is genuinely eligible). It first resets the durable cleanup records to a
clean slate, then injects exactly one eligible control, so the crash fires on that record.

Asserts:
  CRASH AT THE BOUNDARY: the first launch (cleanup armed + crash armed) exits on its own
    with a non-zero code; its log shows delete_done confirmed_gone=1 and the
    test_crash_before_erase marker for the injected session, and NO erase_ack for it (the
    durable erase never ran).
  MID-FLIGHT STATE ON DISK: that session's directory is gone and its durable record is
    still PRESENT -- the real {directory gone, record present}.
  RECONCILED ON RESTART: the second launch (cleanup armed, crash disarmed) reserves the
    orphan, the deleter confirms the already-absent directory gone, the record is
    erase-acked and reads back ABSENT, the engine stays alive, and there is no fault.

Usage: uv run python test/integration/crash_boundary_recovery.py [NODE_DIR] [--seconds N]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

from restart_recovery_negative import ENGINE, INJECT, _latest_node, _zerostate_hashes

FATAL = re.compile(r"\b(FATAL|PANIC|CHECK failed|LOG_CHECK failed|AddressSanitizer|UndefinedBehaviorSanitizer|Aborted)\b")
DELETE_DONE = re.compile(r"VALCLEANUP delete_done session=(?P<s>\S+).* confirmed_gone=(?P<g>[01])")
CRASH_MARK = re.compile(r"VALCLEANUP test_crash_before_erase session=(?P<s>\S+)")
ERASE_ACK = re.compile(r"VALCLEANUP erase_ack session=(?P<s>\S+)")
RESERVE = re.compile(r"VALCLEANUP reserve session=(?P<s>\S+)")
SEED = 60


def _inject_eligible(node: Path, root_b64: str, file_b64: str) -> str:
    # Eligible control: zerostate retirement (ancestor of any GC floor), masterchain
    # workchain, obsolete catchain seqno 0. No predelete -- the real deleter runs live.
    r = subprocess.run(
        [str(INJECT), "write", str(node), str(SEED), "0", root_b64, file_b64, "-1", "0"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise SystemExit(f"injection failed: {r.stdout}{r.stderr}")
    m = re.search(r"session=(?P<s>\S+) dir=\S+.* POISON_LOADABLE=1", r.stdout)
    if not m:
        raise SystemExit(f"injection not loadable: {r.stdout}")
    return m.group("s")


def _check(node: Path) -> tuple[str, int]:
    """(record_state, dir_present) for SEED. record_state is PRESENT/ABSENT/UNKNOWN;
    dir_present is 1/0 when the record is present, -1 when it is not."""
    r = subprocess.run([str(INJECT), "check", str(node), str(SEED)], capture_output=True, text=True)
    if r.returncode != 0:
        return ("UNKNOWN", -1)
    dirp = -1
    dm = re.search(r"DIR_PRESENT=(-?\d+)", r.stdout)
    if dm:
        dirp = int(dm.group(1))
    if "POISON_PRESENT=1" in r.stdout:
        return ("PRESENT", dirp)
    if "POISON_PRESENT=0" in r.stdout:
        return ("ABSENT", dirp)
    return ("UNKNOWN", dirp)


def _launch(node: Path, log_name: str, extra_args: list[str], seconds: float, expect_self_exit: bool):
    log = node / log_name
    cmd = [str(ENGINE), "--global-config", "config.global.json", "--local-config", "config.json",
           "--db", ".", "-v", "3", "--enable-validator-consensus-cleanup", "--initial-sync-delay", "2", *extra_args]
    self_exited = False
    with log.open("w") as lf:
        proc = subprocess.Popen(cmd, cwd=str(node), stdout=lf, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    self_exited = True
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
    return log.read_text(errors="replace"), self_exited, proc.returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("node_dir", nargs="?", type=Path, default=None)
    ap.add_argument("--seconds", type=float, default=150.0, help="max wait for the crash launch")
    ap.add_argument("--reconcile-seconds", type=float, default=60.0)
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
    subprocess.run([str(INJECT), "reset", str(node)], check=True)
    session = _inject_eligible(node, root_b64, file_b64)
    print(f"injected eligible control: session={session}", flush=True)

    # Phase 1: crash at the boundary.
    crash_text, self_exited, code = _launch(
        node, "crash-boundary-crash.log", ["--test-consensus-cleanup-crash-before-erase"],
        args.seconds, expect_self_exit=True,
    )
    crash_marks = {m.group("s") for m in CRASH_MARK.finditer(crash_text)}
    crash_done = {m.group("s"): m.group("g") for m in DELETE_DONE.finditer(crash_text)}
    crash_erase_acks = {m.group("s") for m in ERASE_ACK.finditer(crash_text)}
    crash_fatals = [ln[:400] for ln in crash_text.splitlines() if FATAL.search(ln)]

    # Phase 2: mid-flight on-disk state produced by the real crash.
    mid_state, mid_dir = _check(node)

    # Phase 3: reconcile on a clean restart (crash disarmed).
    recon_text, recon_exited, recon_code = _launch(
        node, "crash-boundary-reconcile.log", [], args.reconcile_seconds, expect_self_exit=False,
    )
    recon_reserves = {m.group("s") for m in RESERVE.finditer(recon_text)}
    recon_done = {m.group("s"): m.group("g") for m in DELETE_DONE.finditer(recon_text)}
    recon_erase_acks = {m.group("s") for m in ERASE_ACK.finditer(recon_text)}
    recon_fatals = [ln[:400] for ln in recon_text.splitlines() if FATAL.search(ln)]
    recon_state, _ = _check(node)

    failures = []
    # Crash at the boundary.
    if not self_exited:
        failures.append("crash launch did not exit on its own (fault never fired)")
    elif code == 0:
        failures.append("crash launch exited 0 (expected abrupt non-zero exit at the fault)")
    if session not in crash_marks:
        failures.append(f"no test_crash_before_erase marker for injected session (marks={sorted(crash_marks)})")
    if crash_done.get(session) != "1":
        failures.append(f"injected session not delete_done confirmed_gone=1 in crash log (got {crash_done.get(session)})")
    if session in crash_erase_acks:
        failures.append("injected session was erase-acked before the crash (erase should NOT have run)")
    if crash_fatals:
        failures.append(f"{len(crash_fatals)} fatal diagnostics in crash log (expected only the abrupt exit)")
    # Mid-flight state.
    if mid_state != "PRESENT":
        failures.append(f"mid-flight durable record not PRESENT (got {mid_state})")
    if mid_dir != 0:
        failures.append(f"mid-flight directory not gone (DIR_PRESENT={mid_dir}; expected 0)")
    # Reconciled on restart.
    if not recon_exited and recon_code not in (None, -15, 0):
        pass  # terminated by us at shutdown is expected; nothing to assert on the code
    if recon_exited:
        failures.append(f"reconcile launch exited on its own (code {recon_code}) -- crash/early-exit")
    if session not in recon_reserves:
        failures.append("orphan record was NOT reserved on restart")
    if recon_done.get(session) != "1":
        failures.append(f"reconcile delete_done confirmed_gone!=1 for session (got {recon_done.get(session)})")
    if session not in recon_erase_acks:
        failures.append("orphan record erase was not acked on restart")
    if recon_state != "ABSENT":
        failures.append(f"orphan record not erased on restart (record_state={recon_state})")
    if recon_fatals:
        failures.append(f"{len(recon_fatals)} fatal diagnostics after reconcile restart")

    verdict = "PASS" if not failures else "FAIL"
    summary = {
        "verdict": verdict,
        "node_dir": str(node),
        "session": session,
        "crash": {
            "self_exited": self_exited,
            "exit_code": code,
            "marker_for_session": session in crash_marks,
            "delete_done_confirmed_gone": crash_done.get(session),
            "erase_acked_before_crash": session in crash_erase_acks,
            "fatals": crash_fatals[:3],
        },
        "mid_flight": {"record_state": mid_state, "dir_present": mid_dir},
        "reconcile": {
            "engine_alive_until_shutdown": not recon_exited,
            "reserved": session in recon_reserves,
            "delete_done_confirmed_gone": recon_done.get(session),
            "erase_acked": session in recon_erase_acks,
            "record_state": recon_state,
            "fatals": recon_fatals[:3],
        },
        "failures": failures,
        "note": (
            "PASS shows the REAL dispatch path interrupted at the boundary (worker confirmed the directory gone, "
            "durable erase not yet dispatched) leaving {dir gone, record present}, and a clean restart reconciling it "
            "(reserve -> confirmed already-absent -> erase-ack -> record ABSENT) with no fault. This is the actual "
            "operation ordering under an abrupt exit, not a fixture reconstruction."
        ),
    }
    (node / "crash-boundary-recovery-analysis.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
