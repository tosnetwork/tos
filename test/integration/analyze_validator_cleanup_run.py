#!/usr/bin/env python3
"""Analyze a validator-election experiment run for GATED validator-cleanup evidence.

Reads the per-node engine logs of a run produced by

    uv run python scripts/validator-election-stage-a.py --mode experiment --stage a \
        --enable-consensus-cleanup --duration-seconds <N> ...

and emits a verdict about the REAL validator-group cleanup path (Finding 1), keyed on the
distinguishable `VALCLEANUP reserve|delete_done|erase_ack` trace (manager.cpp), NOT the
observer startup sweep's "reclaimed ..." log.

POSITIVE (should-delete fired and completed on the real path):
  * >=1 reserved op whose SAME (session,generation,attempt) reached delete_done
    confirmed_gone=1 AND erase_ack;
  * the reserved directory is gone from disk at the end;
  * the reserve carried gc_seqno>0 -> a post-genesis (election) key block advanced the
    GC floor (otherwise the gated path can't run at all).

SAFETY (survived the live deletions):
  * no FATAL / sanitizer / CHECK-failed / Aborted line in any node log;
  * every node's log kept advancing PAST the last erase_ack timestamp (no node died or
    stalled through the reclamations).

This is the "should-delete + survived" half of the acceptance. The full "should-NOT-
delete" negative matrix (current/next group, r>=g, unknown/mismatched GC -> no reserve,
dir untouched) and recovery-after-delete are covered deterministically by the C++
integration/pure tests (test-validator-cleanup*, scenario 5 in particular); this real-net
run additionally demonstrates the safety gate does not break a live group on a real
MasterchainState (survival + continued progress).

Usage:
    uv run python test/integration/analyze_validator_cleanup_run.py [RUN_DIR]
If RUN_DIR is omitted, the newest run under test/integration/.validator-election-experiment/
is used.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

TS = r"\[\s*\d+\]\[t\s*\d+\]\[(?P<ts>[0-9:. \-]+)\]"
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
ANY_TS = re.compile(r"\[\s*\d\]\[t\s*\d+\]\[(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\]")
FATAL = re.compile(
    r"\b(FATAL|PANIC|CHECK failed|LOG_CHECK failed|AddressSanitizer|UndefinedBehaviorSanitizer|Aborted)\b"
)


def _latest_run() -> Path | None:
    root = REPO / "test/integration/.validator-election-experiment"
    runs = sorted((p for p in root.glob("*") if (p / "network").is_dir()), reverse=True)
    return runs[0] if runs else None


def _key(m: re.Match) -> tuple[str, str, str]:
    return (m.group("session"), m.group("gen"), m.group("attempt"))


def _last_timestamp(text: str) -> str | None:
    last = None
    for m in ANY_TS.finditer(text):
        last = m.group("ts")
    return last


def analyze(run_dir: Path) -> int:
    network = run_dir / "network"
    node_dirs = sorted(p for p in network.glob("node*") if p.is_dir())
    if not node_dirs:
        print(f"ERROR: no node dirs under {network}", file=sys.stderr)
        return 2

    reserves: list[dict] = []
    completed: list[dict] = []  # reserve that reached delete_done(gone=1) AND erase_ack
    fatal_lines: list[str] = []
    per_node = []
    max_gc_seqno = 0

    for nd in node_dirs:
        log = nd / "log"
        text = log.read_text(errors="replace") if log.is_file() else ""
        res = {_key(m): m.groupdict() for m in RESERVE.finditer(text)}
        done_ok = {_key(m) for m in DELETE_DONE.finditer(text) if m.group("gone") == "1"}
        acked = {_key(m) for m in ERASE_ACK.finditer(text)}
        # timestamp of the last erase_ack on this node (for the "alive after" check).
        ack_iter = list(ERASE_ACK.finditer(text))
        node_reserves = list(res.values())
        node_completed = [res[k] for k in res if k in done_ok and k in acked]
        for r in node_reserves:
            max_gc_seqno = max(max_gc_seqno, int(r["gc"]))
        node_fatals = [ln[:500] for ln in text.splitlines() if FATAL.search(ln)]
        fatal_lines += [f"{nd.name}: {ln}" for ln in node_fatals]

        # last erase_ack line position -> is there log activity AFTER it? (survival)
        alive_after_last_delete = None
        if ack_iter:
            tail = text[ack_iter[-1].end():]
            alive_after_last_delete = _last_timestamp(tail) is not None

        # confirm each completed reserve's dir is gone from disk now
        gone_on_disk = []
        for r in node_completed:
            gone_on_disk.append(not (nd / "consensus" / r["dir"]).exists())

        reserves += node_reserves
        completed += node_completed
        per_node.append(
            {
                "node": nd.name,
                "reserves": len(node_reserves),
                "completed_deletes": len(node_completed),
                "completed_dirs_gone_from_disk": sum(1 for g in gone_on_disk if g),
                "completed_dirs_still_present": sum(1 for g in gone_on_disk if not g),
                "last_log_ts": _last_timestamp(text),
                "alive_after_last_delete": alive_after_last_delete,
                "fatal_lines": len(node_fatals),
            }
        )

    completed_total = len(completed)
    all_completed_dirs_gone = all(
        n["completed_dirs_still_present"] == 0 for n in per_node
    )
    # survival: on every node that did a delete, the log continued afterwards.
    survived = all(
        (n["alive_after_last_delete"] is None) or (n["alive_after_last_delete"] is True)
        for n in per_node
    )

    failures: list[str] = []
    if completed_total == 0:
        failures.append(
            "no validator-group delete completed on the REAL path "
            "(no reserve -> delete_done(gone=1) -> erase_ack triple)"
        )
    if max_gc_seqno == 0 and completed_total > 0:
        failures.append("deletes fired but gc_seqno==0 (no post-genesis key block advanced the GC floor?)")
    if not all_completed_dirs_gone:
        failures.append("a completed-delete directory is still present on disk")
    if not survived:
        failures.append("a node's log did not continue after its last delete (possible death/stall through cleanup)")
    if fatal_lines:
        failures.append(f"{len(fatal_lines)} fatal/crash diagnostics in node logs")

    verdict = "PASS" if not failures else "FAIL"
    summary = {
        "verdict": verdict,
        "run_dir": str(run_dir),
        "real_path_completed_deletes": completed_total,
        "distinct_reserved_ops": len({_key_from(r) for r in reserves}),
        "max_gc_seqno_at_reserve": max_gc_seqno,
        "nodes": per_node,
        "failures": failures,
        "fatal_sample": fatal_lines[:5],
        "note": (
            "PASS proves the gated validator cleanup FIRED and COMPLETED on the real path "
            "and every node survived. The should-NOT-delete negative matrix and recovery "
            "are covered by the C++ tests, not by this run."
        ),
    }
    out = run_dir / "validator-cleanup-analysis.json"
    out.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if not failures else 1


def _key_from(r: dict) -> tuple[str, str, str]:
    return (r["session"], r["gen"], r["attempt"])


def main() -> int:
    run_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else _latest_run()
    if run_dir is None or not run_dir.is_dir():
        print("ERROR: no run dir found; pass one explicitly", file=sys.stderr)
        return 2
    return analyze(run_dir)


if __name__ == "__main__":
    raise SystemExit(main())
