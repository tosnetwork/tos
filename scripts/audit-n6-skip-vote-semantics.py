#!/usr/bin/env python3
"""Classify Simplex SkipVote log sites; never treat a text substring as a vote count."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
MASTERCHAIN = re.compile(r"\[!valgroup\(-1,[^]]+\)")
SLOT = re.compile(r"SkipVote\{slot=(\d+)\}")
STAMP = re.compile(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\.(\d{9})\]")


def fail(message: str) -> None:
    raise RuntimeError(f"N6_SKIP_VOTE_SEMANTICS_FAILURE: {message}")


def classify_text(line: str) -> tuple[str, list[int]] | None:
    line = ANSI.sub("", line)
    if not MASTERCHAIN.search(line):
        return None
    slots = [int(slot) for slot in SLOT.findall(line)]
    if not slots:
        return None
    if "BroadcastVote@" in line:
        site = "local_broadcast_vote_request"
    elif "TraceEvent@" in line and "Voted{vote=SkipVote" in line:
        site = "local_cast_trace_event"
    elif "OutgoingProtocolMessage@" in line:
        site = "outgoing_protocol_rendering"
    elif "IncomingProtocolMessage@" in line:
        site = "incoming_protocol_rendering"
    elif "PersistOwnVoteIntent@" in line or "PersistOwnSignedVote@" in line:
        site = "local_vote_persistence"
    else:
        site = "certificate_or_other_diagnostic"
    return site, slots


def structured_local_casts(path: Path) -> tuple[Counter[tuple[str, int]], float]:
    masterchain_sessions: set[str] = set()
    votes: Counter[tuple[str, int]] = Counter()
    latest_by_session: dict[str, float] = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            batch = json.loads(line)
            if batch.get("@type") != "consensus.stats.events":
                continue
            session = batch["id"]
            for timestamped in batch["events"]:
                ts = timestamped.get("ts")
                if isinstance(ts, (int, float)):
                    latest_by_session[session] = max(latest_by_session.get(session, 0.0), ts)
                event = timestamped.get("event", {})
                if event.get("@type") == "consensus.stats.id" and event.get("workchain") == -1:
                    masterchain_sessions.add(session)
                if event.get("@type") != "consensus.simplex.stats.voted":
                    continue
                vote = event.get("vote", {})
                if vote.get("@type") == "consensus.simplex.skipVote":
                    votes[(session, vote["slot"])] += 1
    if len(masterchain_sessions) != 1:
        fail(f"expected one masterchain session in {path}, found {len(masterchain_sessions)}")
    session = next(iter(masterchain_sessions))
    return (
        Counter({key: count for key, count in votes.items() if key[0] == session}),
        latest_by_session[session],
    )


def line_timestamp(line: str) -> float:
    match = STAMP.search(line)
    if match is None:
        fail("SkipVote log line has no parseable timestamp")
    whole = datetime.strptime(match[1], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return whole.timestamp() + int(match[2]) / 1_000_000_000


def text_site_counts(
    path: Path, structured_horizon: float
) -> tuple[Counter[str], Counter[int], int]:
    result = subprocess.run(
        ["grep", "-aF", "SkipVote", str(path)],
        capture_output=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        fail(f"could not search node log {path}: grep exited {result.returncode}")
    sites: Counter[str] = Counter()
    local_casts: Counter[int] = Counter()
    casts_after_horizon = 0
    for line in result.stdout.decode("utf-8", errors="replace").splitlines():
        classified = classify_text(line)
        if classified is None:
            continue
        site, slots = classified
        sites[site] += 1
        if site == "local_cast_trace_event":
            if len(slots) != 1:
                fail(f"local cast line in {path} does not name exactly one slot")
            # The structured JSON timestamp is rounded to microseconds;
            # the text log retains nanoseconds for the same TraceEvent.
            if line_timestamp(line) <= structured_horizon + 0.001:
                local_casts[slots[0]] += 1
            else:
                casts_after_horizon += 1
    return sites, local_casts, casts_after_horizon


def compare_casts(node: str, text_casts: Counter[int], structured: Counter[int]) -> None:
    if text_casts != structured:
        slots = sorted(set(text_casts) | set(structured))
        differences = {
            slot: {"local_text_casts": text_casts[slot], "structured_voted": structured[slot]}
            for slot in slots
            if text_casts[slot] != structured[slot]
        }
        fail(f"{node} local cast/structured voted mismatch by slot: {differences}")


def audit(artifact_dir: Path) -> dict[str, Any]:
    result = json.loads((artifact_dir / "result.json").read_text(encoding="utf-8"))
    per_node = result["sustained_observation"]["simplex_skip_runs"]["skip_votes_per_node"]
    if not per_node:
        fail("result does not name the validator nodes whose local votes must be joined")
    node_records = {record["name"]: record for record in result["nodes"]}
    site_totals: Counter[str] = Counter()
    structured_total = 0
    unflushed_tail_total = 0
    per_node_result: dict[str, Any] = {}
    for node in sorted(per_node):
        record = node_records.get(node)
        if record is None or record.get("role") != "validator":
            fail(f"{node} is missing its validator process record")
        base = Path(record["db_root"])
        structured, horizon = structured_local_casts(base / "session-logs")
        sites, text_casts, tail_casts = text_site_counts(Path(record["log"]), horizon)
        if len({session for session, _ in structured}) > 1:
            fail(f"{node} has multiple masterchain sessions; text slot join is ambiguous")
        by_slot = Counter({slot: count for (_, slot), count in structured.items()})
        compare_casts(node, text_casts, by_slot)
        site_totals.update(sites)
        structured_total += sum(by_slot.values())
        unflushed_tail_total += tail_casts
        per_node_result[node] = {
            "text_lines_by_site": dict(sorted(sites.items())),
            "structured_local_cast_events": sum(by_slot.values()),
            "structured_unique_slots": len(by_slot),
            "sustained_result_snapshot_unique_slots": per_node[node],
            "local_cast_to_structured_one_to_one": True,
            "local_casts_after_structured_horizon": tail_casts,
            "structured_horizon_wall_unix_seconds": horizon,
        }
    return {
        "evidence_class": "COLOCATED_DIAGNOSTIC_ONLY",
        "text_semantics": "site occurrences, not a count of distinct or locally cast protocol votes",
        "snapshot_note": "node logs can include events after the sustained result snapshot during teardown",
        "text_lines_by_site": dict(sorted(site_totals.items())),
        "structured_local_cast_events": structured_total,
        "local_casts_after_structured_horizon": unflushed_tail_total,
        "local_cast_to_structured_one_to_one": True,
        "per_node": per_node_result,
    }


def self_test() -> None:
    sample = "[!valgroup(-1,8000000000000000).0.SimplexPool] "
    peer = classify_text(sample + "IncomingProtocolMessage@0x1{vote=SkipVote{slot=7}}")
    cast = classify_text(sample + "TraceEvent@0x1{event=Voted{vote=SkipVote{slot=7}}}")
    if peer != ("incoming_protocol_rendering", [7]) or cast != ("local_cast_trace_event", [7]):
        fail("text source sites were not distinguished")
    if classify_text("[!valgroup(0,8000000000000000).0] SkipVote{slot=7}") is not None:
        fail("basechain text was counted as masterchain evidence")
    compare_casts("synthetic", Counter({7: 1}), Counter({7: 1}))
    try:
        compare_casts("synthetic", Counter({7: 1}), Counter())
    except RuntimeError as error:
        if "local cast/structured voted mismatch" not in str(error):
            raise
    else:
        fail("a missing structured event did not make the local-cast invariant fail")
    # A received peer vote cannot become a local-vote count merely because
    # its rendered text contains SkipVote.
    if peer[0] == "local_cast_trace_event":
        fail("a received peer vote was promoted to a local vote")
    print("N6_SKIP_VOTE_SEMANTICS_OK: source sites and local-cast invariant checked")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--artifact-dir", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        print(json.dumps(audit(args.artifact_dir), indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
