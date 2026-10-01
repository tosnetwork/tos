#!/usr/bin/env python3
"""Verify a bounded, local C09 development observation window."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

MIN_SPAN_NS = 30 * 60 * 1_000_000_000
FUNCTIONAL_MIN_GAP_NS = 300 * 1_000_000_000
FUNCTIONAL_MAX_GAP_NS = 360 * 1_000_000_000
Q_MAX_GAP_NS = 120 * 1_000_000_000
MAX_INPUT_BYTES = 16 * 1024 * 1024
NODES = {"validator1", "validator2", "validator3", "validator4", "observer5", "observer6"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def load(path):
    with Path(path).open("rb") as source:
        raw = source.read(MAX_INPUT_BYTES + 1)
    require(len(raw) <= MAX_INPUT_BYTES, "input_too_large")
    require(raw.endswith(b"\n"), "incomplete_last_row")
    rows = [json.loads(line) for line in raw.splitlines()]
    require(rows, "empty_input")
    return rows, hashlib.sha256(raw).hexdigest()


def utc(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.utcoffset() == dt.timedelta(0), "non_utc_time")
    return parsed


def verify(functional_path, q_path):
    functional, functional_sha = load(functional_path)
    q_rows, q_sha = load(q_path)
    window = functional[0].get("window_id")
    boot = functional[0].get("boot_id")
    require(isinstance(window, str) and len(window) == 64, "window_identity")
    require(isinstance(boot, str) and boot, "boot_identity")
    previous = None
    max_functional_gap = 0
    phases = set()
    for row in functional:
        require(row.get("window_id") == window and row.get("boot_id") == boot,
                "functional_domain_changed")
        require(row.get("status") == "pass" and row.get("cleanup_confirmed") is True
                and row.get("fixed_grant_query_status") == "pass"
                and row.get("error_kind") is None and row.get("projection_probe_error") is None,
                "functional_failure")
        require(row.get("projection_head_status") in ("lagging", "caught_up"),
                "projection_probe_unavailable")
        require(type(row.get("boottime_ns")) is int and type(row.get("slot")) is int,
                "functional_counter")
        require(row.get("known_run_ids") == row.get("grant_requests_attempted"),
                "unconfirmed_grant")
        phases.add(row.get("phase"))
        if previous is not None:
            gap = row["boottime_ns"] - previous["boottime_ns"]
            require(row["slot"] == previous["slot"] + 1
                    and FUNCTIONAL_MIN_GAP_NS <= gap <= FUNCTIONAL_MAX_GAP_NS,
                    "functional_gap")
            max_functional_gap = max(max_functional_gap, gap)
        previous = row
    functional_span = functional[-1]["boottime_ns"] - functional[0]["boottime_ns"]
    require(functional_span >= MIN_SPAN_NS, "functional_under_30m")
    require("scope_negative" in phases, "scope_negative_missing")
    start, end = utc(functional[0]["wall_utc"]), utc(functional[-1]["wall_utc"])
    selected = [row for row in q_rows if start <= utc(row["wall_utc"]) <= end]
    require(len(selected) >= 2, "q_window_missing")
    max_q_gap = 0
    previous = None
    max_lag = 0
    for row in selected:
        require(type(row.get("boottime_ns")) is int, "q_clock")
        require(row.get("sample_errors") == [], "q_sample_error")
        projection = row.get("broker_projection", {})
        require(projection.get("probe_ok") is True and projection.get("http_status") == 200
                and projection.get("source_identity_match") is True
                and projection.get("manager_conflicted") is False,
                "q_projection_probe")
        require(set(row.get("nodes", {})) == NODES
                and all(node.get("status") == "fresh" and type(node.get("age_ms")) is int
                        and 0 <= node["age_ms"] <= 180_000
                        for node in row["nodes"].values()), "q_node_freshness")
        require(len(row.get("units", {})) == 7
                and all(unit.get("ActiveState") == "active"
                        and str(unit.get("NRestarts")) == "0"
                        for unit in row["units"].values()), "q_unit_state")
        max_lag = max(max_lag, int(projection["lag_global_m_seq"]))
        if previous is not None:
            gap = row["boottime_ns"] - previous["boottime_ns"]
            require(0 < gap <= Q_MAX_GAP_NS, "q_sample_gap")
            max_q_gap = max(max_q_gap, gap)
        previous = row
    q_span = selected[-1]["boottime_ns"] - selected[0]["boottime_ns"]
    require(q_span >= MIN_SPAN_NS, "q_under_30m")
    return {
        "schema_version": 1,
        "gate": "c09_development_30m",
        "result": "pass",
        "production_72h": "deferred_by_user_for_development",
        "window_id": window,
        "boot_id": boot,
        "functional_log_sha256": functional_sha,
        "q_log_sha256": q_sha,
        "functional_first_utc": functional[0]["wall_utc"],
        "functional_last_utc": functional[-1]["wall_utc"],
        "functional_rows": len(functional),
        "functional_span_ms": functional_span // 1_000_000,
        "functional_max_gap_ms": max_functional_gap // 1_000_000,
        "q_first_utc": selected[0]["wall_utc"],
        "q_last_utc": selected[-1]["wall_utc"],
        "q_rows": len(selected),
        "q_span_ms": q_span // 1_000_000,
        "q_max_gap_ms": max_q_gap // 1_000_000,
        "q_max_lag_global_m_seq": max_lag,
        "projection_caught_up_continuously": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--functional", required=True)
    parser.add_argument("--q-aware", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.functional, args.q_aware), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
