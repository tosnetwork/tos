#!/usr/bin/env python3
"""Join DEBUG ADNL external-query events by id for a diagnostic cluster run."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

EVENT = re.compile(r"ADNL_EXT_QUERY (\w+) id=([0-9A-F]{64})(?:\s|$)")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def events(path: Path, *, outer_client: bool) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = ANSI.sub("", raw)
        if outer_client and line.startswith("[INFO]["):
            continue  # Node stdout is mirrored into the outer process log.
        match = EVENT.search(line)
        if match:
            found.setdefault(match[2], []).append(line[line.index("ADNL_EXT_QUERY ") :])
    return found


def classify(lines: list[str]) -> str:
    joined = "\n".join(lines)
    if "client_timeout" not in joined:
        return "answered" if "client_answer" in joined else "incomplete_without_timeout"
    if "admission=drop reason=per-connection-limit" in joined:
        return "server_per_connection_admission_drop"
    if "admission=drop reason=server-or-per-ip-limit" in joined:
        return "server_or_per_ip_admission_drop"
    if "server_completion" in joined and "response_sent=false" in joined:
        return "server_completion_without_answer"
    if "client_transmit" not in joined:
        return "client_not_transmitted"
    if "server_ingress" not in joined:
        return "transmitted_without_server_ingress"
    return "server_accepted_without_client_answer"


def analyze(client_log: Path, node_logs: list[Path]) -> dict[str, object]:
    client = events(client_log, outer_client=True)
    server: dict[str, list[str]] = {}
    for path in node_logs:
        for query_id, lines in events(path, outer_client=False).items():
            server.setdefault(query_id, []).extend(lines)
    queries = {}
    for query_id, client_lines in client.items():
        if not any("client_create" in line for line in client_lines):
            continue
        lines = client_lines + server.get(query_id, [])
        queries[query_id] = {"classification": classify(lines), "events": lines}
    return {"query_count": len(queries), "queries": queries}


def self_test() -> None:
    cases = {
        "client_not_transmitted": ["client_create", "client_timeout"],
        "server_per_connection_admission_drop": [
            "client_create",
            "client_transmit",
            "server_ingress admission=drop reason=per-connection-limit",
            "client_timeout",
        ],
        "server_completion_without_answer": [
            "client_create",
            "client_transmit",
            "server_ingress admission=accepted",
            "server_completion outcome=error response_sent=false",
            "client_timeout",
        ],
        "answered": [
            "client_create",
            "client_transmit",
            "server_ingress admission=accepted",
            "server_completion outcome=success response_sent=true",
            "client_answer",
        ],
    }
    for expected, lines in cases.items():
        actual = classify(lines)
        if actual != expected:
            raise RuntimeError(f"ADNL_QUERY_ID_ANALYSIS_FAILURE: expected {expected}, got {actual}")
    print(
        "ADNL_QUERY_ID_ANALYSIS_OK: missing transmit, admission drop, failed completion, and answered paths distinguished"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--client-log", type=Path)
    parser.add_argument("--node-log", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.client_log is None or not args.node_log:
        parser.error("--client-log and at least one --node-log are required")
    print(json.dumps(analyze(args.client_log, args.node_log), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
