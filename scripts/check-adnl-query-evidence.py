#!/usr/bin/env python3
"""Check one-host ADNL query attempts against raw journald records and fixed provenance."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import subprocess
from pathlib import Path

ID = re.compile(r"ADNL_EXT_QUERY ([a-z_]+) id=([0-9a-fA-F]{64})(?:\s|$)")
HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
SGR = re.compile(rb"\x1b\[(?:0|1;31|1;32|1;33|1;34|1;36|1;90)m")
EVENT_TIME = re.compile(r"^\[ ?[0-9]+\]\[t ?[0-9]+\]\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d{9})\]"
                        r"\[([^\]/:]+):[0-9]+\](?:\[[#!&][^\]]*\])*\t")
STAGE_SOURCE = {"client_create": "adnl-ext-client.hpp", "client_refuse": "adnl-ext-client.hpp",
                "client_transmit": "adnl-ext-client.hpp", "client_answer": "adnl-ext-client.cpp",
                "client_complete": "adnl-query.cpp", "client_timeout": "adnl-query.cpp",
                "server_ingress": "adnl-ext-server.cpp", "server_completion": "adnl-ext-server.cpp",
                "server_answer_enqueue": "adnl-ext-server.cpp"}
BOOT = re.compile(r"[0-9a-fA-F]{32}\Z")
STAGES = ("client_create", "client_transmit", "server_ingress", "server_completion",
          "server_answer_enqueue", "client_answer", "client_complete")
SOURCE_FILES = ("adnl/adnl-ext-client.hpp", "adnl/adnl-ext-client.cpp",
                "adnl/adnl-ext-server.cpp", "adnl/adnl-ext-connection.cpp",
                "adnl/adnl-ext-connection.hpp", "adnl/adnl-query.cpp",
                "scripts/analyze-adnl-query-id-trace.py",
                "scripts/check-adnl-query-evidence.py", "tdutils/td/utils/logging.cpp",
                "tdutils/td/utils/StringBuilder.h")


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def boot_id(value: object) -> str:
    require(isinstance(value, str), "boot ID absent")
    compact = value.replace("-", "").lower()
    require(BOOT.fullmatch(compact) is not None and int(compact, 16) != 0,
            "boot ID malformed")
    return compact


def source_identity(manifest: dict) -> None:
    root = Path(manifest["source_root"]).resolve()
    commit = manifest["source_commit"]
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "source commit absent")
    head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain",
                                     "--untracked-files=no"], text=True)
    require(head == commit and not dirty, "source tree is not fixed and clean")
    hashes = manifest.get("source_files") or {}
    require(set(hashes) == set(SOURCE_FILES), "source file manifest incomplete")
    for name in SOURCE_FILES:
        require(HEX64.fullmatch(hashes[name]) is not None
                and sha((root / name).read_bytes()) == hashes[name],
                f"source bytes differ: {name}")


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_or_binary(row: dict) -> None:
    path = Path(row["path"])
    require(HEX64.fullmatch(row.get("sha256", "")) is not None
            and file_sha(path) == row["sha256"].lower(),
            f"retained bytes differ: {path}")


def key_value(message: str, key: str) -> str | None:
    match = re.search(r"(?:^|\s)" + re.escape(key) + r"=([^\s]+)", message)
    return match.group(1) if match else None


def socket_host(endpoint: object) -> str:
    require(isinstance(endpoint, str), "client local socket endpoint absent")
    if endpoint.startswith("["):
        host, marker, port = endpoint[1:].partition("]:")
    else:
        host, marker, port = endpoint.rpartition(":")
    require(bool(marker) and port.isdecimal() and 0 < int(port) <= 65535,
            "client local socket endpoint malformed")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError as error:
        raise ValueError("client local socket host is not an IP address") from error


def message_bytes(value: object) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8", errors="surrogateescape")
    require(isinstance(value, list)
            and all(type(item) is int and 0 <= item <= 255 for item in value),
            "journal MESSAGE is neither text nor a byte array")
    return bytes(value)


def event_wall_ns(match: re.Match) -> int:
    try:
        stamp = datetime.strptime(match[1], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ValueError("source event timestamp malformed") from error
    seconds = (stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)).days * 86400
    seconds += stamp.hour * 3600 + stamp.minute * 60 + stamp.second
    value = seconds * 1_000_000_000 + int(match[2])
    require(value > 0, "source event timestamp is not positive")
    return value


def raw_events(row: dict, role: str, log_name: str, expected_boot: str,
               tracked_ids: set[str]) -> tuple[list[dict], list[dict]]:
    source_or_binary(row)
    require(type(row.get("pid")) is int and row["pid"] > 0, "log PID absent")
    require(boot_id(row.get("boot_id")) == expected_boot, "log boot differs")
    endpoint = row.get("endpoint")
    require(isinstance(endpoint, str) and endpoint, "log endpoint absent")
    result, excluded = [], []
    with Path(row["path"]).open("rb") as handle:
        for line_number, raw in enumerate(handle, 1):
            try:
                entry = json.loads(raw)
            except (ValueError, TypeError) as error:
                raise ValueError("raw journal JSON malformed") from error
            require(isinstance(entry, dict), "raw journal JSON is not an object")
            original_message = message_bytes(entry.get("MESSAGE"))
            view = SGR.sub(b"", original_message)
            require(b"\x1b" not in view, "journal MESSAGE contains an unsupported escape")
            try:
                message = view.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError("journal MESSAGE is not UTF-8") from error
            if not ID.search(message):
                continue
            prefix = EVENT_TIME.match(message)
            require(prefix is not None, "source event nanosecond timestamp absent")
            match = ID.match(message, prefix.end())
            require(match is not None, "query stage is not the source message body")
            stage, query_id = match.group(1), match.group(2).upper()
            require(stage in STAGES or stage in ("client_refuse", "client_timeout"),
                    f"unknown query stage {stage}")
            require(prefix[3] == STAGE_SOURCE[stage], "query stage source file differs")
            unrelated = (role == "server" and stage in ("client_complete", "client_timeout")
                         and prefix[3] == "adnl-query.cpp" and query_id not in tracked_ids)
            require(unrelated or (stage.startswith("client_") if role == "client"
                                  else stage.startswith("server_")),
                    "query stage logged by wrong process role")
            mono, wall = entry.get("__MONOTONIC_TIMESTAMP"), entry.get("__REALTIME_TIMESTAMP")
            require(entry.get("_PID") == str(row["pid"])
                    and boot_id(entry.get("_BOOT_ID")) == expected_boot,
                    "query stage PID or boot differs")
            require(isinstance(mono, str) and mono.isdecimal() and int(mono) > 0
                    and isinstance(wall, str) and wall.isdecimal() and int(wall) > 0,
                    "query stage raw time absent")
            emitted_ns = event_wall_ns(prefix)
            event = {"stage": stage, "query_id": query_id, "message": message,
                     "source_event_wall_ns": emitted_ns,
                     "source_file": prefix[3],
                     "journal_lag_ns": int(wall) * 1000 - emitted_ns,
                     "journal_mono_us": int(mono), "journal_wall_us": int(wall),
                     "pid": row["pid"], "endpoint": endpoint, "role": role,
                     "log_name": log_name, "log_path": str(Path(row["path"]).resolve()),
                     "line_number": line_number,
                     "message_b64": base64.b64encode(original_message).decode(),
                     "message_sha256": sha(original_message),
                     "raw_b64": base64.b64encode(raw).decode(),
                     "raw_sha256": sha(raw), "log_sha256": row["sha256"]}
            (excluded if unrelated else result).append(event)
    return result, excluded


def validate_attempts(manifest: dict) -> dict[str, dict]:
    attempts = manifest.get("attempts")
    require(isinstance(attempts, list) and attempts, "query attempts absent")
    by_id = {}
    by_logical: dict[str, list[dict]] = {}
    for attempt in attempts:
        query_id = attempt.get("query_id")
        require(isinstance(query_id, str) and HEX64.fullmatch(query_id) is not None
                and int(query_id, 16) != 0, "query ID is not nonzero 64-hex")
        query_id = query_id.upper()
        require(query_id not in by_id, "query ID reused across attempts")
        require(isinstance(attempt.get("logical_request"), str) and attempt["logical_request"]
                and isinstance(attempt.get("operation"), str) and attempt["operation"]
                and type(attempt.get("attempt")) is int and attempt["attempt"] >= 0,
                "logical request, operation or attempt absent")
        require(attempt.get("server") in manifest["server_logs"], "attempt server absent")
        by_id[query_id] = attempt
        by_logical.setdefault(attempt["logical_request"], []).append(attempt)
    for logical, group in by_logical.items():
        ordered = sorted(group, key=lambda item: item["attempt"])
        require([row["attempt"] for row in ordered] == list(range(len(ordered))),
                f"{logical} attempt sequence has a gap")
        require(len({row["operation"] for row in ordered}) == 1,
                f"{logical} retry changed operation")
        for index, row in enumerate(ordered):
            expected = ordered[index - 1]["query_id"].upper() if index else None
            require(row.get("retry_of") == expected,
                    f"{logical} retry predecessor differs")
    return by_id


def actor_sequence(rows: list[dict], expected: tuple[str, ...]) -> dict:
    # Never sort by wall time to manufacture an execution sequence.
    if not rows:
        return {"status": "unproven", "source_wall_consistent": False}
    files = {(row["pid"], row["log_path"], row["log_sha256"]) for row in rows}
    if len(files) != 1:
        return {"status": "unproven", "source_wall_consistent": False}
    ordered = sorted(rows, key=lambda row: row["line_number"])
    require(tuple(row["stage"] for row in ordered) == expected,
            "actor raw stage order differs")
    times = [row["source_event_wall_ns"] for row in ordered]
    return {"status": "raw_file_order_observed", "source_wall_consistent": times == sorted(times),
            "raw_line_numbers": [row["line_number"] for row in ordered]}


def classify_attempt(attempt: dict, rows: list[dict], manifest: dict) -> dict:
    stages: dict[str, dict] = {}
    for row in rows:
        require(row["stage"] not in stages, "duplicate query stage")
        stages[row["stage"]] = row
        if row["role"] == "server":
            require(row["log_name"] == attempt["server"]
                    and row["endpoint"] == manifest["server_logs"][attempt["server"]]["endpoint"],
                    "server endpoint or process differs")
    create = stages.get("client_create")
    require(create is not None, "client create absent")
    require(key_value(create["message"], "server") ==
            manifest["server_logs"][attempt["server"]]["endpoint"],
            "client target endpoint differs")
    require(key_value(create["message"], "function_id") == attempt["operation"],
            "query operation differs")
    if "client_transmit" in stages:
        require(key_value(stages["client_transmit"]["message"], "server") ==
                manifest["server_logs"][attempt["server"]]["endpoint"],
                "client transmit target differs")
    if "server_ingress" in stages:
        peer = key_value(stages["server_ingress"]["message"], "peer")
        try:
            observed_peer_ip = str(ipaddress.ip_address(peer))
        except (ValueError, TypeError) as error:
            raise ValueError("server ingress peer is not a host IP") from error
        require(observed_peer_ip == manifest["client_peer_ip"],
                "server ingress peer IP differs from client peer IP")
    if "client_refuse" in stages:
        refuse = stages["client_refuse"]
        require(set(stages) == {"client_create", "client_refuse"}
                and key_value(create["message"], "connection_present") == "false"
                and key_value(refuse["message"], "reason") == "no-live-connection"
                and key_value(refuse["message"], "pending_queries") == "0",
                "no-connection fail-fast was not isolated before send")
        status = "client_no_connection_fail_fast"
        sequences = {"client": actor_sequence(rows, ("client_create", "client_refuse"))}
    else:
        success = all(stage in stages for stage in STAGES)
        if success:
            sequences = {
                "client": actor_sequence([row for row in rows if row["role"] == "client"],
                                         ("client_create", "client_transmit", "client_answer", "client_complete")),
                "server": actor_sequence([row for row in rows if row["role"] == "server"],
                                         ("server_ingress", "server_completion", "server_answer_enqueue"))}
            require(key_value(stages["server_ingress"]["message"], "admission") == "accepted"
                    and key_value(stages["server_completion"]["message"], "outcome") == "success"
                    and key_value(stages["server_completion"]["message"], "response_ready") == "true"
                    and key_value(stages["server_answer_enqueue"]["message"], "enqueued") == "true"
                    and key_value(stages["client_complete"]["message"], "outcome") == "answer"
                    and "client_timeout" not in stages,
                    "query stages do not show successful answer")
            status = "transport_answered"
        else:
            sequences = {}
            status = "unproven_answer" if ("client_answer" in stages or
                                           "client_complete" in stages) else "incomplete_query"
    return {"classification": status, "transport_answer": status == "transport_answered",
            "application_result": "unproven; payload semantics not decoded",
            "application_success_proven": False, "query_id": attempt["query_id"].upper(),
            "logical_request": attempt["logical_request"], "attempt": attempt["attempt"],
            "retry_of": attempt.get("retry_of"), "operation": attempt["operation"],
            "server": attempt["server"], "actor_sequences": sequences,
            "source_sequence_consistent": bool(sequences) and all(
                row["source_wall_consistent"] for row in sequences.values()),
            "events": rows,
            "cross_process_source_wall_order_observed": all(stage in stages for stage in STAGES)
                and [stages[stage]["source_event_wall_ns"] for stage in STAGES] ==
                sorted(stages[stage]["source_event_wall_ns"] for stage in STAGES)}


def verify(manifest: dict) -> dict:
    require(manifest.get("schema") == "tos.q01.query-evidence.v1", "wrong Q01 schema")
    source_identity(manifest)
    require(set(manifest["binaries"]) == {"client", *manifest["server_logs"]},
            "client/server binary manifest incomplete")
    for row in manifest["binaries"].values():
        source_or_binary(row)
    expected_boot = boot_id(manifest.get("boot_id"))
    try:
        client_peer_ip = str(ipaddress.ip_address(manifest.get("client_peer_ip")))
    except (ValueError, TypeError) as error:
        raise ValueError("client peer IP is absent or malformed") from error
    require(client_peer_ip == manifest["client_peer_ip"]
            and socket_host(manifest["client_log"].get("endpoint")) == client_peer_ip,
            "client peer IP differs from local socket host")
    by_id = validate_attempts(manifest)
    all_events, excluded = raw_events(manifest["client_log"], "client", "client",
                                      expected_boot, set(by_id))
    for name, row in manifest["server_logs"].items():
        events, ignored = raw_events(row, "server", name, expected_boot, set(by_id))
        all_events.extend(events)
        excluded.extend(ignored)
    grouped: dict[str, list[dict]] = {query_id: [] for query_id in by_id}
    for row in all_events:
        require(row["query_id"] in grouped, "unmapped query ID in raw logs")
        grouped[row["query_id"]].append(row)
    queries = {query_id: classify_attempt(by_id[query_id], rows, manifest)
               for query_id, rows in grouped.items()}
    for attempt in by_id.values():
        predecessor = attempt.get("retry_of")
        if predecessor is None:
            continue
        prior = queries[predecessor]
        current = queries[attempt["query_id"].upper()]
        terminal = next((row for row in prior["events"] if row["stage"] in
                         ("client_refuse", "client_complete", "client_timeout")), None)
        create = next((row for row in current["events"] if row["stage"] == "client_create"), None)
        require(terminal is not None and create is not None, "retry client terminal/create absent")
        same_file = all(terminal[key] == create[key] for key in ("pid", "log_path", "log_sha256"))
        if same_file:
            require(terminal["line_number"] < create["line_number"], "retry client raw order differs")
        current["retry_source_sequence_consistent"] = same_file and (
            terminal["source_event_wall_ns"] <= create["source_event_wall_ns"])
    process_sequences = []
    process_files: dict[tuple[int, str, str], list[dict]] = {}
    for row in all_events:
        process_files.setdefault((row["pid"], row["log_path"], row["log_sha256"]), []).append(row)
    for (pid, path, digest), rows in process_files.items():
        raw_order = sorted(rows, key=lambda row: row["line_number"])
        regressions = [{"previous_line": before["line_number"], "line": after["line_number"]}
                       for before, after in zip(raw_order, raw_order[1:])
                       if after["source_event_wall_ns"] < before["source_event_wall_ns"]]
        process_sequences.append({"pid": pid, "log_path": path, "log_sha256": digest,
                                  "source_wall_regressions": regressions})
    attribution = any(row["classification"] == "transport_answered" for row in queries.values()) and all(
        row["classification"] in ("transport_answered", "client_no_connection_fail_fast") for row in queries.values())
    return {"schema": "tos.q01.trace-attribution-result.v2", "evidence_scope": "trace-attribution",
            "passed": False, "legacy_interface": "unsupported; explicitly consume v2 scope",
            "trace_attribution_passed": attribution,
            "process_file_sequences": process_sequences,
            "source_sequence_consistent": not any(row["source_wall_regressions"] for row in process_sequences)
                and all(row["source_sequence_consistent"] and
                row.get("retry_source_sequence_consistent", True) for row in queries.values()),
            "q01_signoff": False, "cross_process_time_proven": False,
            "deadline_proven": False, "socket_flush_proven": False, "finite_error_bound": None,
            "scope": "Q01 one-host raw query-attempt attribution only",
            "source_commit": manifest["source_commit"],
            "checker_sha256": file_sha(Path(__file__)),
            "event_clock": "td source system_clock UTC ns; journal event-loop metadata us; no causal bound",
            "min_journal_metadata_minus_source_ns": min(row["journal_lag_ns"] for row in all_events + excluded),
            "max_journal_metadata_minus_source_ns": max(row["journal_lag_ns"] for row in all_events + excluded),
            "excluded_server_client_event_counts": {
                name: {stage: sum(row["log_name"] == name and row["stage"] == stage
                                  for row in excluded)
                       for stage in ("client_complete", "client_timeout")}
                for name in manifest["server_logs"]},
            "excluded_server_client_events": excluded, "queries": queries}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-scope", required=True, choices=("trace-attribution",))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    raw = args.manifest.read_bytes()
    require(sha(raw) == args.manifest_sha256, "frozen manifest SHA differs")
    result = verify(json.loads(raw))
    print(json.dumps(result, sort_keys=True, indent=2))
    require(result["trace_attribution_passed"], "Q01 query attribution incomplete")


if __name__ == "__main__":
    main()
