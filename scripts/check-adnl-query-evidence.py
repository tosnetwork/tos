#!/usr/bin/env python3
"""Check one-host ADNL query attempts against raw journald records and fixed provenance."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import re
import subprocess
from pathlib import Path

ID = re.compile(r"ADNL_EXT_QUERY ([a-z_]+) id=([0-9a-fA-F]{64})(?:\s|$)")
HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
BOOT = re.compile(r"[0-9a-fA-F]{32}\Z")
STAGES = ("client_create", "client_transmit", "server_ingress", "server_completion",
          "server_answer_enqueue", "client_answer", "client_complete")
SOURCE_FILES = ("adnl/adnl-ext-client.hpp", "adnl/adnl-ext-client.cpp",
                "adnl/adnl-ext-server.cpp", "adnl/adnl-ext-connection.cpp",
                "adnl/adnl-ext-connection.hpp", "adnl/adnl-query.cpp",
                "scripts/analyze-adnl-query-id-trace.py",
                "scripts/check-adnl-query-evidence.py")


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


def source_or_binary(row: dict) -> None:
    path = Path(row["path"])
    require(HEX64.fullmatch(row.get("sha256", "")) is not None
            and sha(path.read_bytes()) == row["sha256"].lower(),
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


def raw_events(row: dict, role: str, log_name: str, expected_boot: str) -> list[dict]:
    source_or_binary(row)
    require(type(row.get("pid")) is int and row["pid"] > 0, "log PID absent")
    require(boot_id(row.get("boot_id")) == expected_boot, "log boot differs")
    endpoint = row.get("endpoint")
    require(isinstance(endpoint, str) and endpoint, "log endpoint absent")
    result = []
    for raw in Path(row["path"]).read_bytes().splitlines(keepends=True):
        try:
            entry = json.loads(raw)
        except (ValueError, TypeError) as error:
            raise ValueError("raw journal JSON malformed") from error
        message = entry.get("MESSAGE")
        if not isinstance(message, str):
            continue
        match = ID.search(message)
        if not match:
            continue
        stage, query_id = match.group(1), match.group(2).upper()
        require(stage in STAGES or stage in ("client_refuse", "client_timeout"),
                f"unknown query stage {stage}")
        require((stage.startswith("client_") if role == "client" else stage.startswith("server_")),
                "query stage logged by wrong process role")
        mono, wall = entry.get("__MONOTONIC_TIMESTAMP"), entry.get("__REALTIME_TIMESTAMP")
        require(entry.get("_PID") == str(row["pid"])
                and boot_id(entry.get("_BOOT_ID")) == expected_boot,
                "query stage PID or boot differs")
        require(isinstance(mono, str) and mono.isdecimal() and int(mono) > 0
                and isinstance(wall, str) and wall.isdecimal() and int(wall) > 0,
                "query stage raw time absent")
        result.append({"stage": stage, "query_id": query_id, "message": message,
                       "mono_us": int(mono), "wall_us": int(wall), "pid": row["pid"],
                       "endpoint": endpoint, "role": role, "log_name": log_name,
                       "raw_b64": base64.b64encode(raw).decode(),
                       "raw_sha256": sha(raw), "log_sha256": row["sha256"]})
    return result


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
                and key_value(refuse["message"], "pending_queries") == "0"
                and create["mono_us"] <= refuse["mono_us"],
                "no-connection fail-fast was not isolated before send")
        status = "client_no_connection_fail_fast"
    else:
        success = all(stage in stages for stage in STAGES)
        if success:
            ordered = [stages[stage] for stage in STAGES]
            require([row["mono_us"] for row in ordered] == sorted(row["mono_us"] for row in ordered),
                    "query five-point order differs")
            require(key_value(stages["server_ingress"]["message"], "admission") == "accepted"
                    and key_value(stages["server_completion"]["message"], "outcome") == "success"
                    and key_value(stages["server_completion"]["message"], "response_ready") == "true"
                    and key_value(stages["server_answer_enqueue"]["message"], "enqueued") == "true"
                    and key_value(stages["client_complete"]["message"], "outcome") == "answer"
                    and "client_timeout" not in stages,
                    "query stages do not show successful answer")
            status = "answered"
        else:
            status = "unproven_answer" if ("client_answer" in stages or
                                           "client_complete" in stages) else "incomplete_query"
    return {"classification": status, "query_id": attempt["query_id"].upper(),
            "logical_request": attempt["logical_request"], "attempt": attempt["attempt"],
            "retry_of": attempt.get("retry_of"), "operation": attempt["operation"],
            "server": attempt["server"], "events": sorted(rows, key=lambda row: row["mono_us"])}


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
    all_events = raw_events(manifest["client_log"], "client", "client", expected_boot)
    for name, row in manifest["server_logs"].items():
        all_events.extend(raw_events(row, "server", name, expected_boot))
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
        require(prior["events"] and current["events"]
                and prior["events"][-1]["mono_us"] <= current["events"][0]["mono_us"],
                "retry began before previous attempt ended")
    return {"passed": any(row["classification"] == "answered" for row in queries.values())
            and all(row["classification"] in
                    ("answered", "client_no_connection_fail_fast")
                    for row in queries.values()),
            "scope": "Q01 one-host raw query-attempt attribution",
            "source_commit": manifest["source_commit"], "queries": queries}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    raw = args.manifest.read_bytes()
    require(sha(raw) == args.manifest_sha256, "frozen manifest SHA differs")
    result = verify(json.loads(raw))
    print(json.dumps(result, sort_keys=True, indent=2))
    require(result["passed"], "Q01 query attribution incomplete")


if __name__ == "__main__":
    main()
