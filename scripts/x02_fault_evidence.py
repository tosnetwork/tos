#!/usr/bin/env python3
"""Read-only X02 raw capture and fail-closed offline evidence checker.

The capture command never installs a fault. PQ must freeze the policy bytes and
their SHA-256 before injecting one, then capture baseline, fault, and recovery
snapshots. The checker is deliberately narrower than a network acceptance run.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

HEX = re.compile(r"[0-9a-fA-F]{64}\Z")
MARKER = re.compile(
    r"BlockFinalizedInMasterchain.*?\{block=\(-1,8000000000000000,(\d+)\):"
    r"([0-9A-Fa-f]{64}):([0-9A-Fa-f]{64})\}"
)
SHARD = "8000000000000000"
PHASES = ("baseline", "three_of_four", "two_of_four", "recovery")
SOURCE_FILES = ("scripts/x02_fault_evidence.py", "scripts/validator-election-stage-a.py")
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
BOOT_ID_COMPACT = re.compile(r"[0-9a-f]{32}\Z")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot_digest(snapshot: dict) -> str:
    return digest((json.dumps(snapshot, sort_keys=True, indent=2) + "\n").encode())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalize_boot_id(value: object) -> str:
    require(isinstance(value, str), "host boot identity is absent")
    compact = value.lower().replace("-", "")
    require((BOOT_ID.fullmatch(value.lower()) is not None
             or BOOT_ID_COMPACT.fullmatch(value.lower()) is not None)
            and BOOT_ID_COMPACT.fullmatch(compact) is not None
            and int(compact, 16) != 0, "host boot identity is malformed")
    return compact


def positive(value: object, name: str) -> int | float:
    require(type(value) in (int, float) and value > 0, f"{name} must be positive")
    return value


def hex64(value: object, name: str) -> str:
    require(isinstance(value, str) and HEX.fullmatch(value) is not None
            and int(value, 16) != 0, f"{name} must be a nonzero 256-bit hex value")
    return value.lower()


def hash_value(value: object, name: str) -> str:
    require(isinstance(value, str), f"{name} is absent")
    if HEX.fullmatch(value):
        return hex64(value, name)
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ValueError(f"{name} is neither hex nor base64") from error
    require(len(raw) == 32 and any(raw), f"{name} is zero or malformed")
    return raw.hex()


def full_id(raw: dict, name: str) -> tuple[int, str, int, str, str]:
    require(isinstance(raw, dict), f"{name} has no BlockIdExt")
    try:
        wc, shard, seq = raw["workchain"], raw["shard"], raw["seqno"]
        root, file_hash = raw["root_hash"], raw["file_hash"]
    except KeyError as error:
        raise ValueError(f"{name} has incomplete BlockIdExt") from error
    require(type(wc) is int and wc == -1 and type(seq) is int and seq >= 0,
            f"{name} has wrong masterchain height")
    require(str(shard).lower() == SHARD.lower(), f"{name} has wrong shard")
    return wc, SHARD, seq, hash_value(root, f"{name} root"), hash_value(file_hash, f"{name} file")


def validate_policy(policy: dict) -> None:
    require(policy.get("schema") == "tos.x02.fault-policy.v1", "wrong policy schema")
    require(isinstance(policy.get("source_commit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", policy["source_commit"]) is not None,
            "missing fixed source commit")
    require(set(policy.get("source_files") or {}) == set(SOURCE_FILES),
            "fixed recorder and Stage A source hashes are absent")
    for name in SOURCE_FILES:
        hex64(policy["source_files"][name], f"{name} source SHA")
    hex64(policy.get("binary_sha256"), "binary SHA")
    zero = policy.get("zerostate") or {}
    hex64(zero.get("root_hash"), "zerostate root")
    hex64(zero.get("file_hash"), "zerostate file")
    try:
        manifest_raw = base64.b64decode(policy["readiness_manifest_b64"], validate=True)
        manifest = json.loads(manifest_raw)
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError("raw Stage A readiness manifest is absent") from error
    require(digest(manifest_raw) == policy.get("readiness_manifest_sha256"),
            "Stage A readiness manifest SHA differs")
    require(manifest.get("schema") == "tos.validator-election-experiment-readiness.v1"
            and manifest.get("status") == "ready"
            and (manifest.get("provenance") or {}).get("source_commit") == policy["source_commit"],
            "Stage A readiness provenance differs")
    manifest_zero = ((manifest.get("network") or {}).get("zero_state") or {}).get("masterchain") or {}
    require(manifest_zero.get("root_hash_hex", "").lower() == zero["root_hash"].lower()
            and manifest_zero.get("file_hash_hex", "").lower() == zero["file_hash"].lower(),
            "Stage A readiness zerostate differs")
    manifest_nodes = {item.get("node_name"): item for item in manifest.get("validators", [])
                      if isinstance(item, dict)}
    nodes = policy.get("nodes")
    require(isinstance(nodes, list) and len(nodes) == 4, "policy requires four nodes")
    names, pids, rpc_urls, endpoints = set(), set(), set(), set()
    for node in nodes:
        require(isinstance(node, dict), "malformed node")
        name, pid = node.get("name"), node.get("pid")
        require(isinstance(name, str) and name and name not in names,
                "duplicate or missing node name")
        require(type(pid) is int and pid > 0 and pid not in pids, "duplicate or missing PID")
        positive(node.get("pid_start_ticks"), f"{name} PID start ticks")
        require(isinstance(node.get("service"), str) and node["service"], "missing service")
        require(isinstance(node.get("data_dir"), str) and node["data_dir"], "missing data dir")
        require(isinstance(node.get("rpc_url"), str)
                and node["rpc_url"].startswith("http://127.0.0.1:")
                and node["rpc_url"] not in rpc_urls, "RPC must have a unique loopback endpoint")
        ipaddress.ip_address(node["peer_ip"])
        require(type(node.get("peer_port")) is int and 1 <= node["peer_port"] <= 65535,
                "missing peer port")
        require((node["peer_ip"], node["peer_port"]) not in endpoints,
                "duplicate peer endpoint")
        for field in ("consensus_key_id", "adnl_id", "exe_sha256"):
            hex64(node.get(field), f"{name} {field}")
        require(node["exe_sha256"].lower() == policy["binary_sha256"].lower(),
                "node executable differs from frozen binary SHA")
        manifest_node = manifest_nodes.get(name) or {}
        peer = manifest_node.get("peer_transport") or {}
        require(manifest_node.get("consensus_key_id_hex", "").lower()
                == node["consensus_key_id"].lower()
                and manifest_node.get("adnl_id_hex", "").lower() == node["adnl_id"].lower()
                and manifest_node.get("rpc_url") == node["rpc_url"]
                and manifest_node.get("node_data_dir") == node["data_dir"]
                and manifest_node.get("process_id") == node["pid"]
                and peer == {"protocol": "udp", "ip": node["peer_ip"],
                             "port": node["peer_port"]},
                f"{name} peer tuple or identity differs from Stage A readiness")
        names.add(name); pids.add(pid); rpc_urls.add(node["rpc_url"])
        endpoints.add((node["peer_ip"], node["peer_port"]))
    require(len({node["adnl_id"].lower() for node in nodes}) == 4,
            "ADNL identities are not distinct")
    rpc_ports = {urllib.parse.urlparse(node["rpc_url"]).port for node in nodes}
    require(not ({node["peer_port"] for node in nodes} & rpc_ports),
            "validator peer transport overlaps RPC control port")
    require(len(manifest_nodes) == 4 and set(manifest_nodes) == names,
            "Stage A readiness does not bind four nodes")
    thresholds = policy.get("thresholds") or {}
    for field in ("min_rule_packets", "min_rule_drops", "three_min_delta",
                  "three_max_seconds", "halt_min_seconds", "halt_tail_min_seconds",
                  "halt_tail_samples", "recovery_min_delta", "recovery_max_seconds"):
        positive(thresholds.get(field), field)
    require(type(thresholds["halt_tail_samples"]) is int,
            "halt_tail_samples must be an integer")
    require(thresholds["min_rule_packets"] == 1
            and thresholds["min_rule_drops"] == 1
            and thresholds["three_min_delta"] == 2
            and thresholds["three_max_seconds"] == 120
            and thresholds["halt_min_seconds"] == 60
            and thresholds["recovery_min_delta"] == 2
            and thresholds["recovery_max_seconds"] == 180,
            "isolation thresholds differ from the frozen X02 slice")
    live = policy.get("live_nodes") or {}
    require(set(live.get("three_of_four", [])) <= names
            and len(set(live.get("three_of_four", []))) == 3,
            "3/4 live identities are invalid")
    require(set(live.get("two_of_four", [])) <= names
            and len(set(live.get("two_of_four", []))) == 2,
            "2/4 live identities are invalid")
    require(names == {"node1", "node2", "node3", "node4"}
            and set(live["three_of_four"]) == {"node1", "node2", "node3"}
            and set(live["two_of_four"]) == {"node1", "node2"},
            "frozen X02 slice must isolate node4 before node3")
    rules = policy.get("rules")
    require(isinstance(rules, list) and rules, "no target peer rules")
    clsact = policy.get("clsact") or {}
    require(clsact.get("interface") == "lo"
            and clsact.get("setup_argv") == ["tc", "qdisc", "add", "dev", "lo", "clsact"]
            and clsact.get("cleanup_argv") == ["tc", "qdisc", "del", "dev", "lo", "clsact"],
            "precommitted clsact setup/cleanup is absent")
    seen = set()
    by_name = {node["name"]: node for node in nodes}
    for rule in rules:
        require(isinstance(rule, dict) and rule.get("id") not in seen,
                "duplicate fault rule")
        seen.add(rule["id"])
        require(rule.get("phase") in ("three_of_four", "two_of_four"),
                "fault rule has invalid phase")
        require(rule.get("src_node") in names and rule.get("dst_node") in names
                and rule["src_node"] != rule["dst_node"], "fault rule has invalid peer pair")
        require(rule.get("mode") == "drop_all", "first X02 slice requires exact 100% drop")
        require(isinstance(rule.get("interface"), str)
                and re.fullmatch(r"[A-Za-z0-9_.:-]+", rule["interface"]) is not None,
                "invalid fault interface")
        require(rule["interface"] == clsact["interface"],
                "fault rule is not on the precommitted clsact interface")
        require(type(rule.get("pref")) is int and rule["pref"] > 0
                and isinstance(rule.get("handle"), str) and rule["handle"],
                "rule preference or handle absent")
        for action in ("install", "remove"):
            argv = rule.get(action + "_argv")
            require(isinstance(argv, list) and len(argv) >= 5
                    and Path(argv[0]).name == "tc" and argv[1] == "filter"
                    and argv[2] == ("add" if action == "install" else "del")
                    and "dev" in argv and argv[argv.index("dev") + 1] == rule["interface"]
                    and "pref" in argv and str(rule["pref"]) in argv
                    and "handle" in argv and rule["handle"] in argv,
                    f"{action} command is absent or not bound to the rule")
            if action == "install":
                for key, value in (("ip_proto", "udp"),
                                   ("src_ip", by_name[rule["src_node"]]["peer_ip"]),
                                   ("dst_ip", by_name[rule["dst_node"]]["peer_ip"]),
                                   ("src_port", str(by_name[rule["src_node"]]["peer_port"])),
                                   ("dst_port", str(by_name[rule["dst_node"]]["peer_port"]))):
                    require(key in argv and argv[argv.index(key) + 1] == value,
                            f"install command lacks exact {key}")
                require("flower" in argv and argv[-2:] == ["action", "drop"],
                        "install command is not an exact flower drop")
    require(any(rule["phase"] == "three_of_four" for rule in rules)
            and any(rule["phase"] == "two_of_four" for rule in rules),
            "isolation rule phases are absent")
    require(len({rule["id"] for rule in rules}) == len(rules), "duplicate rule ID")
    require(len({(rule["interface"], rule["pref"], rule["handle"]) for rule in rules})
            == len(rules), "duplicate tc rule identity")
    expected_three = {(a, b) for a in ("node1", "node2", "node3")
                      for b in ("node4",)} | {
        ("node4", a) for a in ("node1", "node2", "node3")}
    expected_two_new = {(a, "node3") for a in ("node1", "node2")} | {
        ("node3", a) for a in ("node1", "node2")}
    for phase, expected in (("three_of_four", expected_three),
                            ("two_of_four", expected_two_new)):
        pairs = [(r["src_node"], r["dst_node"]) for r in rules if r["phase"] == phase]
        require(len(pairs) == len(expected) and set(pairs) == expected,
                f"{phase} peer pair set has a missing, duplicate or extra edge")


def read_policy(path: Path, expected_sha: str) -> dict:
    data = path.read_bytes()
    require(digest(data) == expected_sha, "policy bytes differ from precommitted SHA")
    policy = json.loads(data)
    validate_policy(policy)
    return policy


def run_raw(argv: list[str]) -> dict:
    started = time.monotonic_ns()
    result = subprocess.run(argv, capture_output=True, check=False)
    completed = time.monotonic_ns()
    return {"argv": argv, "started_ns": started, "completed_ns": completed,
            "exit": result.returncode, "stdout_b64": base64.b64encode(result.stdout).decode(),
            "stderr_b64": base64.b64encode(result.stderr).decode(),
            "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr)}


def capture_tc(policy: dict) -> dict:
    interfaces = sorted({rule["interface"] for rule in policy["rules"]})
    return {iface: {"filters": run_raw(["tc", "-j", "-s", "filter", "show", "dev", iface, "egress"]),
                    "qdiscs": run_raw(["tc", "-j", "-s", "qdisc", "show", "dev", iface])}
            for iface in interfaces}


def fault_event(policy: dict, policy_sha: str, rule_id: str, action: str) -> dict:
    """Execute only one precommitted tc argv, retaining raw command and post-state."""
    source = require_source_commit(policy)
    if rule_id == "clsact":
        require(action in ("setup", "cleanup"), "unknown clsact action")
        argv = policy["clsact"][action + "_argv"]
    else:
        require(action in ("install", "remove"), "unknown fault action")
        matches = [rule for rule in policy["rules"] if rule["id"] == rule_id]
        require(len(matches) == 1, "unknown fault rule")
        argv = matches[0][action + "_argv"]
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    pre_tc = capture_tc(policy)
    command = run_raw(argv)
    post_tc = capture_tc(policy)
    require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == boot_id,
            "host rebooted during fault event")
    return {"schema": "tos.x02.tc-event.v1", "policy_sha256": policy_sha,
            "rule_id": rule_id, "action": action, "command": command,
            "boot_id": boot_id,
            "source": source, "pre_tc": pre_tc, "post_tc": post_tc}


def require_source_commit(policy: dict) -> dict:
    repo = Path(__file__).resolve().parents[1]
    source = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True)
    require(source.stdout.strip() == policy["source_commit"],
            "running source commit differs from precommitted policy")
    status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain",
                             "--untracked-files=no"], capture_output=True, check=True)
    require(status.stdout == b"", "tracked source tree has uncommitted changes")
    files = {}
    for name in SOURCE_FILES:
        tracked = subprocess.run(["git", "-C", str(repo), "ls-files", "--error-unmatch", name],
                                 capture_output=True, check=False)
        require(tracked.returncode == 0, f"{name} is not tracked by fixed commit")
        frozen = subprocess.run(["git", "-C", str(repo), "show", f"HEAD:{name}"],
                                capture_output=True, check=True).stdout
        current = (repo / name).read_bytes()
        require(current == frozen, f"{name} bytes differ from fixed commit")
        files[name] = digest(current)
        require(files[name] == policy["source_files"][name],
                f"{name} SHA differs from precommitted policy")
    return {"commit": source.stdout.strip(), "tracked_status_b64": "",
            "files_sha256": files}


def capture_process(node: dict) -> dict:
    pid = node["pid"]
    proc = Path(f"/proc/{pid}")
    stat = (proc / "stat").read_bytes()
    exe = (proc / "exe").resolve(strict=True)
    cwd = (proc / "cwd").resolve(strict=True)
    cmdline = (proc / "cmdline").read_bytes()
    data_dir = Path(node["data_dir"]).resolve(strict=True)
    fd_sockets = set()
    for fd in (proc / "fd").iterdir():
        try:
            match = re.fullmatch(r"socket:\[(\d+)\]", os.readlink(fd))
        except OSError:
            continue
        if match:
            fd_sockets.add(int(match.group(1)))
    udp = Path("/proc/net/udp").read_text()
    return {"pid": pid, "stat_b64": base64.b64encode(stat).decode(),
            "stat_sha256": digest(stat), "exe_path": str(exe),
            "exe_sha256": digest(exe.read_bytes()), "data_dir": str(data_dir),
            "cwd": str(cwd), "cmdline_b64": base64.b64encode(cmdline).decode(),
            "cmdline_sha256": digest(cmdline),
            "socket_inodes": sorted(fd_sockets), "udp_table_b64": base64.b64encode(udp.encode()).decode(),
            "udp_table_sha256": digest(udp.encode())}


def rpc(url: str, method: str, params: dict | None, query_id: int) -> dict:
    request = json.dumps({"jsonrpc": "2.0", "id": query_id, "method": method,
                          "params": params or {}}, separators=(",", ":")).encode()
    started = time.monotonic_ns()
    try:
        req = urllib.request.Request(url, data=request,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as response:
            raw = response.read()
            status = response.status
        error = None
    except Exception as exc:
        raw, status, error = b"", 0, repr(exc)
    completed = time.monotonic_ns()
    return {"url": url, "method": method, "started_ns": started,
            "completed_ns": completed, "request_b64": base64.b64encode(request).decode(),
            "response_b64": base64.b64encode(raw).decode(), "response_sha256": digest(raw),
            "http_status": status, "error": error}


def parse_rpc(row: dict, node: dict, method: str, *,
              expected_init: dict | None = None,
              expected_seq: int | None = None) -> tuple[int, str, int, str, str]:
    require(row.get("url") == node["rpc_url"] and row.get("method") == method,
            "RPC endpoint or method differs")
    require(row.get("http_status") == 200 and row.get("error") is None,
            "RPC failed or HTTP status is not 200")
    try:
        request = json.loads(base64.b64decode(row["request_b64"], validate=True))
        raw = base64.b64decode(row["response_b64"], validate=True)
        response = json.loads(raw)
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError("raw RPC request/response is malformed") from error
    require(digest(raw) == row.get("response_sha256"), "RPC response SHA differs")
    require(request.get("method") == method and response.get("id") == request.get("id")
            and response.get("error") is None, "RPC request/response ID or result differs")
    result = response.get("result") or {}
    if method == "getMasterchainInfo" and expected_init is not None:
        init = full_id(result.get("init"), f"{node['name']} zerostate")
        require(init[2] == 0 and init[3] == expected_init["root_hash"].lower()
                and init[4] == expected_init["file_hash"].lower(),
                "RPC endpoint zerostate differs from frozen policy")
    if method == "getBlockHeader" and expected_seq is not None:
        params = request.get("params") or {}
        require(params.get("workchain") == -1 and params.get("shard") == SHARD
                and params.get("seqno") == expected_seq,
                "raw header request is for the wrong height")
    value = result.get("last") if method == "getMasterchainInfo" else result.get("id")
    return full_id(value, f"{node['name']} {method}")


def capture(policy: dict, policy_sha: str, phase: str,
            anchor: dict | None = None, previous: dict | None = None) -> dict:
    require(phase in PHASES, "unknown phase")
    if phase in ("three_of_four", "recovery"):
        expected_phase = "baseline" if phase == "three_of_four" else "two_of_four"
        require(isinstance(anchor, dict) and anchor.get("phase") == expected_phase
                and anchor.get("policy_sha256") == policy_sha
                and type(anchor.get("common_seqno")) is int,
                f"{phase} requires a raw {expected_phase} anchor")
    else:
        require(anchor is None, f"{phase} must not select an anchor")
    source = require_source_commit(policy)
    started = time.monotonic_ns()
    tc = capture_tc(policy)
    processes = {}
    for node in policy["nodes"]:
        try:
            processes[node["name"]] = capture_process(node)
        except (OSError, ValueError) as error:
            processes[node["name"]] = {"error": repr(error), "pid": node["pid"]}
    journals = {}
    for node in policy["nodes"]:
        prior = ((previous or {}).get("journals") or {}).get(node["name"])
        prior_cursor = journal_end_cursor(prior, node) if prior is not None else None
        require(previous is None or prior_cursor is not None,
                "previous journal cursor is absent")
        argv = ["journalctl", "-u", node["service"], "--no-pager", "-o", "json"]
        if prior_cursor is not None:
            argv += ["--cursor", prior_cursor]
        journals[node["name"]] = run_raw(argv)
    first = {node["name"]: rpc(node["rpc_url"], "getMasterchainInfo", None, i * 3 + 1)
             for i, node in enumerate(policy["nodes"])}
    result = {"schema": "tos.x02.raw-snapshot.v1", "policy_sha256": policy_sha,
            "source_commit": policy["source_commit"],
            "source": source,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "phase": phase, "started_ns": started, "completed_ns": time.monotonic_ns(),
            "tc": tc, "processes": processes, "journals": journals,
            "anchor_sha256": snapshot_digest(anchor) if anchor is not None else None,
            "previous_sha256": snapshot_digest(previous) if previous is not None else None,
            "anchor_common_seqno": anchor["common_seqno"] if anchor is not None else None,
            "rpc": {"first": first, "headers": {}, "previous_headers": {},
                    "range_headers": {}, "last": {}}}
    try:
        first_ids = {node["name"]: parse_rpc(first[node["name"]], node, "getMasterchainInfo")
                     for node in policy["nodes"]}
        live = (set(policy["live_nodes"][phase]) if phase in policy["live_nodes"]
                else {node["name"] for node in policy["nodes"]})
        common = min(first_ids[name][2] for name in live)
        result["common_seqno"] = common
        params = {"workchain": -1, "shard": SHARD, "seqno": common}
        result["rpc"]["headers"] = {
            node["name"]: rpc(node["rpc_url"], "getBlockHeader", params, i * 4 + 2)
            for i, node in enumerate(policy["nodes"]) if node["name"] in live}
        previous_params = {**params, "seqno": max(0, common - 1)}
        result["rpc"]["previous_headers"] = {
            node["name"]: rpc(node["rpc_url"], "getBlockHeader", previous_params, i * 4 + 3)
            for i, node in enumerate(policy["nodes"]) if node["name"] in live}
        if anchor is not None:
            require(common >= anchor["common_seqno"], "common height regressed below anchor")
            result["rpc"]["range_headers"] = {
                node["name"]: {
                    str(height): rpc(node["rpc_url"], "getBlockHeader",
                                     {**params, "seqno": height}, height)
                    for height in range(anchor["common_seqno"] + 1, common + 1)}
                for node in policy["nodes"] if node["name"] in live}
        result["rpc"]["last"] = {
            node["name"]: rpc(node["rpc_url"], "getMasterchainInfo", None, i * 4 + 4)
            for i, node in enumerate(policy["nodes"])}
    except (ValueError, KeyError, TypeError) as error:
        result["capture_error"] = repr(error)
    result["completed_ns"] = time.monotonic_ns()
    return result


def command_json(row: dict, expected: list[str]) -> list:
    require(row.get("argv") == expected and row.get("exit") == 0
            and type(row.get("started_ns")) is int
            and type(row.get("completed_ns")) is int
            and row["started_ns"] <= row["completed_ns"], "raw command failed or differs")
    try:
        raw = base64.b64decode(row["stdout_b64"], validate=True)
        parsed = json.loads(raw)
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError("raw command output is malformed") from error
    require(digest(raw) == row.get("stdout_sha256") and isinstance(parsed, list),
            "raw command SHA or JSON differs")
    return parsed


def counter(value: object, field: str) -> int:
    require(type(value) is int and value >= 0, f"missing raw {field} counter")
    return value


def tc_rule(snapshot: dict, rule: dict, nodes: dict) -> tuple[int, int] | None:
    iface = rule["interface"]
    require(iface in snapshot["tc"], "target tc interface is absent")
    raw = snapshot["tc"][iface]
    filters = command_json(raw["filters"], ["tc", "-j", "-s", "filter", "show", "dev", iface, "egress"])
    qdiscs = command_json(raw["qdiscs"], ["tc", "-j", "-s", "qdisc", "show", "dev", iface])
    require(not any(q.get("kind") == "netem" and q.get("parent") in (None, "root")
                    for q in qdiscs), "interface-wide netem cannot prove peer isolation")
    matching = [item for item in filters if str(item.get("pref")) == str(rule["pref"])
                and str((item.get("options") or {}).get("handle", item.get("handle"))) == rule["handle"]]
    require(len(matching) <= 1, "duplicate target tc rule")
    if not matching:
        return None
    item = matching[0]
    require(item.get("kind") == "flower", "target rule is not a peer flower filter")
    opts = item.get("options") or {}
    keys = opts.get("keys") or {}
    src, dst = nodes[rule["src_node"]], nodes[rule["dst_node"]]
    require(keys.get("ip_proto") == "udp"
            and keys.get("src_ip") == src["peer_ip"]
            and keys.get("dst_ip") == dst["peer_ip"]
            and int(keys.get("src_port", -1)) == src["peer_port"]
            and int(keys.get("dst_port", -1)) == dst["peer_port"],
            "target rule does not match bound peer flow")
    actions = opts.get("actions") or []
    require(len(actions) == 1 and actions[0].get("kind") == "gact"
            and (actions[0].get("control_action") or {}).get("type") == "drop",
            "target rule is not a drop action")
    stats = actions[0].get("stats") or {}
    return counter(stats.get("packets"), "matched packets"), counter(stats.get("drops"), "dropped packets")


def validate_tc_surface(snapshot: dict, policy: dict) -> None:
    """An unrelated tc classifier can invalidate attribution on the same path."""
    for iface, raw in snapshot["tc"].items():
        filters = command_json(raw["filters"],
                               ["tc", "-j", "-s", "filter", "show", "dev", iface, "egress"])
        allowed = {(str(rule["pref"]), rule["handle"])
                   for rule in policy["rules"] if rule["interface"] == iface}
        for item in filters:
            identity = (str(item.get("pref")),
                        str((item.get("options") or {}).get("handle", item.get("handle"))))
            require(identity in allowed,
                    "unaccounted tc filter shares the validator peer interface")


def has_clsact(snapshot: dict, iface: str) -> bool:
    raw = snapshot["tc"][iface]["qdiscs"]
    qdiscs = command_json(raw, ["tc", "-j", "-s", "qdisc", "show", "dev", iface])
    return any(item.get("kind") == "clsact" for item in qdiscs)


def active_rule_ids(snapshot: dict, policy: dict, nodes: dict) -> set[str]:
    validate_tc_surface(snapshot, policy)
    return {rule["id"] for rule in policy["rules"]
            if tc_rule(snapshot, rule, nodes) is not None}


def journal_entries(row: dict, node: dict) -> list[dict]:
    expected = ["journalctl", "-u", node["service"], "--no-pager", "-o", "json"]
    argv = row.get("argv")
    require(argv == expected or (isinstance(argv, list) and len(argv) == len(expected) + 2
            and argv[:len(expected)] == expected and argv[-2] == "--cursor"
            and isinstance(argv[-1], str) and argv[-1]),
            "journal raw capture failed or wrong service/cursor")
    require(row.get("exit") == 0, "journal raw capture failed")
    raw = base64.b64decode(row["stdout_b64"], validate=True)
    require(digest(raw) == row.get("stdout_sha256"), "journal SHA differs")
    try:
        entries = [json.loads(line) for line in raw.splitlines()]
    except (ValueError, TypeError) as error:
        raise ValueError("journal JSON segment differs") from error
    require(entries and all(isinstance(item, dict) and isinstance(item.get("__CURSOR"), str)
                            and item["__CURSOR"] and isinstance(item.get("MESSAGE"), str)
                            for item in entries), "journal cursor/segment is absent")
    cursors = [item["__CURSOR"] for item in entries]
    require(len(cursors) == len(set(cursors)), "journal segment repeats a cursor")
    if len(argv) > len(expected):
        require(cursors[0] == argv[-1], "journal segment lost previous cursor")
    return entries


def journal_end_cursor(row: dict, node: dict) -> str:
    return journal_entries(row, node)[-1]["__CURSOR"]


def journal_ids(row: dict, node: dict, boot_id: str) -> dict[int, tuple[str, str, int, str]]:
    entries = journal_entries(row, node)
    ids: dict[int, tuple[str, str, int, str]] = {}
    for entry in entries:
        for match in MARKER.finditer(entry["MESSAGE"]):
            require(entry.get("_PID") == str(node["pid"]),
                    "native finalized marker has wrong process identity")
            stamp = entry.get("__MONOTONIC_TIMESTAMP")
            require(normalize_boot_id(entry.get("_BOOT_ID")) == normalize_boot_id(boot_id)
                    and isinstance(stamp, str)
                    and stamp.isdecimal() and int(stamp) > 0,
                    "native finalized marker lacks bound boot/monotonic time")
            marker_ns = int(stamp) * 1000
            require(marker_ns <= row["completed_ns"],
                    "native finalized marker is later than journal capture")
            seq = int(match.group(1))
            block = (match.group(2).lower(), match.group(3).lower())
            require(seq not in ids or ids[seq][:2] == block,
                    f"{node['name']} has conflicting finalized IDs at height {seq}")
            if seq not in ids or marker_ns < ids[seq][2]:
                ids[seq] = (*block, marker_ns, entry["__CURSOR"])
    return ids


def process_identity(raw: dict, node: dict) -> None:
    require(raw.get("pid") == node["pid"] and raw.get("exe_sha256") == node["exe_sha256"]
            and raw.get("data_dir") == str(Path(node["data_dir"]).resolve())
            and raw.get("cwd") == raw.get("data_dir"),
            "process identity differs")
    cmdline = base64.b64decode(raw["cmdline_b64"], validate=True)
    argv = [arg.decode() for arg in cmdline.rstrip(b"\0").split(b"\0")]
    require(digest(cmdline) == raw.get("cmdline_sha256")
            and "--db" in argv and argv[argv.index("--db") + 1] == "."
            and "--json-rpc-address" in argv
            and argv[argv.index("--json-rpc-address") + 1]
            == node["rpc_url"].removeprefix("http://").removesuffix("/jsonRPC"),
            "PID command line does not bind DB and RPC endpoint")
    stat = base64.b64decode(raw["stat_b64"], validate=True)
    require(digest(stat) == raw.get("stat_sha256")
            and stat.startswith(f"{node['pid']} (".encode()), "raw PID stat differs")
    # /proc/PID/stat starttime is field 22, after the comm field in parentheses.
    fields = stat.rsplit(b") ", 1)[1].split()
    require(len(fields) > 19 and int(fields[19]) == node["pid_start_ticks"],
            "PID generation differs from frozen policy")
    udp = base64.b64decode(raw["udp_table_b64"], validate=True)
    require(digest(udp) == raw.get("udp_table_sha256"), "raw UDP socket table differs")
    inodes = set(raw.get("socket_inodes") or [])
    port = node["peer_port"]
    matches = []
    for line in udp.decode().splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 10:
            addr, raw_port = fields[1].split(":")
            if int(raw_port, 16) == port and int(fields[9]) in inodes:
                address = str(ipaddress.IPv4Address(bytes.fromhex(addr)[::-1]))
                if address in (node["peer_ip"], "0.0.0.0"):
                    matches.append(address)
    require(bool(matches), "peer UDP port is not owned by bound PID")


def verify_snapshot(snapshot: dict, policy: dict, policy_sha: str,
                    seen_ids: dict[str, dict[int, tuple[str, str]]],
                    seen_journal: dict[str, dict[int, tuple[str, str, int, str, str, int]]],
                    global_ids: dict[int, tuple[str, str]],
                    generations: dict[str, bytes],
                    last_tip_heights: dict[str, int]) -> dict:
    require(snapshot.get("schema") == "tos.x02.raw-snapshot.v1"
            and snapshot.get("policy_sha256") == policy_sha
            and snapshot.get("source_commit") == policy["source_commit"]
            and snapshot.get("phase") in PHASES, "snapshot schema, policy or phase differs")
    require(snapshot.get("source") == {"commit": policy["source_commit"],
            "tracked_status_b64": "", "files_sha256": policy["source_files"]},
            "snapshot source bytes or cleanliness differ from frozen policy")
    require(type(snapshot.get("started_ns")) is int
            and type(snapshot.get("completed_ns")) is int
            and snapshot["started_ns"] < snapshot["completed_ns"], "snapshot time is invalid")
    boot_id = snapshot.get("boot_id")
    normalize_boot_id(boot_id)
    nodes = {node["name"]: node for node in policy["nodes"]}
    require(set(snapshot.get("processes") or {}) == set(nodes)
            and set(snapshot.get("journals") or {}) == set(nodes),
            "four process/journal captures are absent")
    first_rpc_start = min(snapshot["rpc"]["first"][name]["started_ns"] for name in nodes)
    for iface, raw in (snapshot.get("tc") or {}).items():
        for kind in ("filters", "qdiscs"):
            row = raw[kind]
            require(snapshot["started_ns"] <= row["started_ns"] <= row["completed_ns"]
                    <= first_rpc_start, f"{iface} raw tc counter was read after RPC observation")
    validate_tc_surface(snapshot, policy)
    first, last, headers, previous_headers, journals, ranges = {}, {}, {}, {}, {}, {}
    live = (set(policy["live_nodes"][snapshot["phase"]])
            if snapshot["phase"] in policy["live_nodes"] else set(nodes))
    require(set((snapshot.get("rpc") or {}).get("headers") or {}) == live
            and set((snapshot.get("rpc") or {}).get("previous_headers") or {}) == live,
            "common-header node set differs from live phase")
    anchor_height = snapshot.get("anchor_common_seqno")
    if snapshot["phase"] in ("three_of_four", "recovery"):
        require(type(anchor_height) is int and anchor_height >= 0
                and isinstance(snapshot.get("anchor_sha256"), str),
                "phase anchor is absent")
        require(set(snapshot["rpc"].get("range_headers") or {}) == live,
                "range-header node set differs from live phase")
    else:
        require(anchor_height is None and snapshot.get("anchor_sha256") is None
                and snapshot["rpc"].get("range_headers") == {},
                "unanchored phase has range headers")
    for name, node in nodes.items():
        proc = snapshot["processes"][name]
        process_identity(proc, node)
        stat = base64.b64decode(proc["stat_b64"], validate=True)
        generation = stat.rsplit(b") ", 1)[1].split()[19]
        require(name not in generations or generations[name] == generation,
                "PID generation changed during fault run")
        generations[name] = generation
        journal_row = snapshot["journals"][name]
        require(snapshot["started_ns"] <= journal_row["started_ns"]
                <= journal_row["completed_ns"] <= first_rpc_start,
                "journal was read after RPC observation")
        local = journal_ids(journal_row, node, boot_id)
        journals[name] = local
        for height, block in local.items():
            require(height not in seen_ids[name] or seen_ids[name][height] == block[:2],
                    f"{name} finalized conflicting IDs across snapshots")
            require(height not in global_ids or global_ids[height] == block[:2],
                    f"validators disagree on full ID at height {height}")
            seen_ids[name][height] = block[:2]
            if height not in seen_journal[name]:
                seen_journal[name][height] = (*block[:3], snapshot["phase"],
                                              block[3], journal_row["completed_ns"])
            elif block[2] < seen_journal[name][height][2]:
                prior = seen_journal[name][height]
                seen_journal[name][height] = (*prior[:2], block[2], prior[3],
                                              prior[4], prior[5])
            global_ids[height] = block[:2]
        rpc_rows = snapshot["rpc"]
        first_row, last_row = rpc_rows["first"][name], rpc_rows["last"][name]
        first[name] = parse_rpc(first_row, node, "getMasterchainInfo",
                                expected_init=policy["zerostate"])
        last[name] = parse_rpc(last_row, node, "getMasterchainInfo",
                               expected_init=policy["zerostate"])
        if name in live:
            header_height = min(
                parse_rpc(rpc_rows["first"][member], nodes[member], "getMasterchainInfo",
                          expected_init=policy["zerostate"])[2] for member in live)
            headers[name] = parse_rpc(rpc_rows["headers"][name], node, "getBlockHeader",
                                      expected_seq=header_height)
            previous_headers[name] = parse_rpc(
                rpc_rows["previous_headers"][name], node, "getBlockHeader",
                expected_seq=max(0, header_height - 1))
            header_time = rpc_rows["previous_headers"][name]["completed_ns"]
            require(rpc_rows["headers"][name]["completed_ns"] <= header_time,
                    "two header queries completed out of order")
            raw_range = (rpc_rows.get("range_headers") or {}).get(name, {})
            expected_heights = (range(anchor_height + 1, header_height + 1)
                                if anchor_height is not None else ())
            require(set(raw_range) == {str(height) for height in expected_heights},
                    "per-height header range has a gap or extra height")
            ranges[name] = {}
            for height in expected_heights:
                item = raw_range[str(height)]
                value = parse_rpc(item, node, "getBlockHeader", expected_seq=height)
                require(header_time <= item["started_ns"] <= item["completed_ns"],
                        "per-height header was not queried after common header")
                header_time = item["completed_ns"]
                ranges[name][height] = value
            if header_height in ranges[name]:
                require(ranges[name][header_height] == headers[name],
                        "range header conflicts with common header")
        else:
            header_time = first_row["completed_ns"]
        require(snapshot["started_ns"] <= first_row["completed_ns"]
                <= header_time <= last_row["completed_ns"] <= snapshot["completed_ns"],
                "per-node RPC completion order differs")
        require(snapshot["started_ns"] <= first_row["started_ns"]
                <= first_row["completed_ns"]
                and first_row["started_ns"] <= first_row["completed_ns"]
                and last_row["started_ns"] <= last_row["completed_ns"],
                "raw RPC start/completion time differs")
        require(last[name][2] >= first[name][2], "tip regressed during sample")
        require(name not in last_tip_heights
                or first[name][2] >= last_tip_heights[name],
                f"{name} tip regressed across samples")
        last_tip_heights[name] = last[name][2]
        for value in (first[name], last[name],
                      *([headers[name], previous_headers[name], *ranges[name].values()]
                        if name in live else [])):
            height, block = value[2], (value[3], value[4])
            require(height not in seen_ids[name] or seen_ids[name][height] == block,
                    f"{name} raw RPC conflicts with finalized ID at height {height}")
            require(height not in global_ids or global_ids[height] == block,
                    f"validators disagree on full ID at height {height}")
            seen_ids[name][height] = block
            global_ids[height] = block
    common = min(first[name][2] for name in live)
    require(all(value[2] == common for value in headers.values())
            and len({value for value in headers.values()}) == 1,
            "live nodes lack identical common-height full ID")
    require(all(value[2] == max(0, common - 1) for value in previous_headers.values())
            and len(set(previous_headers.values())) == 1,
            "live nodes lack identical preceding full ID")
    return {"phase": snapshot["phase"], "start": snapshot["started_ns"],
            "end": snapshot["completed_ns"], "first": first, "last": last,
            "common": next(iter(headers.values())),
            "previous_common": next(iter(previous_headers.values())),
            "range_ids": ranges,
            "journal": journals,
            "journal_seen": {name: dict(seen_journal[name]) for name in nodes},
            "tip_times": {name: snapshot["rpc"]["last"][name]["completed_ns"] for name in nodes}}


def overlap(samples: list[dict], nodes: set[str]) -> float:
    return (min(samples[-1]["tip_times"][name] for name in nodes)
            - max(samples[0]["tip_times"][name] for name in nodes)) / 1e9


def rule_hit_since_install(snapshot: dict, rule: dict, nodes: dict,
                           initial: tuple[int, int] | None,
                           thresholds: dict) -> bool:
    observed = tc_rule(snapshot, rule, nodes)
    return (observed is not None and initial is not None
            and observed[0] - initial[0] >= thresholds["min_rule_packets"]
            and observed[1] - initial[1] >= thresholds["min_rule_drops"])


def verify_event(event: dict, policy_sha: str, rule: dict, action: str,
                 nodes: dict, policy: dict) -> tuple[int, tuple[int, int] | None]:
    require(event.get("schema") == "tos.x02.tc-event.v1"
            and event.get("policy_sha256") == policy_sha
            and event.get("rule_id") == rule["id"] and event.get("action") == action,
            "fault event identity differs")
    require(event.get("source") == {"commit": policy["source_commit"],
            "tracked_status_b64": "", "files_sha256": policy["source_files"]},
            "fault event source bytes or cleanliness differ")
    command = event.get("command") or {}
    require(command.get("argv") == rule[action + "_argv"] and command.get("exit") == 0
            and type(command.get("started_ns")) is int
            and type(command.get("completed_ns")) is int
            and command["started_ns"] <= command["completed_ns"],
            "fault command failed or differs from frozen policy")
    require(isinstance(command.get("stdout_b64"), str)
            and isinstance(command.get("stderr_b64"), str),
            "raw fault command output is absent")
    stdout = base64.b64decode(command["stdout_b64"], validate=True)
    stderr = base64.b64decode(command["stderr_b64"], validate=True)
    require(digest(stdout) == command.get("stdout_sha256")
            and digest(stderr) == command.get("stderr_sha256"),
            "fault command stdout/stderr SHA differs")
    pre = {"tc": event.get("pre_tc")}
    post = {"tc": event.get("post_tc")}
    validate_tc_surface(pre, policy)
    validate_tc_surface(post, policy)
    require(has_clsact(pre, rule["interface"]) and has_clsact(post, rule["interface"]),
            "peer filter command lacks clsact attachment")
    pre_observed = tc_rule(pre, rule, nodes)
    observed = tc_rule(post, rule, nodes)
    require((pre_observed is not None) == (action == "remove"),
            "fault command pre-state did not match target rule")
    require((observed is not None) == (action == "install"),
            "fault command post-state did not change target rule")
    iface = rule["interface"]
    require(pre["tc"][iface]["filters"]["completed_ns"] <= command["started_ns"]
            and pre["tc"][iface]["qdiscs"]["completed_ns"] <= command["started_ns"]
            and post["tc"][iface]["filters"]["started_ns"] >= command["completed_ns"]
            and post["tc"][iface]["qdiscs"]["started_ns"] >= command["completed_ns"],
            "fault command time does not bind raw tc pre/post states")
    end = max(command["completed_ns"],
              post["tc"][iface]["filters"]["completed_ns"],
              post["tc"][iface]["qdiscs"]["completed_ns"])
    return end, observed


def verify_clsact_event(event: dict, policy_sha: str, policy: dict,
                        action: str) -> int:
    require(event.get("schema") == "tos.x02.tc-event.v1"
            and event.get("policy_sha256") == policy_sha
            and event.get("rule_id") == "clsact" and event.get("action") == action,
            "clsact event identity differs")
    require(event.get("source") == {"commit": policy["source_commit"],
            "tracked_status_b64": "", "files_sha256": policy["source_files"]},
            "clsact event source bytes or cleanliness differ")
    command = event.get("command") or {}
    require(command.get("argv") == policy["clsact"][action + "_argv"]
            and command.get("exit") == 0,
            "precommitted clsact command failed or differs")
    stdout = base64.b64decode(command["stdout_b64"], validate=True)
    stderr = base64.b64decode(command["stderr_b64"], validate=True)
    require(digest(stdout) == command.get("stdout_sha256")
            and digest(stderr) == command.get("stderr_sha256"),
            "clsact command stdout/stderr SHA differs")
    pre, post = {"tc": event.get("pre_tc")}, {"tc": event.get("post_tc")}
    validate_tc_surface(pre, policy)
    validate_tc_surface(post, policy)
    iface = policy["clsact"]["interface"]
    require(has_clsact(pre, iface) == (action == "cleanup")
            and has_clsact(post, iface) == (action == "setup"),
            "clsact pre/post qdisc state differs")
    empty = pre if action == "setup" else post
    filters = command_json(empty["tc"][iface]["filters"],
                           ["tc", "-j", "-s", "filter", "show", "dev", iface, "egress"])
    require(not filters, "clsact boundary has an unremoved peer filter")
    require(pre["tc"][iface]["qdiscs"]["completed_ns"] <= command["started_ns"]
            <= command["completed_ns"] <= post["tc"][iface]["qdiscs"]["started_ns"],
            "clsact command time does not bind qdisc state")
    return max(post["tc"][iface]["filters"]["completed_ns"],
               post["tc"][iface]["qdiscs"]["completed_ns"])


def verify(policy: dict, policy_sha: str, snapshots: list[dict], events: list[dict]) -> dict:
    validate_policy(policy)
    require(isinstance(snapshots, list) and snapshots, "no raw snapshots")
    nodes = {node["name"]: node for node in policy["nodes"]}
    rules = {rule["id"]: rule for rule in policy["rules"]}
    phases = {phase: [] for phase in PHASES}
    seen_ids = {name: {} for name in nodes}
    seen_journal = {name: {} for name in nodes}
    global_ids: dict[int, tuple[str, str]] = {}
    generations: dict[str, bytes] = {}
    last_tip_heights: dict[str, int] = {}
    previous_end = -1
    previous_snap = None
    run_boot_id = None
    phase_index = 0
    for snap in snapshots:
        require(run_boot_id is None or normalize_boot_id(snap.get("boot_id")) == run_boot_id,
                "host boot changed during fault run")
        run_boot_id = normalize_boot_id(snap.get("boot_id"))
        require(snap.get("previous_sha256") == (snapshot_digest(previous_snap)
                if previous_snap is not None else None),
                "snapshot journal segment chain is broken")
        if previous_snap is not None:
            for node in policy["nodes"]:
                name = node["name"]
                require(snap["journals"][name]["argv"][-2:] == [
                    "--cursor", journal_end_cursor(previous_snap["journals"][name], node)],
                    "journal segment lost previous cursor")
                require(journal_entries(snap["journals"][name], node)[0]
                        == journal_entries(previous_snap["journals"][name], node)[-1],
                        "journal cursor payload changed across segments")
        phase = snap.get("phase")
        require(phase in PHASES, "unknown phase")
        index = PHASES.index(phase)
        require(phase_index <= index <= phase_index + 1,
                "phase order or sample is missing")
        phase_index = index
        row = verify_snapshot(snap, policy, policy_sha, seen_ids, seen_journal, global_ids,
                              generations, last_tip_heights)
        require(has_clsact(snap, policy["clsact"]["interface"]),
                "clsact egress filter attachment is absent during observation")
        require(row["start"] >= previous_end, "snapshots overlap or time regressed")
        previous_end = row["end"]
        phases[phase].append((snap, row))
        previous_snap = snap
    require(all(phases[phase] for phase in PHASES), "baseline/fault/recovery phase absent")
    require(len(phases["baseline"]) == 1
            and all(len(phases[phase]) >= 2 for phase in PHASES[1:]),
            "insufficient phase samples")
    thresholds = policy["thresholds"]
    require(len(phases["two_of_four"]) >= thresholds["halt_tail_samples"],
            "2/4 tail samples are absent")
    for phase, anchor_phase in (("three_of_four", "baseline"),
                                ("recovery", "two_of_four")):
        anchor_snap, anchor_row = phases[anchor_phase][-1]
        for snap, row in phases[phase]:
            require(snap["anchor_sha256"] == snapshot_digest(anchor_snap)
                    and snap["anchor_common_seqno"] == anchor_row["common"][2],
                    f"{phase} raw anchor differs")

    event_rows = {}
    previous_event_end = -1
    active_ids: set[str] = set()
    for event in events:
        require(normalize_boot_id(event.get("boot_id")) == run_boot_id,
                "host boot changed across fault command and snapshots")
        key = (event.get("rule_id"), event.get("action"))
        require(key not in event_rows, "duplicate tc event")
        if key in (("clsact", "setup"), ("clsact", "cleanup")):
            end, counts = verify_clsact_event(event, policy_sha, policy, key[1]), None
            require(not active_ids, "clsact transition overlaps active peer fault rules")
        else:
            require(key[0] in rules and key[1] in ("install", "remove"),
                    "unknown tc event")
            end, counts = verify_event(event, policy_sha, rules[key[0]], key[1],
                                       nodes, policy)
        pre_ids = active_rule_ids({"tc": event["pre_tc"]}, policy, nodes)
        post_ids = active_rule_ids({"tc": event["post_tc"]}, policy, nodes)
        require(pre_ids == active_ids, "tc event pre-state has extra or missing peer rule")
        expected_post = set(active_ids)
        if key[1] == "install":
            expected_post.add(key[0])
        elif key[1] == "remove":
            require(key[0] in expected_post, "tc remove had no installed target")
            expected_post.remove(key[0])
        require(post_ids == expected_post,
                "tc event post-state has extra or missing peer rule")
        active_ids = expected_post
        started = event["command"]["started_ns"]
        require(started >= previous_event_end, "tc events overlap or reorder")
        previous_event_end = end
        event_rows[key] = (started, end, counts)
    required_events = {(rule_id, action) for rule_id in rules
                       for action in ("install", "remove")}
    required_events |= {("clsact", "setup"), ("clsact", "cleanup")}
    require(set(event_rows) == required_events, "missing install/remove or clsact tc events")
    three_rules = [r for r in policy["rules"] if r["phase"] == "three_of_four"]
    two_rules = [r for r in policy["rules"] if r["phase"] == "two_of_four"]
    last_baseline = phases["baseline"][-1][1]["end"]
    first_baseline = phases["baseline"][0][1]["start"]
    first_three = phases["three_of_four"][0][1]["start"]
    last_three = phases["three_of_four"][-1][1]["end"]
    first_two = phases["two_of_four"][0][1]["start"]
    last_two = phases["two_of_four"][-1][1]["end"]
    first_recovery = phases["recovery"][0][1]["start"]
    last_recovery = phases["recovery"][-1][1]["end"]
    require(event_rows[("clsact", "setup")][1] <= first_baseline
            and last_recovery <= event_rows[("clsact", "cleanup")][0],
            "clsact setup/cleanup does not bracket the fault run")
    require(all(last_baseline <= event_rows[(r["id"], "install")][0]
                < event_rows[(r["id"], "install")][1] <= first_three
                for r in three_rules), "node4 cut was not installed before 3/4 samples")
    require(all(last_three <= event_rows[(r["id"], "install")][0]
                < event_rows[(r["id"], "install")][1] <= first_two
                for r in two_rules), "node3 cut was not installed before 2/4 samples")
    require(all(last_two <= event_rows[(r["id"], "remove")][0]
                < event_rows[(r["id"], "remove")][1] <= first_recovery
                for r in policy["rules"]), "all peer rules were not removed before recovery")

    # A successful `tc` command is insufficient: every directed peer rule must
    # show a positive matched-packet and drop delta after its install snapshot.
    active_by_phase = {"baseline": [], "three_of_four": three_rules,
                       "two_of_four": three_rules + two_rules, "recovery": []}
    effective = {}
    last_counts = {rule["id"]: event_rows[(rule["id"], "install")][2]
                   for rule in policy["rules"]}
    for phase, entries in phases.items():
        active = active_by_phase[phase]
        for snap, _ in entries:
            for rule in policy["rules"]:
                observed = tc_rule(snap, rule, nodes)
                require((observed is not None) == (rule in active),
                        f"{phase} peer rule is absent or active in wrong phase")
                if observed is not None:
                    previous = last_counts[rule["id"]]
                    require(previous is not None
                            and observed[0] >= previous[0] and observed[1] >= previous[1],
                            f"{phase} target rule counters reset or regressed")
                    last_counts[rule["id"]] = observed
        if phase in ("three_of_four", "two_of_four"):
            new_rules = three_rules if phase == "three_of_four" else two_rules
            qualifying = []
            fault_effective = False
            for snap, row in entries:
                hit = all(rule_hit_since_install(
                        snap, rule, nodes, event_rows[(rule["id"], "install")][2], thresholds)
                       for rule in new_rules)
                require(not fault_effective or hit,
                        f"{phase} lost a target peer hit after fault became effective")
                if hit:
                    fault_effective = True
                    qualifying.append(row)
            require(len(qualifying) >= 2, f"{phase} has no sustained target peer hit/drop")
            effective[phase] = qualifying

    live3 = set(policy["live_nodes"]["three_of_four"])
    live2 = set(policy["live_nodes"]["two_of_four"])
    three = effective["three_of_four"]
    require(three[-1]["common"][2] - three[0]["common"][2]
            >= thresholds["three_min_delta"],
            "3/4 has fewer than two newly common finalized heights")
    anchor3 = phases["baseline"][-1][1]["common"][2]
    node4_cut_installed_at = max(event_rows[(r["id"], "install")][1]
                                 for r in three_rules)
    for name in live3:
        for height in range(anchor3 + 1, three[-1]["common"][2] + 1):
            value = three[-1]["range_ids"][name].get(height)
            require(value is not None, "3/4 per-height full ID is absent")
            marker = three[-1]["journal_seen"][name].get(value[2])
            require(marker is not None and marker[:2] == (value[3], value[4]),
                    "3/4 per-height full ID lacks native finalized marker")
            require(marker[3] == "three_of_four" and node4_cut_installed_at < marker[2]
                    and marker[2] <= marker[5],
                    "3/4 native finalized marker predates node4 cut or fault segment")
    require((max(three[-1]["tip_times"][n] for n in live3)
             - node4_cut_installed_at) / 1e9 <= thresholds["three_max_seconds"],
            "3/4 common progress missed 120-second window")
    require(all(three[-1]["last"][n][2] >= three[-1]["common"][2]
                for n in live3), "3/4 live node did not reach common height")

    two = effective["two_of_four"]
    for name in live2:
        anchor = two[0]["last"][name]
        require(all(row["first"][name] == anchor and row["last"][name] == anchor
                    for row in two), "2/4 live node advanced")
        require(all(all(height <= anchor[2] for height in row["journal"][name])
                    for row in two), "2/4 native finalized marker advanced")
    require(overlap(two, live2) >= thresholds["halt_min_seconds"],
            "2/4 common tip observation window is shorter than 60 seconds")
    require(overlap(two[-thresholds["halt_tail_samples"]:], live2)
            >= thresholds["halt_tail_min_seconds"],
            "2/4 common tail tip window is too short")

    recovery = [row for _, row in phases["recovery"]]
    removed_at = max(event_rows[(r["id"], "remove")][1] for r in policy["rules"])
    require((recovery[-1]["end"] - removed_at) / 1e9
            <= thresholds["recovery_max_seconds"],
            "recovery missed 180-second deadline")
    require(recovery[-1]["common"][2] - two[-1]["common"][2]
            >= thresholds["recovery_min_delta"],
            "four nodes lack two newly common finalized heights after recovery")
    anchor_recovery = phases["two_of_four"][-1][1]["common"][2]
    for name in nodes:
        for height in range(anchor_recovery + 1, recovery[-1]["common"][2] + 1):
            value = recovery[-1]["range_ids"][name].get(height)
            require(value is not None, "recovery per-height full ID is absent")
            marker = recovery[-1]["journal_seen"][name].get(value[2])
            require(marker is not None and marker[:2] == (value[3], value[4]),
                    "recovery per-height full ID lacks native finalized marker")
            require(marker[3] == "recovery" and removed_at < marker[2]
                    and marker[2] <= marker[5],
                    "recovery native finalized marker predates fault removal or recovery segment")
    require(all(recovery[-1]["last"][n][2] >= recovery[-1]["common"][2]
                for n in nodes), "node3 or node4 failed to catch up")
    return {"passed": True, "scope": "X02 directed 100% isolation offline slice",
            "policy_sha256": policy_sha, "snapshots": len(snapshots),
            "nodes": sorted(nodes)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("capture", "event", "verify"))
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--phase", choices=PHASES)
    parser.add_argument("--anchor-snapshot", type=Path)
    parser.add_argument("--previous-snapshot", type=Path)
    parser.add_argument("--rule-id")
    parser.add_argument("--action", choices=("setup", "install", "remove", "cleanup"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--snapshots", type=Path, nargs="*")
    parser.add_argument("--events", type=Path, nargs="*")
    args = parser.parse_args()
    policy = read_policy(args.policy, args.policy_sha256)
    if args.command == "capture":
        require(args.phase is not None and args.output is not None, "capture needs phase and output")
        require(not args.output.exists(), "capture output already exists")
        anchor = json.loads(args.anchor_snapshot.read_bytes()) if args.anchor_snapshot else None
        previous = json.loads(args.previous_snapshot.read_bytes()) if args.previous_snapshot else None
        result = capture(policy, args.policy_sha256, args.phase, anchor, previous)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        require("capture_error" not in result, "RPC capture failed; raw snapshot retained")
    elif args.command == "event":
        require(args.rule_id is not None and args.action is not None
                and args.output is not None, "event needs rule ID, action and output")
        require(not args.output.exists(), "event output already exists")
        result = fault_event(policy, args.policy_sha256, args.rule_id, args.action)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        require(result["command"]["exit"] == 0, "tc command failed; raw event retained")
    else:
        require(args.snapshots is not None and len(args.snapshots) > 0, "verify needs raw snapshots")
        require(args.events is not None and len(args.events) > 0, "verify needs raw tc events")
        snapshots = [json.loads(path.read_bytes()) for path in args.snapshots]
        events = [json.loads(path.read_bytes()) for path in args.events]
        print(json.dumps(verify(policy, args.policy_sha256, snapshots, events), sort_keys=True))


if __name__ == "__main__":
    main()
