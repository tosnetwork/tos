#!/usr/bin/env python3
"""Freeze an X02 100% directed-isolation policy from live Stage A readiness."""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
from pathlib import Path

import x02_fault_evidence as x02

REPO = Path(__file__).resolve().parents[1]
GIT = ["git", "-c", f"safe.directory={REPO}", "-C", str(REPO)]


def fixed_source() -> tuple[str, dict[str, str]]:
    head = subprocess.check_output([*GIT, "rev-parse", "HEAD"], text=True).strip()
    status = subprocess.check_output([*GIT, "status", "--porcelain",
                                      "--untracked-files=no"])
    x02.require(not status, "tracked source changed before X02 policy freeze")
    files = {}
    for name in x02.SOURCE_FILES:
        raw = (REPO / name).read_bytes()
        frozen = subprocess.check_output([*GIT, "show", f"HEAD:{name}"])
        x02.require(raw == frozen, f"{name} differs from fixed source commit")
        files[name] = x02.digest(raw)
    return head, files


def live_node(item: dict) -> dict:
    name, pid = item["node_name"], item["process_id"]
    directory = Path(item["node_data_dir"]).resolve(strict=True)
    log = directory / "log"
    log_stat = log.stat()
    db_stat = directory.stat()
    proc = Path(f"/proc/{pid}")
    raw_stat = (proc / "stat").read_bytes()
    exe = (proc / "exe").resolve(strict=True)
    x02.require((proc / "cwd").resolve(strict=True) == directory,
                f"{name} validator DB cwd differs from readiness")
    stream = item.get("raw_log_stream") or {}
    harness_pid = stream.get("harness_pid")
    x02.require(type(harness_pid) is int and harness_pid > 0,
                f"{name} raw log harness is absent")
    harness = Path(f"/proc/{harness_pid}")
    harness_stat = (harness / "stat").read_bytes()
    harness_exe = (harness / "exe").resolve(strict=True)
    x02.require(x02._proc_parent_pid(raw_stat) == harness_pid
                and x02._proc_start_ticks(harness_stat) == stream["harness_start_ticks"]
                and os.readlink(proc / "fd/2") == stream["input_link"]
                and os.readlink(harness / "fd" / str(stream["input_fd"]))
                    == stream["input_link"],
                f"{name} child stderr is not its declared harness input")
    writer = (harness / "fd" / str(stream["output_fd"])).stat()
    x02.require((writer.st_dev, writer.st_ino)
                == (log_stat.st_dev, log_stat.st_ino)
                == (stream["output_dev"], stream["output_ino"]),
                f"{name} harness writer is not its declared node log")
    peer = item["peer_transport"]
    node = {"name": name, "pid": pid,
            "pid_start_ticks": x02._proc_start_ticks(raw_stat),
            "service": name, "data_dir": str(directory),
            "rpc_url": item["rpc_url"],
            "peer_ip": peer["ip"], "peer_port": peer["port"],
            "consensus_key_id": item["consensus_key_id_hex"],
            "adnl_id": item["adnl_id_hex"],
            "exe_sha256": x02.digest(exe.read_bytes()),
            "db_dev": db_stat.st_dev, "db_ino": db_stat.st_ino,
            "log_path": str(log), "log_dev": log_stat.st_dev,
            "log_ino": log_stat.st_ino,
            "harness_pid": harness_pid,
            "harness_start_ticks": stream["harness_start_ticks"],
            "harness_exe_sha256": x02.digest(harness_exe.read_bytes()),
            "input_fd": stream["input_fd"], "input_link": stream["input_link"],
            "output_fd": stream["output_fd"]}
    x02.process_identity(x02.capture_process(node), node)
    x02.capture_native_log(node)
    return node


def rule(index: int, phase: str, src: str, dst: str, nodes: dict) -> dict:
    pref, handle = 100 + index, str(index)
    base = ["tc", "filter", "add", "dev", "lo", "egress", "protocol", "ip",
            "pref", str(pref), "handle", handle, "flower", "ip_proto", "udp",
            "src_ip", nodes[src]["peer_ip"], "dst_ip", nodes[dst]["peer_ip"],
            "src_port", str(nodes[src]["peer_port"]),
            "dst_port", str(nodes[dst]["peer_port"]), "action", "drop"]
    return {"id": f"r{index}", "phase": phase, "src_node": src,
            "dst_node": dst, "mode": "drop_all", "interface": "lo",
            "pref": pref, "handle": handle, "install_argv": base,
            "remove_argv": ["tc", "filter", "del", "dev", "lo", "egress",
                            "pref", str(pref), "handle", handle]}


def build_policy(raw: bytes, head: str, files: dict[str, str], nodes: list[dict]) -> dict:
    manifest = json.loads(raw)
    by_name = {node["name"]: node for node in nodes}
    x02.require(set(by_name) == {f"node{i}" for i in range(1, 5)},
                "X02 requires four distinct Stage A validators")
    x02.require(len({node["exe_sha256"] for node in nodes}) == 1,
                "four validator processes have different executable bytes")
    pairs = [("three_of_four", a, "node4") for a in ("node1", "node2", "node3")]
    pairs += [("three_of_four", "node4", a) for a in ("node1", "node2", "node3")]
    pairs += [("two_of_four", a, "node3") for a in ("node1", "node2")]
    pairs += [("two_of_four", "node3", a) for a in ("node1", "node2")]
    zero = manifest["network"]["zero_state"]["masterchain"]
    policy = {"schema": "tos.x02.fault-policy.v1", "source_commit": head,
              "source_files": files, "binary_sha256": nodes[0]["exe_sha256"],
              "readiness_manifest_b64": base64.b64encode(raw).decode(),
              "readiness_manifest_sha256": x02.digest(raw),
              "zerostate": {"root_hash": zero["root_hash_hex"],
                            "file_hash": zero["file_hash_hex"]},
              "log_source": "native-file", "nodes": nodes,
              "live_nodes": {"three_of_four": ["node1", "node2", "node3"],
                             "two_of_four": ["node1", "node2"]},
              "clsact": {"interface": "lo",
                         "setup_argv": ["tc", "qdisc", "add", "dev", "lo", "clsact"],
                         "cleanup_argv": ["tc", "qdisc", "del", "dev", "lo", "clsact"]},
              "rules": [rule(index, *pair, by_name)
                        for index, pair in enumerate(pairs, start=1)],
              "thresholds": {"min_rule_packets": 1, "min_rule_drops": 1,
                             "three_min_delta": 2, "three_max_seconds": 120,
                             "halt_min_seconds": 60, "halt_tail_min_seconds": 20,
                             "halt_tail_samples": 2, "recovery_min_delta": 2,
                             "recovery_max_seconds": 180}}
    x02.validate_policy(policy)
    return policy


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readiness", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    x02.require(not args.output.exists(), "X02 policy output already exists")
    raw = args.readiness.read_bytes()
    manifest = json.loads(raw)
    head, files = fixed_source()
    x02.require((manifest.get("provenance") or {}).get("source_commit") == head,
                "Stage A readiness source commit differs")
    nodes = [live_node(item) for item in manifest["validators"]]
    policy = build_policy(raw, head, files, nodes)
    encoded = (json.dumps(policy, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(encoded)
    print(json.dumps({"policy": str(args.output), "sha256": x02.digest(encoded),
                      "source_commit": head}, sort_keys=True))


if __name__ == "__main__":
    main()
