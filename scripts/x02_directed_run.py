#!/usr/bin/env python3
"""Run one frozen X02 100% directed peer cut on an already-live Stage A network.

Requires CAP_NET_ADMIN. Every tc action and RPC/native snapshot is written
before a verdict; on any error, only this policy's installed rules are removed.
This does not start a validator network or prove partial packet loss.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

import x02_fault_evidence as x02


def write_once(path: Path, value: dict) -> None:
    encoded = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(encoded)


def rule_ids(policy: dict, phase: str) -> list[str]:
    return [rule["id"] for rule in policy["rules"] if rule["phase"] == phase]


def common_height(snapshot: dict) -> int:
    x02.require(type(snapshot.get("common_seqno")) is int,
                "raw snapshot lacks a common finalized height")
    return snapshot["common_seqno"]


def collect(policy: dict, sha: str, root: Path) -> dict:
    x02.require_source_commit(policy)
    x02.require(os.geteuid() == 0, "X02 tc injection requires root/CAP_NET_ADMIN")
    x02.require(not root.exists(), "X02 output directory already exists")
    root.mkdir(parents=True)
    events: list[dict] = []
    snapshots: list[dict] = []
    installed: list[str] = []
    clsact = False
    attempted_install: str | None = None
    attempted_clsact = False
    write_once(root / "invocation.json", {"argv": sys.argv,
               "euid": os.geteuid(), "pid": os.getpid(),
               "source_commit": policy["source_commit"], "policy_sha256": sha})
    before = x02.capture_tc(policy)
    write_once(root / "tc-before.json", before)
    iface = policy["clsact"]["interface"]
    qdiscs = x02.command_json(before[iface]["qdiscs"],
                              ["tc", "-j", "-s", "qdisc", "show", "dev", iface])
    x02.require(len(qdiscs) == 1 and qdiscs[0].get("kind") == "noqueue"
                and qdiscs[0].get("root") is True,
                "pre-existing root qdisc is not the allowed loopback noqueue state")
    x02.require(x02.command_json(before[iface]["filters"],
                                 ["tc", "-j", "-s", "filter", "show", "dev", iface,
                                  "egress"]) == [],
                "pre-existing tc filters make directed attribution ambiguous")
    x02.require(not x02.has_clsact({"tc": before}, iface),
                "pre-existing clsact must not be deleted by X02")

    def event(rule_id: str, action: str) -> dict:
        nonlocal attempted_install, attempted_clsact
        if (rule_id, action) == ("clsact", "setup"):
            attempted_clsact = True
        elif action == "install":
            attempted_install = rule_id
        row = x02.fault_event(policy, sha, rule_id, action)
        write_once(root / f"event-{len(events):02d}-{rule_id}-{action}.json", row)
        x02.require(row["command"]["exit"] == 0,
                    f"tc {rule_id} {action} failed; raw event retained")
        if action == "install":
            attempted_install = None
        elif (rule_id, action) == ("clsact", "setup"):
            attempted_clsact = False
        events.append(row)
        return row

    def sample(phase: str, anchor: dict | None = None) -> dict:
        previous = snapshots[-1] if snapshots else None
        row = x02.capture(policy, sha, phase, anchor, previous)
        write_once(root / f"sample-{len(snapshots):02d}-{phase}.json", row)
        x02.require("capture_error" not in row,
                    "RPC capture failed; raw snapshot retained")
        snapshots.append(row)
        return row

    status = "failed"
    error = None
    try:
        event("clsact", "setup")
        clsact = True
        baseline = sample("baseline")
        three_ids = rule_ids(policy, "three_of_four")
        for rule_id in three_ids:
            event(rule_id, "install")
            installed.append(rule_id)
        three_start = time.monotonic()
        first_three = sample("three_of_four", baseline)
        first_height = common_height(first_three)
        while True:
            x02.require(time.monotonic() - three_start < 120,
                        "3/4 did not gain two common IDs within 120 seconds")
            time.sleep(10)
            current = sample("three_of_four", baseline)
            if common_height(current) - first_height >= 2:
                break
        two_ids = rule_ids(policy, "two_of_four")
        for rule_id in two_ids:
            event(rule_id, "install")
            installed.append(rule_id)
        # Predetermined drain: any old finality becoming visible in these 30 s
        # remains in the first raw 2/4 sample, never silently skipped later.
        time.sleep(policy["thresholds"]["two_drain_seconds"])
        first_two = sample("two_of_four")
        first_two_height = common_height(first_two)
        for _ in range(3):
            time.sleep(25)
            row = sample("two_of_four")
            x02.require(common_height(row) == first_two_height,
                        "2/4 common height advanced during claimed safe halt")
        recovery_anchor = snapshots[-1]
        for rule_id in reversed(installed):
            event(rule_id, "remove")
            installed.remove(rule_id)
        removed_at = time.monotonic()
        recovery_target = (common_height(recovery_anchor)
                           + policy["thresholds"]["recovery_min_delta"])
        current = sample("recovery", recovery_anchor)
        while common_height(current) < recovery_target:
            x02.require(time.monotonic() - removed_at < 180,
                        "recovery did not gain two common IDs within 180 seconds")
            time.sleep(10)
            current = sample("recovery", recovery_anchor)
        event("clsact", "cleanup")
        clsact = False
        verdict = x02.verify(policy, sha, snapshots, events)
        write_once(root / "verdict.json", verdict)
        x02.require(verdict.get("passed") is True,
                    "X02 verifier did not accept the directed fault evidence")
        status = "passed"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        cleanup = []
        cleanup_ids = list(installed)
        if attempted_install is not None and attempted_install not in cleanup_ids:
            cleanup_ids.append(attempted_install)
        for rule_id in reversed(cleanup_ids):
            rule = next(item for item in policy["rules"] if item["id"] == rule_id)
            row = x02.run_raw(rule["remove_argv"])
            cleanup.append({"rule_id": rule_id, "action": "remove", "raw": row})
        if clsact or attempted_clsact:
            cleanup.append({"rule_id": "clsact", "action": "cleanup",
                            "raw": x02.run_raw(policy["clsact"]["cleanup_argv"])})
        after = x02.capture_tc(policy)
        write_once(root / "cleanup.json", {"fallback_commands": cleanup,
                                           "tc_after": after})
        try:
            x02.require(x02.command_json(after[iface]["filters"],
                                        ["tc", "-j", "-s", "filter", "show", "dev",
                                         iface, "egress"]) == []
                        and not x02.has_clsact({"tc": after}, iface),
                        "X02 tc cleanup left a filter or clsact behind")
        except Exception as exc:
            status = "failed"
            error = f"{error}; cleanup: {type(exc).__name__}: {exc}"
        result = {"status": status, "error": error,
                  "source_commit": policy["source_commit"],
                  "policy_sha256": sha, "snapshots": len(snapshots),
                  "events": len(events), "scope": "directed 100% local peer isolation"}
        write_once(root / "result.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    policy = x02.read_policy(args.policy, args.policy_sha256)
    result = collect(policy, args.policy_sha256, args.output_dir)
    print(json.dumps(result, sort_keys=True))
    x02.require(result["status"] == "passed", "X02 directed fault run failed; originals retained")


if __name__ == "__main__":
    main()
