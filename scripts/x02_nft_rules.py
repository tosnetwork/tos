#!/usr/bin/env python3
"""Owned-table NFQUEUE rules and independent later-hook counters.

No live entrypoint. Caller must prove source/identity/phase and quiescence before
comparing entry/post-hook counters. Post-hook is not socket delivery evidence.
"""

from __future__ import annotations

import json
import re
import subprocess
import time

from x02_partial_adapter import DecisionAdapter
from x02_partial_sequence import DIRECTIONS, require


class RuleManager:
    def __init__(self, run_id: str, adapter: DecisionAdapter, backend, ledger):
        require(isinstance(run_id, str) and re.fullmatch(r"[0-9a-f]{16}", run_id) is not None,
                "run ID must be a frozen sixteen-hex token")
        require(set(backend.queues.values()) == set(DIRECTIONS)
                and len(backend.queues) == 24, "backend directions differ")
        self.table = "x02_" + run_id
        self.marker = "x02-owner-" + run_id
        self.adapter, self.backend, self.ledger = adapter, backend, ledger
        self.attempted = False
        self.preflight_done = False
        self.install_acknowledged = False
        self.ownership = None
        self.removed = False

    def command(self, argv: list[str], stdin: bytes | None = None) -> bytes:
        started = time.monotonic_ns()
        result = subprocess.run(argv, input=stdin, capture_output=True, timeout=5, check=False)
        self.ledger.append({"event": "nft_command", "argv": argv,
                            "stdin_hex": stdin.hex() if stdin is not None else None,
                            "started_ns": started, "completed_ns": time.monotonic_ns(),
                            "exit": result.returncode, "stdout_hex": result.stdout.hex(),
                            "stderr_hex": result.stderr.hex()})
        require(result.returncode == 0, "nft command failed; cleanup required")
        return result.stdout

    def preflight(self) -> None:
        raw = self.command(["/usr/sbin/nft", "-j", "list", "ruleset"])
        objects = json.loads(raw)["nftables"]
        require(not any(item.get("table", {}).get("name") == self.table
                        and item.get("table", {}).get("family") == "ip" for item in objects),
                "owned table already exists; do not touch it")
        self.backend.health(require_empty=True)
        require(all(count["seen"] == 0 for count in self.adapter.counts.values())
                and not self.adapter.failed and self.adapter.pending is None,
                "adapter is not at original index zero")
        self.preflight_done = True

    def script(self) -> bytes:
        require(self.preflight_done, "preflight incomplete")
        prefix = f"ip {self.table}"
        lines = [f'create table {prefix} {{ comment "{self.marker}"; }}',
                 f"add chain {prefix} enqueue {{ type filter hook output priority 0; policy accept; }}",
                 f"add chain {prefix} afterq {{ type filter hook output priority 10; policy accept; }}"]
        queues = {direction: queue for queue, direction in self.backend.queues.items()}
        for ordinal, direction in enumerate(DIRECTIONS):
            src, sport, dst, dport = self.adapter.endpoints[direction]
            match = f"ip saddr {src} ip daddr {dst} udp sport {sport} udp dport {dport}"
            lines.append(f'add rule {prefix} enqueue {match} counter queue to {queues[direction]} comment "{self.marker}:entry{ordinal}"')
            lines.append(f'add rule {prefix} afterq {match} counter comment "{self.marker}:post{ordinal}"')
        return ("\n".join(lines) + "\n").encode("ascii")

    def install(self) -> None:
        require(self.preflight_done and not self.attempted, "installation cannot repeat")
        raw = self.script()
        self.attempted = True
        self.command(["/usr/sbin/nft", "-f", "-"], raw)
        self.install_acknowledged = True
        ownership, counts = self.validate_snapshot(self.snapshot())
        self.ownership = ownership

    def snapshot(self) -> bytes:
        return self.command(["/usr/sbin/nft", "-j", "-a", "list", "table", "ip", self.table])

    def validate_snapshot(self, raw: bytes) -> tuple[dict, dict]:
        tables, chains, rules = [], {}, {}
        counts = {}
        queues = {direction: queue for queue, direction in self.backend.queues.items()}
        for item in json.loads(raw)["nftables"]:
            require(isinstance(item, dict) and len(item) == 1, "unknown nft snapshot object")
            kind, obj = next(iter(item.items()))
            if kind == "metainfo":
                continue
            require(kind in ("table", "chain", "rule") and isinstance(obj, dict),
                    "unexpected object in owned table")
            require(obj.get("family") == "ip" and type(obj.get("handle")) is int
                    and obj["handle"] > 0, "object family/handle differs")
            if kind == "table":
                require(obj.get("name") == self.table and obj.get("comment") == self.marker
                        and not obj.get("flags"), "table owner marker or flags differ")
                tables.append(obj["handle"])
                continue
            require(obj.get("table") == self.table, "object table differs")
            if kind == "chain":
                name = obj.get("name")
                require(name in ("enqueue", "afterq") and name not in chains
                        and obj.get("type") == "filter" and obj.get("hook") == "output"
                        and type(obj.get("prio")) is int
                        and obj["prio"] == (0 if name == "enqueue" else 10)
                        and obj.get("policy") == "accept", "chain hook/priority/policy differs")
                chains[name] = obj["handle"]
                continue
            label = obj.get("comment")
            require(isinstance(label, str) and label.startswith(self.marker + ":"),
                    "rule owner marker differs")
            label = label[len(self.marker) + 1:]
            matched = re.fullmatch(r"(entry|post)([0-9]|1[0-9]|2[0-3])", label)
            require(matched is not None and label not in rules, "counter rule identity differs")
            role, ordinal = matched[1], int(matched[2])
            direction = DIRECTIONS[ordinal]
            chain = "enqueue" if role == "entry" else "afterq"
            require(obj.get("chain") == chain, "counter chain differs")
            src, sport, dst, dport = self.adapter.endpoints[direction]
            expected = []
            for protocol, field, value in (("ip", "saddr", src), ("ip", "daddr", dst),
                                           ("udp", "sport", sport), ("udp", "dport", dport)):
                expected.append({"match": {"op": "==", "left": {"payload": {
                    "protocol": protocol, "field": field}}, "right": value}})
            expr = obj.get("expr")
            require(isinstance(expr, list), "missing rule expression")
            # nft may materialize its implicit UDP protocol guard.
            proto = {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "udp"}}
            require(sum(part == proto for part in expr) <= 1, "duplicate protocol guard")
            expr = [part for part in expr if part != proto]
            require(len(expr) == (6 if role == "entry" else 5)
                    and expr[:4] == expected, "counter four-tuple or expression differs")
            for part in expr[2:4]:
                require(type(part["match"]["right"]) is int, "port is not an integer")
            counter = expr[4]
            require(isinstance(counter, dict) and set(counter) == {"counter"}
                    and isinstance(counter["counter"], dict)
                    and set(counter["counter"]) == {"packets", "bytes"}
                    and all(type(value) is int and value >= 0
                            for value in counter["counter"].values()), "kernel counter differs")
            if role == "entry":
                queue = expr[5].get("queue") if isinstance(expr[5], dict) else None
                require(isinstance(queue, dict) and set(expr[5]) == {"queue"}
                        and set(queue) <= {"num", "flags"} and not queue.get("flags")
                        and type(queue.get("num")) is int and queue["num"] == queues[direction],
                        "queue number/flags differ")
            rules[label] = obj["handle"]
            counts[label] = counter["counter"]
        require(len(tables) == 1 and set(chains) == {"enqueue", "afterq"} and len(rules) == 48,
                "missing or extra table/chain/rule")
        ownership = {"table": tables[0], "chains": chains, "rules": rules}
        if self.ownership is not None:
            require(ownership == self.ownership, "recorded owner handles changed")
        return ownership, counts

    def counters_quiescent(self) -> dict:
        """Read kernel counters; exact comparison needs independently proven idle senders."""
        self.backend.health(require_empty=True)
        require(self.install_acknowledged and self.ownership is not None, "no proven table owner")
        ownership, counts = self.validate_snapshot(self.snapshot())
        # A second queue-empty witness narrows but does not prove sender quiescence.
        self.backend.health(require_empty=True)
        return counts

    def remove_owned_table(self) -> None:
        require(self.preflight_done, "cannot delete table without ownership preflight")
        if self.attempted and not self.removed:
            require(self.install_acknowledged and self.ownership is not None,
                    "installation failed or ownership unknown: do not delete same-name table")
            self.validate_snapshot(self.snapshot())
            self.command(["/usr/sbin/nft", "delete", "table", "ip", "handle", str(self.ownership["table"])])
            raw = self.command(["/usr/sbin/nft", "-j", "list", "ruleset"])
            require(not any(item.get("table", {}).get("name") == self.table
                            and item.get("table", {}).get("family") == "ip"
                            for item in json.loads(raw)["nftables"]), "owned table remains")
            self.removed = True

    def cleanup(self) -> None:
        self.remove_owned_table()
        # Never unbind while queued packets exist. Failure requires supervisor recovery.
        self.backend.close_drained()
