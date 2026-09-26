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
        self.adapter, self.backend, self.ledger = adapter, backend, ledger
        self.attempted = False
        self.preflight_done = False

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
        lines = [f"create table {prefix}",
                 f"add chain {prefix} enqueue {{ type filter hook output priority 0; policy accept; }}",
                 f"add chain {prefix} afterq {{ type filter hook output priority 10; policy accept; }}"]
        queues = {direction: queue for queue, direction in self.backend.queues.items()}
        for ordinal, direction in enumerate(DIRECTIONS):
            src, sport, dst, dport = self.adapter.endpoints[direction]
            match = f"ip saddr {src} ip daddr {dst} udp sport {sport} udp dport {dport}"
            lines.append(f'add rule {prefix} enqueue {match} counter queue to {queues[direction]} comment "entry{ordinal}"')
            lines.append(f'add rule {prefix} afterq {match} counter comment "post{ordinal}"')
        return ("\n".join(lines) + "\n").encode("ascii")

    def install(self) -> None:
        require(self.preflight_done and not self.attempted, "installation cannot repeat")
        raw = self.script()
        self.attempted = True
        self.command(["/usr/sbin/nft", "-f", "-"], raw)

    def counters_quiescent(self) -> dict:
        """Read kernel counters; exact comparison needs independently proven idle senders."""
        self.backend.health(require_empty=True)
        raw = self.command(["/usr/sbin/nft", "-j", "list", "table", "ip", self.table])
        counts = {}
        for item in json.loads(raw)["nftables"]:
            rule = item.get("rule")
            if rule is None:
                continue
            require(rule.get("table") == self.table and rule.get("family") == "ip",
                    "unexpected rule identity")
            label = rule.get("comment")
            require(isinstance(label, str) and re.fullmatch(r"(entry|post)([0-9]|1[0-9]|2[0-3])", label)
                    is not None and label not in counts, "counter identity differs")
            counter = [expr["counter"] for expr in rule["expr"] if "counter" in expr]
            require(len(counter) == 1 and isinstance(counter[0], dict)
                    and type(counter[0].get("packets")) is int
                    and counter[0]["packets"] >= 0, "missing kernel packet counter")
            counts[label] = counter[0]
        require(len(counts) == 48, "missing direction counter")
        # A second queue-empty witness narrows but does not prove sender quiescence.
        self.backend.health(require_empty=True)
        return counts

    def cleanup(self) -> None:
        require(self.preflight_done, "cannot delete table without ownership preflight")
        if self.attempted:
            self.command(["/usr/sbin/nft", "delete", "table", "ip", self.table])
            raw = self.command(["/usr/sbin/nft", "-j", "list", "ruleset"])
            require(not any(item.get("table", {}).get("name") == self.table
                            and item.get("table", {}).get("family") == "ip"
                            for item in json.loads(raw)["nftables"]), "owned table remains")
        # Never unbind while queued packets exist. Failure requires supervisor recovery.
        self.backend.close_drained()
