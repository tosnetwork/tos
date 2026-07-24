#!/usr/bin/env python3
"""Monitor a local or multi-region Simplex2 network and produce a hard verdict.

The default duration is 72 hours.  A shorter duration is useful for validating
the harness, but is explicitly marked as ineligible for the release gate.

Local example:

    python3 scripts/simplex2-soak.py --local-systemd-nodes 3

Multi-region example:

    python3 scripts/simplex2-soak.py --inventory doc/examples/simplex2-soak-inventory.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MC_FINALIZED = re.compile(
    r"BlockFinalizedInMasterchain.*?"
    r"\{block=\(-1,8000000000000000,(?P<seqno>\d+)\):"
    r"(?P<root>[0-9A-Fa-f]{64}):(?P<file>[0-9A-Fa-f]{64})\}"
)
FATAL = re.compile(
    r"\b(FATAL|PANIC|CHECK failed|LOG_CHECK failed|AddressSanitizer|"
    r"UndefinedBehaviorSanitizer|Segmentation fault|core dumped)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Node:
    name: str
    service: str
    region: str
    host: str | None = None
    data_dir: str | None = None
    ssh_options: tuple[str, ...] = ()
    netem: dict[str, Any] | None = None


class Runner:
    def __init__(self, node: Node):
        self.node = node

    def run(self, command: str, timeout: float = 30.0) -> str:
        if self.node.host:
            argv = [
                "ssh",
                "-o",
                "BatchMode=yes",
                *self.node.ssh_options,
                self.node.host,
                "bash",
                "-lc",
                shlex.quote(command),
            ]
        else:
            argv = ["bash", "-lc", command]
        result = subprocess.run(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"{self.node.name}: command failed ({result.returncode}): "
                f"{command}\n{result.stdout[-2000:]}"
            )
        return result.stdout


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--inventory", type=Path)
    source.add_argument("--local-systemd-nodes", type=int)
    parser.add_argument("--duration", type=float, default=72 * 60 * 60)
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument(
        "--disk-interval",
        type=float,
        default=300.0,
        help="seconds between recursive disk measurements (default: 300)",
    )
    parser.add_argument("--journal-lines", type=int, default=8000)
    parser.add_argument("--stall-seconds", type=float, default=120.0)
    parser.add_argument("--max-height-spread", type=int, default=20)
    parser.add_argument(
        "--height-spread-grace",
        type=float,
        default=30.0,
        help="seconds a height spread may exceed its limit before failure",
    )
    parser.add_argument("--max-rss-gib", type=float, default=48.0)
    parser.add_argument("--max-disk-gib", type=float, default=500.0)
    parser.add_argument("--max-rss-growth-gib-per-hour", type=float, default=1.0)
    parser.add_argument("--max-disk-growth-gib-per-hour", type=float, default=10.0)
    parser.add_argument(
        "--min-growth-window",
        type=float,
        default=3600.0,
        help="minimum elapsed seconds before growth-rate limits are enforced",
    )
    parser.add_argument(
        "--restart-interval",
        type=float,
        default=0.0,
        help="rolling systemd restart interval; zero disables restarts",
    )
    parser.add_argument(
        "--apply-netem",
        action="store_true",
        help="apply inventory netem settings and remove them on exit",
    )
    parser.add_argument("--artifact-dir", type=Path)
    return parser.parse_args()


def _load_nodes(args: argparse.Namespace) -> list[Node]:
    if args.local_systemd_nodes is not None:
        if args.local_systemd_nodes < 1:
            raise ValueError("--local-systemd-nodes must be positive")
        return [
            Node(
                name=f"validator-{index}",
                service=f"tos-validator@{index}",
                region="local",
            )
            for index in range(1, args.local_systemd_nodes + 1)
        ]

    raw = json.loads(args.inventory.read_text())
    items = raw.get("nodes")
    if not isinstance(items, list) or not items:
        raise ValueError("inventory must contain a non-empty nodes array")
    nodes = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("every inventory node must be an object")
        nodes.append(
            Node(
                name=str(item["name"]),
                service=str(item["service"]),
                region=str(item["region"]),
                host=str(item["host"]) if item.get("host") else None,
                data_dir=str(item["data_dir"]) if item.get("data_dir") else None,
                ssh_options=tuple(str(value) for value in item.get("ssh_options", [])),
                netem=item.get("netem"),
            )
        )
    if len({node.name for node in nodes}) != len(nodes):
        raise ValueError("inventory node names must be unique")
    return nodes


def _artifact_dir(repo: Path, requested: Path | None) -> Path:
    if requested is None:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        requested = repo / "build/simplex2-soak" / stamp
    requested.mkdir(parents=True, exist_ok=False)
    return requested


def _systemctl_value(runner: Runner, service: str, key: str) -> str:
    command = (
        f"systemctl show {shlex.quote(service)} "
        f"--property={shlex.quote(key)} --value"
    )
    return runner.run(command).strip()


def _discover_data_dir(runner: Runner, node: Node) -> str:
    if node.data_dir:
        return node.data_dir
    value = _systemctl_value(runner, node.service, "WorkingDirectory")
    if not value:
        raise RuntimeError(f"{node.name}: service has no WorkingDirectory")
    return value


def _finalized_blocks(text: str) -> dict[int, str]:
    result: dict[int, str] = {}
    for match in MC_FINALIZED.finditer(text):
        result[int(match.group("seqno"))] = (
            match.group("root").upper() + ":" + match.group("file").upper()
        )
    return result


def _sample_node(
    runner: Runner,
    node: Node,
    data_dir: str,
    journal_lines: int,
    previous_disk_bytes: int | None,
    measure_disk: bool,
) -> tuple[dict[str, Any], dict[int, str]]:
    active = runner.run(
        f"systemctl is-active {shlex.quote(node.service)}"
    ).strip()
    pid_text = _systemctl_value(runner, node.service, "MainPID")
    restarts_text = _systemctl_value(runner, node.service, "NRestarts")
    pid = int(pid_text or "0")
    rss_kib = 0
    if pid > 0:
        rss_output = runner.run(
            f"ps -o rss= -p {pid} | tr -d ' '", timeout=10
        ).strip()
        rss_kib = int(rss_output or "0")
    disk_bytes = previous_disk_bytes
    if measure_disk or disk_bytes is None:
        disk_bytes = int(
            runner.run(
                f"du -sb -- {shlex.quote(data_dir)} | awk '{{print $1}}'",
                timeout=120,
            )
            .strip()
            .splitlines()[-1]
        )
    journal = runner.run(
        f"journalctl -u {shlex.quote(node.service)} -n {journal_lines} "
        "--no-pager -o cat",
        timeout=60,
    )
    blocks = _finalized_blocks(journal)
    height = max(blocks, default=-1)
    return (
        {
            "active": active,
            "pid": pid,
            "restarts": int(restarts_text or "0"),
            "rss_bytes": rss_kib * 1024,
            "disk_bytes": int(disk_bytes),
            "height": height,
            "latest_hash": blocks.get(height, ""),
        },
        blocks,
    )


def _growth_per_hour(
    samples: list[dict[str, Any]], node: str, field: str
) -> float:
    points = [
        (float(sample["elapsed_seconds"]), float(sample["nodes"][node][field]))
        for sample in samples
        if node in sample["nodes"] and sample["nodes"][node].get(field) is not None
    ]
    if len(points) < 2 or points[-1][0] <= points[0][0]:
        return 0.0
    elapsed_hours = (points[-1][0] - points[0][0]) / 3600.0
    return (points[-1][1] - points[0][1]) / (1024**3) / elapsed_hours


def _netem_command(settings: dict[str, Any], action: str) -> str:
    interface = str(settings["interface"])
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", interface):
        raise ValueError(f"unsafe netem interface {interface!r}")
    if action == "delete":
        return f"sudo -n tc qdisc del dev {shlex.quote(interface)} root"
    delay = float(settings.get("delay_ms", 0))
    jitter = float(settings.get("jitter_ms", 0))
    loss = float(settings.get("loss_percent", 0))
    rate = float(settings.get("rate_mbit", 0))
    if min(delay, jitter, loss, rate) < 0 or loss > 100:
        raise ValueError(f"invalid netem settings for {interface}")
    parts = [
        "sudo",
        "-n",
        "tc",
        "qdisc",
        "replace",
        "dev",
        shlex.quote(interface),
        "root",
        "netem",
    ]
    if delay or jitter:
        parts += ["delay", f"{delay:g}ms", f"{jitter:g}ms"]
    if loss:
        parts += ["loss", f"{loss:g}%"]
    if rate:
        parts += ["rate", f"{rate:g}mbit"]
    return " ".join(parts)


def _write_csv(path: Path, samples: list[dict[str, Any]], nodes: list[Node]) -> None:
    with path.open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                "utc",
                "elapsed_seconds",
                "node",
                "region",
                "active",
                "height",
                "latest_hash",
                "rss_bytes",
                "disk_bytes",
                "restarts",
            ]
        )
        for sample in samples:
            for node in nodes:
                value = sample["nodes"].get(node.name, {})
                writer.writerow(
                    [
                        sample["utc"],
                        sample["elapsed_seconds"],
                        node.name,
                        node.region,
                        value.get("active", "ERROR"),
                        value.get("height", -1),
                        value.get("latest_hash", ""),
                        value.get("rss_bytes", -1),
                        value.get("disk_bytes", -1),
                        value.get("restarts", -1),
                    ]
                )


def main() -> int:
    args = _args()
    if (
        args.duration <= 0
        or args.interval <= 0
        or args.disk_interval <= 0
        or args.min_growth_window < 0
        or args.height_spread_grace < 0
    ):
        raise ValueError(
            "duration, interval, and disk interval must be positive; "
            "minimum growth window must be non-negative"
        )
    repo = Path(__file__).resolve().parents[1]
    nodes = _load_nodes(args)
    runners = {node.name: Runner(node) for node in nodes}
    artifact = _artifact_dir(repo, args.artifact_dir)
    started_epoch = int(time.time())
    started_monotonic = time.monotonic()
    deadline = started_monotonic + args.duration
    data_dirs: dict[str, str] = {}
    samples: list[dict[str, Any]] = []
    failures: list[str] = []
    observed: dict[str, dict[int, str]] = {node.name: {} for node in nodes}
    last_progress_at: dict[str, float] = {
        node.name: started_monotonic for node in nodes
    }
    last_height: dict[str, int] = {node.name: -1 for node in nodes}
    disk_bytes: dict[str, int | None] = {node.name: None for node in nodes}
    next_disk_sample = started_monotonic
    height_spread_exceeded_at: float | None = None
    applied_netem: list[Node] = []
    next_restart = (
        started_monotonic + args.restart_interval
        if args.restart_interval > 0
        else math.inf
    )
    restart_index = 0

    metadata = {
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_seconds": args.duration,
        "interval_seconds": args.interval,
        "disk_interval_seconds": args.disk_interval,
        "minimum_growth_window_seconds": args.min_growth_window,
        "height_spread_grace_seconds": args.height_spread_grace,
        "nodes": [node.__dict__ for node in nodes],
        "git_commit": subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip(),
    }
    (artifact / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

    try:
        for node in nodes:
            runner = runners[node.name]
            data_dirs[node.name] = _discover_data_dir(runner, node)
            if args.apply_netem and node.netem:
                runner.run(_netem_command(node.netem, "replace"))
                applied_netem.append(node)

        while True:
            now = time.monotonic()
            measure_disk = now >= next_disk_sample
            sample: dict[str, Any] = {
                "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "elapsed_seconds": round(now - started_monotonic, 3),
                "nodes": {},
            }
            for node in nodes:
                try:
                    value, blocks = _sample_node(
                        runners[node.name],
                        node,
                        data_dirs[node.name],
                        args.journal_lines,
                        disk_bytes[node.name],
                        measure_disk,
                    )
                    sample["nodes"][node.name] = value
                    disk_bytes[node.name] = value["disk_bytes"]
                    observed[node.name].update(blocks)
                    if value["height"] > last_height[node.name]:
                        last_height[node.name] = value["height"]
                        last_progress_at[node.name] = now
                    if value["active"] != "active":
                        failures.append(
                            f"{sample['utc']} {node.name} service={value['active']}"
                        )
                    if value["rss_bytes"] > args.max_rss_gib * 1024**3:
                        failures.append(
                            f"{sample['utc']} {node.name} RSS exceeded "
                            f"{args.max_rss_gib:g} GiB"
                        )
                    if value["disk_bytes"] > args.max_disk_gib * 1024**3:
                        failures.append(
                            f"{sample['utc']} {node.name} disk exceeded "
                            f"{args.max_disk_gib:g} GiB"
                        )
                    if now - last_progress_at[node.name] > args.stall_seconds:
                        failures.append(
                            f"{sample['utc']} {node.name} made no finalized "
                            f"progress for {now - last_progress_at[node.name]:.1f}s"
                        )
                except (RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
                    sample["nodes"][node.name] = {"error": str(error)}
                    failures.append(f"{sample['utc']} {error}")

            heights = [
                value["height"]
                for value in sample["nodes"].values()
                if isinstance(value, dict) and value.get("height", -1) >= 0
            ]
            if len(heights) == len(nodes):
                spread = max(heights) - min(heights)
                sample["height_spread"] = spread
                if spread > args.max_height_spread:
                    if height_spread_exceeded_at is None:
                        height_spread_exceeded_at = now
                    sample["height_spread_exceeded_seconds"] = round(
                        now - height_spread_exceeded_at, 3
                    )
                    if (
                        now - height_spread_exceeded_at
                        >= args.height_spread_grace
                    ):
                        failures.append(
                            f"{sample['utc']} height spread exceeded "
                            f"{args.max_height_spread} for "
                            f"{now - height_spread_exceeded_at:.1f}s: {heights}"
                        )
                else:
                    height_spread_exceeded_at = None

            common_heights = set.intersection(
                *(set(observed[node.name]) for node in nodes)
            )
            if common_heights:
                common_height = max(common_heights)
                hashes = {
                    observed[node.name][common_height] for node in nodes
                }
                sample["common_height"] = common_height
                sample["common_hashes"] = sorted(hashes)
                if len(hashes) != 1:
                    failures.append(
                        f"{sample['utc']} finalized divergence at "
                        f"masterchain height {common_height}: {sorted(hashes)}"
                    )
                # Each journal query overlaps the preceding one. Retain a
                # small overlap instead of accumulating every finalized hash
                # for the full 72-hour run.
                prune_below = max(0, common_height - 64)
                for node in nodes:
                    observed[node.name] = {
                        height: block_hash
                        for height, block_hash in observed[node.name].items()
                        if height >= prune_below
                    }

            samples.append(sample)
            with (artifact / "samples.jsonl").open("a") as file:
                file.write(json.dumps(sample, sort_keys=True) + "\n")
            _write_csv(artifact / "samples.csv", samples, nodes)
            if measure_disk:
                next_disk_sample = now + args.disk_interval

            if now >= next_restart:
                node = nodes[restart_index % len(nodes)]
                runners[node.name].run(
                    f"sudo -n systemctl restart {shlex.quote(node.service)}",
                    timeout=60,
                )
                restart_index += 1
                next_restart = now + args.restart_interval

            if now >= deadline:
                break
            time.sleep(min(args.interval, max(0.0, deadline - time.monotonic())))
    finally:
        for node in reversed(applied_netem):
            try:
                runners[node.name].run(
                    _netem_command(node.netem or {}, "delete"), timeout=30
                )
            except RuntimeError as error:
                failures.append(f"netem cleanup failed: {error}")

    fatal_evidence: dict[str, list[str]] = {}
    for node in nodes:
        try:
            journal = runners[node.name].run(
                f"journalctl -u {shlex.quote(node.service)} "
                f"--since '@{started_epoch}' --no-pager -o cat",
                timeout=180,
            )
            lines = [line[:2000] for line in journal.splitlines() if FATAL.search(line)]
            fatal_evidence[node.name] = lines
            if lines:
                failures.append(
                    f"{node.name} emitted {len(lines)} fatal diagnostics"
                )
            (artifact / f"{node.name}.fatal.log").write_text("\n".join(lines) + "\n")
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            failures.append(f"failed to collect final journal for {node.name}: {error}")

    growth: dict[str, dict[str, float]] = {}
    elapsed = time.monotonic() - started_monotonic
    enforce_growth_limits = elapsed >= args.min_growth_window
    for node in nodes:
        rss = _growth_per_hour(samples, node.name, "rss_bytes")
        disk = _growth_per_hour(samples, node.name, "disk_bytes")
        growth[node.name] = {
            "rss_gib_per_hour": rss,
            "disk_gib_per_hour": disk,
        }
        if enforce_growth_limits and rss > args.max_rss_growth_gib_per_hour:
            failures.append(
                f"{node.name} RSS growth {rss:.3f} GiB/h exceeded "
                f"{args.max_rss_growth_gib_per_hour:.3f}"
            )
        if enforce_growth_limits and disk > args.max_disk_growth_gib_per_hour:
            failures.append(
                f"{node.name} disk growth {disk:.3f} GiB/h exceeded "
                f"{args.max_disk_growth_gib_per_hour:.3f}"
            )

    regions = sorted({node.region for node in nodes})
    release_gate_eligible = elapsed >= 72 * 60 * 60 and len(regions) >= 2
    failures = list(dict.fromkeys(failures))
    release_gate_ineligibility_reasons: list[str] = []
    if elapsed < 72 * 60 * 60:
        release_gate_ineligibility_reasons.append(
            f"elapsed {elapsed:.1f}s is shorter than 72 hours"
        )
    if len(regions) < 2:
        release_gate_ineligibility_reasons.append(
            f"observed only {len(regions)} region(s)"
        )
    summary = {
        "verdict": "PASS" if not failures else "FAIL",
        "release_gate_eligible": release_gate_eligible,
        "release_gate_ineligibility_reasons": release_gate_ineligibility_reasons,
        "ended_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(elapsed, 3),
        "sample_count": len(samples),
        "regions": regions,
        "growth_limits_enforced": enforce_growth_limits,
        "growth": growth,
        "failures": failures,
        "artifact_dir": str(artifact),
    }
    (artifact / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2) from error
