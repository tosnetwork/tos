#!/usr/bin/env python3
"""Equal-duration soak of a disposable local chain, with per-process RSS and fd census.

LOCAL ONLY. Boots a DHT node, four PQ validators (genesis ceremony as the harness runs it)
and two observers of a disposable local chain (global id 3) in a new working directory on
--base-port, runs it for --duration seconds, and every --interval seconds records, for
every engine process of this chain:

  - RSS (VmRSS from /proc/<pid>/status);
  - a census of /proc/<pid>/fd, each descriptor classified by its readlink target:
      consensus_db       <db>/consensus/consensus.<session>/... (*.sst, LOG, MANIFEST, ...)
      signing_ledger     <db>/consensus/signing-ledger/log.* and the header
      archive            <db>/archive/...
      celldb             <db>/celldb/...
      db_<dir>           anything else under the node's directory, by its top-level directory
      socket, pipe, anon_inode, other
  - the number of live consensus sessions (distinct consensus.<session> directories with an
    open descriptor).

Run it once with a build without the log (OFF) and once with it (ON), one after the
other, so chain age matches. --compare OFF_DIR ON_DIR judges the pair:
  - ON - OFF RSS slope at matched age within +-10 MiB/h, per role (validator, observer);
  - signing_ledger log fds <= live consensus sessions + 1 at every ON sample;
  - no fd class whose count grows over the run in ON but not in OFF.
Exit 0 when all hold, 3 otherwise, 1 when the input cannot be read.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

SESSION_DIR = re.compile(r"/consensus/consensus\.([^/]+)/")
MIB = 1024 * 1024


def classify(target: str, node_dir: str) -> str:
    if target.startswith("socket:"):
        return "socket"
    if target.startswith("pipe:"):
        return "pipe"
    if target.startswith("anon_inode:"):
        return "anon_inode"
    if not target.startswith(node_dir + "/"):
        return "other"
    rest = target[len(node_dir) :]
    if rest.startswith("/consensus/signing-ledger/"):
        return "signing_ledger"
    if rest.startswith("/consensus/consensus."):
        return "consensus_db"
    if rest.startswith("/archive/"):
        return "archive"
    if rest.startswith("/celldb/"):
        return "celldb"
    # Any other database file, by its top-level directory under the node (files, state, ...).
    top = rest.strip("/").split("/", 1)[0]
    top = "dht" if top.startswith("dht-") else top
    return f"db_{top}" if top else "other_db"


def census(pid: int, node_dir: str) -> dict[str, Any] | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        names = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return None
    vm_rss = re.search(r"^VmRSS:\s+(\d+) kB", status, re.M)
    if vm_rss is None:
        return None
    rss_kib = int(vm_rss.group(1))
    classes: dict[str, int] = {}
    sessions: set[str] = set()
    ledger_logs = 0
    for name in names:
        try:
            target = os.readlink(f"/proc/{pid}/fd/{name}")
        except OSError:
            continue
        kind = classify(target, node_dir)
        classes[kind] = classes.get(kind, 0) + 1
        if m := SESSION_DIR.search(target):
            sessions.add(m.group(1))
        if kind == "signing_ledger" and "/signing-ledger/log." in target:
            ledger_logs += 1
    return {
        "rss_bytes": rss_kib * 1024,
        "fds": len(names),
        "classes": classes,
        "live_sessions": len(sessions),
        "signing_ledger_log_fds": ledger_logs,
    }


def engine_processes(node_dirs: dict[str, str]) -> dict[str, int]:
    """node name -> pid of the validator-engine whose command line names that node's directory."""
    found: dict[str, int] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            argv = Path(f"/proc/{entry}/cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if not argv or not argv[0].endswith(b"validator-engine"):
            continue
        text = [a.decode(errors="replace") for a in argv]
        for name, directory in node_dirs.items():
            if any(a == directory or a.startswith(directory + "/") for a in text):
                found[name] = int(entry)
    return found


async def run(args: argparse.Namespace) -> int:
    from tostester.install import Install
    from tostester.network import Network

    working_dir = args.working_dir.resolve()
    working_dir.mkdir(parents=True, exist_ok=False)
    install = Install(args.build.resolve(), args.source.resolve())
    install.toslibjson.client_set_verbosity_level(1)
    samples_path = working_dir / "samples.jsonl"
    meta: dict[str, Any] = {
        "build": str(args.build.resolve()),
        "label": args.label,
        "base_port": args.base_port,
        "duration": args.duration,
        "interval": args.interval,
    }
    async with Network(install, working_dir, base_port=args.base_port) as network:
        config = network.config
        config.auth_network_tag = hashlib.sha256(
            f"TOS-AUTH-NETWORK-TAG-v1;network=signing-soak;global_id=3;epoch={int(time.time())}".encode()
        ).digest()
        config.shard_validators = 4
        dht = network.create_dht_node()
        roles: dict[str, str] = {}
        nodes = []
        for index in range(4):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"soak-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"soak-validator-seed-{index}".encode()).digest(),
            )
            node.announce_to(dht)
            nodes.append(node)
            roles[node.directory.name] = "validator"
        for _ in range(2):
            node = network.create_full_node()
            node._local_config.validators = []  # pyright: ignore[reportPrivateUsage]
            node.announce_to(dht)
            nodes.append(node)
            roles[node.directory.name] = "observer"
        async with asyncio.TaskGroup() as group:
            group.create_task(dht.run())
            for node in nodes:
                group.create_task(node.run())
        started = time.time()
        meta["started_at"] = started
        meta["roles"] = roles
        (working_dir / "soak-meta.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n"
        )
        node_dirs = {n.directory.name: str(n.directory.resolve()) for n in nodes}
        while True:
            now = time.time()
            pids = engine_processes(node_dirs)
            row: dict[str, Any] = {"at": now, "age": now - started, "nodes": {}}
            for name, directory in node_dirs.items():
                pid = pids.get(name)
                row["nodes"][name] = (
                    {"role": roles[name], "pid": pid, **(census(pid, directory) or {})}
                    if pid
                    else None
                )
            with samples_path.open("a") as out:
                out.write(json.dumps(row, sort_keys=True) + "\n")
            if now - started >= args.duration:
                break
            await asyncio.sleep(max(1.0, args.interval - (time.time() - now)))
        meta["ended_at"] = time.time()
        (working_dir / "soak-meta.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n"
        )
    return 0


def load(directory: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    meta = json.loads((directory / "soak-meta.json").read_text())
    rows = [
        json.loads(x) for x in (directory / "samples.jsonl").read_text().splitlines() if x.strip()
    ]
    return meta, rows


def slope(points: list[tuple[float, float]]) -> float | None:
    """Least-squares slope, units of y per unit of x."""
    if len(points) < 2:
        return None
    n = len(points)
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    den = sum((x - mx) ** 2 for x, _ in points)
    if den == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in points) / den


def role_series(rows: list[dict[str, Any]], role: str, field: str) -> list[tuple[float, float]]:
    """Mean of `field` over the live processes of `role`, against chain age in hours."""
    out = []
    for row in rows:
        values = [
            n[field] for n in row["nodes"].values() if n and n.get("role") == role and field in n
        ]
        if values:
            out.append((row["age"] / 3600.0, sum(values) / len(values)))
    return out


def class_series(rows: list[dict[str, Any]], kind: str) -> list[tuple[float, float]]:
    out = []
    for row in rows:
        total = sum((n.get("classes") or {}).get(kind, 0) for n in row["nodes"].values() if n)
        out.append((row["age"] / 3600.0, float(total)))
    return out


def compare(off_dir: Path, on_dir: Path) -> dict[str, Any]:
    _, off = load(off_dir)
    _, on = load(on_dir)
    horizon = min(off[-1]["age"], on[-1]["age"]) if off and on else 0
    off = [r for r in off if r["age"] <= horizon]
    on = [r for r in on if r["age"] <= horizon]
    rss = {}
    for role in ("validator", "observer"):
        s_off = slope(role_series(off, role, "rss_bytes"))
        s_on = slope(role_series(on, role, "rss_bytes"))
        diff = None if s_off is None or s_on is None else (s_on - s_off) / MIB
        rss[role] = {
            "off_mib_per_h": None if s_off is None else s_off / MIB,
            "on_mib_per_h": None if s_on is None else s_on / MIB,
            "on_minus_off_mib_per_h": diff,
            "within_10_mib_per_h": diff is not None and abs(diff) <= 10.0,
        }
    ledger_violations = [
        {
            "age": r["age"],
            "node": name,
            "ledger_log_fds": n["signing_ledger_log_fds"],
            "sessions": n["live_sessions"],
        }
        for r in on
        for name, n in r["nodes"].items()
        if n and n.get("signing_ledger_log_fds", 0) > n.get("live_sessions", 0) + 1
    ]
    kinds = sorted(
        {k for r in off + on for n in r["nodes"].values() if n for k in (n.get("classes") or {})}
    )
    growth = {}
    for kind in kinds:
        s_off = slope(class_series(off, kind))
        s_on = slope(class_series(on, kind))
        growth[kind] = {"off_per_h": s_off, "on_per_h": s_on}
    # A class grows "only in ON" when its ON slope is clearly positive (more than one fd per
    # hour per process) and its OFF slope is not.
    only_on = [
        k
        for k, g in growth.items()
        if g["on_per_h"] is not None
        and g["on_per_h"] > 6.0
        and (g["off_per_h"] is None or g["off_per_h"] <= 6.0)
    ]
    return {
        "matched_age_hours": horizon / 3600.0,
        "samples": {"off": len(off), "on": len(on)},
        "rss": rss,
        "signing_ledger_log_fd_violations": ledger_violations,
        "fd_class_growth": growth,
        "fd_classes_growing_only_in_on": only_on,
        "passed": all(v["within_10_mib_per_h"] for v in rss.values())
        and not ledger_violations
        and not only_on,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("OFF_DIR", "ON_DIR"))
    parser.add_argument("--build", type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--working-dir", type=Path)
    parser.add_argument("--label", default="")
    parser.add_argument("--base-port", type=int, default=34700)
    parser.add_argument("--duration", type=int, default=7200)
    parser.add_argument("--interval", type=int, default=300)
    args = parser.parse_args()
    if args.compare:
        try:
            verdict = compare(*args.compare)
        except (OSError, ValueError, KeyError) as error:
            print(f"SOAK_FAILED cannot read the runs: {error}", file=sys.stderr)
            return 1
        (args.compare[1] / "soak-verdict.json").write_text(
            json.dumps(verdict, indent=2, sort_keys=True) + "\n"
        )
        print(json.dumps(verdict, indent=2, sort_keys=True))
        return 0 if verdict["passed"] else 3
    if args.build is None or args.working_dir is None:
        parser.error("--build and --working-dir are required for a run")
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
