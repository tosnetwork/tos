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
import math
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
    if re.match(r"/consensus/signing-ledger(?:\.[0-9A-Fa-f]{64})?/", rest):
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
        # Field 22 after the parenthesized command name, which may itself contain spaces.
        start_ticks = int(Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[19])
        status = Path(f"/proc/{pid}/status").read_text()
        names = os.listdir(f"/proc/{pid}/fd")
    except (OSError, ValueError, IndexError):
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
        if kind == "signing_ledger" and "/log." in target:
            ledger_logs += 1
    return {
        "start_ticks": start_ticks,
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


def sample_errors(meta: dict[str, Any], rows: list[dict[str, Any]]) -> list[str]:
    """Refuse incomplete measurements before averaging can hide a lost process."""
    roles = meta.get("roles")
    if (
        not isinstance(roles, dict)
        or sorted(roles.values()) != ["observer"] * 2 + ["validator"] * 4
    ):
        return ["expected inventory of four validators and two observers is missing"]
    duration, interval = meta.get("duration"), meta.get("interval")
    if (
        not isinstance(duration, (int, float))
        or not isinstance(interval, (int, float))
        or any(not math.isfinite(n) or n <= 0 for n in (duration, interval))
    ):
        return ["duration or sampling interval is missing or invalid"]
    if "ended_at" not in meta or len(rows) < 2:
        return ["run did not finish or has fewer than two samples"]
    identities: dict[str, tuple[int, int]] = {}
    previous = None
    for index, row in enumerate(rows):
        age = row.get("age")
        if not isinstance(age, (int, float)) or not math.isfinite(age) or age < 0:
            return [f"sample {index}: invalid age"]
        if (previous is None and age > interval) or (
            previous is not None and (age <= previous or age - previous > 2 * interval)
        ):
            return [f"sample {index}: missing or unordered samples"]
        previous = age
        nodes = row.get("nodes")
        if not isinstance(nodes, dict) or nodes.keys() != roles.keys():
            return [f"sample {index}: node inventory differs from the run metadata"]
        for name, role in roles.items():
            node = nodes[name]
            if not isinstance(node, dict) or node.get("role") != role:
                return [f"sample {index}: {name} is missing or has the wrong role"]
            for field in (
                "pid",
                "start_ticks",
                "rss_bytes",
                "fds",
                "live_sessions",
                "signing_ledger_log_fds",
            ):
                value = node.get(field)
                minimum = 1 if field in ("pid", "start_ticks", "rss_bytes", "fds") else 0
                if type(value) is not int or value < minimum:
                    return [f"sample {index}: {name} has no valid {field}"]
            classes = node.get("classes")
            if (
                not isinstance(classes, dict)
                or not classes
                or any(type(n) is not int or n < 0 for n in classes.values())
            ):
                return [f"sample {index}: {name} has no complete fd census"]
            identity = (node["pid"], node["start_ticks"])
            if name in identities and identities[name] != identity:
                return [f"sample {index}: {name} restarted during the run"]
            identities[name] = identity
    if rows[-1]["age"] < duration:
        return ["samples end before the requested run duration"]
    return []


def compare(off_dir: Path, on_dir: Path) -> dict[str, Any]:
    off_meta, off = load(off_dir)
    on_meta, on = load(on_dir)
    errors = {"off": sample_errors(off_meta, off), "on": sample_errors(on_meta, on)}
    if any(errors.values()):
        return {"passed": False, "sample_errors": errors}
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
        "sample_errors": errors,
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
