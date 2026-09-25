#!/usr/bin/env python3
"""Read-only F01 comparison of per-validator masterchain finalization logs.

The transition height and set digests must come from separately retained raw
ConfigParam 34 evidence. This checker does not infer a set change from height.
"""

import argparse
from bisect import bisect_left
import hashlib
import json
import re
from pathlib import Path


FINALIZED = re.compile(
    r"BlockFinalizedInMasterchain.*?"
    r"\{block=\(-1,8000000000000000,(?P<height>\d+)\):"
    r"(?P<root>[0-9A-Fa-f]{64}):(?P<file>[0-9A-Fa-f]{64})\}"
)
STAMP = re.compile(r"\[(?P<stamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\]")


def require_nonzero_hashes(root_hash: str, file_hash: str) -> None:
    for value in (root_hash, file_hash):
        if not isinstance(value, str) or re.fullmatch(r"[0-9A-Fa-f]{64}", value) is None:
            raise ValueError("finalized root/file hash is malformed")
        if int(value, 16) == 0:
            raise ValueError("finalized BlockIdExt has zero root/file hash")


def extract(path: Path) -> tuple[list[dict], str]:
    raw = path.read_bytes()
    events = []
    for line_number, line in enumerate(raw.decode(errors="replace").splitlines(), 1):
        match = FINALIZED.search(line)
        if match is None:
            continue
        require_nonzero_hashes(match["root"], match["file"])
        stamp = STAMP.search(line)
        if stamp is None:
            raise ValueError(f"{path}:{line_number}: finalization has no host timestamp")
        events.append({
            "height": int(match["height"]),
            "id": (-1, "8000000000000000", int(match["height"]),
                   match["root"].lower(), match["file"].lower()),
            "at": stamp["stamp"], "line": line_number,
        })
    if not events:
        raise ValueError(f"{path}: no BlockFinalizedInMasterchain full IDs")
    return events, hashlib.sha256(raw).hexdigest()


def evaluate(nodes: dict[str, list[dict]], transition_height: int,
             before_set: str, after_set: str) -> dict:
    if len(nodes) < 4 or transition_height < 1:
        raise ValueError("F01 needs at least four validator logs and a positive transition height")
    if (not all(re.fullmatch(r"[0-9a-f]{64}", value) and int(value, 16) != 0
                for value in (before_set, after_set)) or before_set == after_set):
        raise ValueError("F01 needs two distinct raw ConfigParam 34 set digests")
    by_node = {}
    timeline = []
    for node, events in nodes.items():
        if not events:
            raise ValueError(f"{node}: empty finalization log")
        seen = {}
        for event in events:
            height, block_id = event["height"], tuple(event["id"])
            if (len(block_id) != 5 or block_id[0] != -1
                    or block_id[1] != "8000000000000000"
                    or block_id[2] != height or height < 0):
                raise ValueError(f"{node}: finalized BlockIdExt is malformed")
            require_nonzero_hashes(block_id[3], block_id[4])
            if height in seen and seen[height] != block_id:
                raise ValueError(f"{node}: conflicting finalized IDs at height {height}")
            seen[height] = block_id
            timeline.append((event["at"], node, height))
        by_node[node] = seen
    common = set.intersection(*(set(rows) for rows in by_node.values()))
    if not {transition_height - 1, transition_height, transition_height + 1} <= common:
        raise ValueError("absent all-node common-height IDs around set change")
    checked = sorted(common)
    if checked != list(range(checked[0], checked[-1] + 1)):
        raise ValueError("common-height finalization evidence has a gap")
    for height in checked:
        ids = {rows[height] for rows in by_node.values()}
        if len(ids) != 1:
            raise ValueError(f"conflicting finalized full BlockIdExt at height {height}")

    # On this single host, log timestamps order per-node observations. A lag
    # is caught up only when that same node later finalizes the then-known tip.
    tips = {node: -1 for node in nodes}
    progress = {node: [] for node in nodes}
    lag_events = []
    for at, node, height in sorted(timeline):
        if height > tips[node]:
            tips[node] = height
            progress[node].append((height, at))
        maximum = max(tips.values())
        if all(value >= 0 for value in tips.values()):
            for lagged, current in tips.items():
                if current < maximum:
                    lag_events.append({"at": at, "node": lagged,
                                       "height": current, "target": maximum,
                                       "lag_blocks": maximum - current})
    progress_heights = {
        node: [height for height, _ in advances] for node, advances in progress.items()
    }
    for lag in lag_events:
        advances = progress[lag["node"]]
        index = bisect_left(progress_heights[lag["node"]], lag["target"])
        lag["caught_up"] = index < len(advances) and advances[index][1] >= lag["at"]
    if any(not lag["caught_up"] for lag in lag_events):
        raise ValueError("one or more observed validator lags never caught up")
    return {
        "schema": "tos.f01.finalized-id-check.v1", "passed": True,
        "transition_height": transition_height,
        "before_set_sha256": before_set, "after_set_sha256": after_set,
        "nodes": sorted(nodes), "checked_heights": checked,
        "common_height_count": len(checked),
        "final_node_heights": tips, "lag_events": lag_events,
        "max_lag_blocks": max((item["lag_blocks"] for item in lag_events), default=0),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-log", action="append", required=True, metavar="NAME=PATH")
    parser.add_argument("--transition-height", type=int, required=True)
    parser.add_argument("--before-set", required=True, help="raw pre-change ConfigParam 34 cell SHA-256")
    parser.add_argument("--after-set", required=True, help="raw post-change ConfigParam 34 cell SHA-256")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    nodes = {}
    sources = {}
    paths = set()
    file_ids = set()
    digests = set()
    for entry in args.node_log:
        if "=" not in entry:
            parser.error("--node-log must be NAME=PATH")
        name, filename = entry.split("=", 1)
        if not name or name in nodes:
            parser.error("node names must be nonempty and unique")
        path = Path(filename)
        resolved = path.resolve(strict=True)
        stat = resolved.stat()
        file_id = (stat.st_dev, stat.st_ino)
        if resolved in paths or file_id in file_ids:
            raise ValueError("F01 node logs alias one raw file")
        events, digest = extract(path)
        if digest in digests:
            raise ValueError("F01 node logs have duplicate raw SHA-256")
        paths.add(resolved)
        file_ids.add(file_id)
        digests.add(digest)
        nodes[name], sources[name] = events, digest
    report = evaluate(nodes, args.transition_height, args.before_set, args.after_set)
    report["raw_node_log_sha256"] = sources
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
