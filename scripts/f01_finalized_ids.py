#!/usr/bin/env python3
"""Read-only F01 comparison of per-validator masterchain finalization logs.

The transition height and set digests must come from separately retained raw
ConfigParam 34 evidence. This checker does not infer a set change from height.
"""

import argparse
import base64
from bisect import bisect_left
import hashlib
import json
import re
from pathlib import Path

from pytosiq_core import Cell


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


def rpc_block_id(value: dict) -> tuple[int, str, int, str, str]:
    """Re-derive the full ID from a raw JSON-RPC header, not a manifest label."""
    if not isinstance(value, dict):
        raise ValueError("F01 raw header has no block ID")
    try:
        root = base64.b64decode(value["root_hash"], validate=True)
        file_hash = base64.b64decode(value["file_hash"], validate=True)
        workchain, shard, height = (int(value[field]) for field in
                                    ("workchain", "shard", "seqno"))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("F01 raw header block ID is malformed") from error
    if (workchain != -1 or shard != -(1 << 63) or height < 0
            or len(root) != 32 or len(file_hash) != 32):
        raise ValueError("F01 raw header is not a full masterchain BlockIdExt")
    require_nonzero_hashes(root.hex(), file_hash.hex())
    return workchain, "8000000000000000", height, root.hex(), file_hash.hex()


def names_predecessor(header: dict, block_id: tuple) -> bool:
    previous = header.get("prev_blocks")
    return (isinstance(previous, list) and len(previous) == 1
            and rpc_block_id(previous[0]) == block_id)


def raw_header_facts(raw_rows: dict, nodes: dict) -> dict:
    """Derive coverage exceptions from agreeing headers bound to all four native logs."""
    flags: dict[int, bool] = {}
    preceding: dict[int, int] = {}
    ids: dict[int, tuple] = {}
    headers: dict[int, dict[str, list[dict]]] = {}
    for (name, method, height), responses in raw_rows.items():
        if method != "getBlockHeader":
            continue
        for response in responses:
            result = response["result"]
            block_id = rpc_block_id(result.get("id"))
            if block_id[2] != height:
                raise ValueError("F01 raw header ID is not the requested height")
            if ids.setdefault(height, block_id) != block_id:
                raise ValueError(f"F01 raw header differs: validators disagree on the full block ID at {height}")
            headers.setdefault(height, {}).setdefault(name, []).append(result)
            if "is_key_block" in result:
                flag = result["is_key_block"]
                if type(flag) is not bool:
                    raise ValueError("F01 raw header is_key_block is not a boolean")
                if flags.setdefault(height, flag) != flag:
                    raise ValueError("F01 raw headers disagree on is_key_block")
            if "prev_key_block_seqno" in result:
                previous = result["prev_key_block_seqno"]
                if type(previous) is not int or not 0 <= previous < height:
                    raise ValueError("F01 raw header prev_key_block_seqno is invalid")
                if preceding.setdefault(height, previous) != previous:
                    raise ValueError("F01 raw headers disagree on prev_key_block_seqno")
    for previous in preceding.values():
        if flags.get(previous) is False:
            raise ValueError("F01 raw header names a non-key block as a key block")

    native = {}
    for name, events in nodes.items():
        for event in events:
            if event["height"] in headers:
                native.setdefault((name, event["height"]), set()).add(tuple(event["id"]))

    def anchored(name, height):
        marked = native.get((name, height))
        if marked:
            return marked == {ids[height]}
        successor = headers.get(height + 1, {}).get(name, [])
        return (all(row.get("is_key_block") is True for row in headers[height][name])
                and bool(successor) and native.get((name, height + 1)) == {ids[height + 1]}
                and all(names_predecessor(row, ids[height]) for row in successor))

    key, named = set(), set()
    for height, by_node in headers.items():
        if by_node.keys() != nodes.keys() or not all(anchored(name, height) for name in nodes):
            continue
        answers = [row for rows in by_node.values() for row in rows]
        if all(row.get("is_key_block") is True for row in answers):
            key.add(height)
        if all("prev_key_block_seqno" in row for row in answers):
            named.add(preceding[height])
    known_keys = sorted(key | named)
    for height, previous in preceding.items():
        index = bisect_left(known_keys, height)
        if index and previous < known_keys[index - 1]:
            raise ValueError("F01 raw header prev_key_block_seqno skips a known key block")
    return {"key": key, "named": named}


def rpc_config34_hash(response: dict) -> str:
    try:
        encoded = response["result"]["config"]["bytes"]
        cell = Cell.one_from_boc(base64.b64decode(encoded, validate=True))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("F01 raw ConfigParam 34 response is malformed") from error
    return cell.hash.hex()


def verify_capture(manifest_path: Path, nodes: dict[str, list[dict]],
                   log_sources: dict[str, tuple[Path, str]], transition_height: int,
                   before_set: str, after_set: str) -> dict:
    """Join H-1/H/H+1 native IDs to the retained per-node raw RPC bytes."""
    raw_manifest = manifest_path.read_bytes()
    manifest = json.loads(raw_manifest)
    if manifest.get("schema") != "tos.f01.stage-a-capture.v1":
        raise ValueError("F01 capture manifest schema is wrong")
    validators = manifest.get("validators")
    if (not isinstance(validators, list) or len(validators) != 4
            or {entry.get("node_name") for entry in validators} != set(nodes)):
        raise ValueError("F01 capture does not bind the four node logs")
    for validator in validators:
        path, digest = log_sources[validator["node_name"]]
        combined = validator.get("combined_log", {})
        if (combined.get("sha256") != digest
                or Path(combined.get("path", "")).resolve(strict=True) != path.resolve(strict=True)):
            raise ValueError("F01 native log path/SHA differs from capture manifest")
    rpc_addresses = {entry["node_name"]: entry.get("rpc_address")
                     for entry in validators}
    if (any(not isinstance(address, str) or not address
            for address in rpc_addresses.values())
            or len(set(rpc_addresses.values())) != 4):
        raise ValueError("F01 capture aliases or omits per-node RPC addresses")
    transitions = [entry for entry in manifest.get("transitions", [])
                   if entry.get("height") == transition_height]
    if (len(transitions) != 1
            or transitions[0].get("before_config34_cell_hash") != before_set
            or transitions[0].get("after_config34_cell_hash") != after_set):
        raise ValueError("F01 raw Config34 transition does not match requested set digests")
    transition = transitions[0]
    provenance = manifest.get("source", {}).get("config34_raw_rpc_transcript", {})
    transcript_path = Path(provenance.get("path", ""))
    raw_transcript = transcript_path.read_bytes()
    transcript_sha = hashlib.sha256(raw_transcript).hexdigest()
    if transcript_sha != provenance.get("sha256"):
        raise ValueError("F01 raw RPC transcript SHA-256 differs from manifest")
    heights = (transition_height - 1, transition_height, transition_height + 1)
    expected_pairs = {(name, height) for name in nodes for height in heights}
    observations = transition.get("observations")
    if not isinstance(observations, list) or len(observations) != len(expected_pairs):
        raise ValueError("F01 capture lacks four raw headers at H-1/H/H+1")
    indexed = {}
    for observation in observations:
        pair = (observation.get("node_name"), observation.get("height"))
        if pair not in expected_pairs or pair in indexed:
            raise ValueError("F01 capture aliases or omits a node/height observation")
        indexed[pair] = observation
    raw_rows: dict[tuple[str, str, int], list[dict]] = {}
    for line in raw_transcript.splitlines():
        row = json.loads(line)
        request = row.get("request", {})
        method = request.get("method")
        params = request.get("params", {})
        if method not in ("getConfigParam", "getBlockHeader") or "seqno" not in params:
            continue
        name = row.get("node_name")
        if name not in rpc_addresses or row.get("address") != rpc_addresses[name]:
            raise ValueError("F01 raw RPC endpoint differs from node identity")
        if (method == "getConfigParam" and params.get("param") != 34
                or method == "getBlockHeader" and
                (params.get("workchain") != -1
                 or params.get("shard") != "-9223372036854775808")):
            raise ValueError("F01 raw RPC request is not Config34/masterchain header")
        if row.get("http_status") != 200:
            raise ValueError("F01 retained raw RPC has non-200 status")
        try:
            response = json.loads(base64.b64decode(row["response_base64"], validate=True))
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("F01 retained raw RPC response is malformed") from error
        if response.get("error") is not None or response.get("result") is None:
            raise ValueError("F01 retained raw RPC returned an error")
        key = (name, method, int(params["seqno"]))
        raw_rows.setdefault(key, []).append(response)
    facts = raw_header_facts(raw_rows, nodes)
    h_proven_by = {}
    for name, height in expected_pairs:
        observation = indexed[(name, height)]
        expected_hash = before_set if height < transition_height else after_set
        if observation.get("config34_cell_hash") != expected_hash:
            raise ValueError("F01 capture Config34 observation is not the bounded transition")
        header_rows = raw_rows.get((name, "getBlockHeader", height), [])
        config_rows = raw_rows.get((name, "getConfigParam", height), [])
        if not header_rows or not config_rows:
            raise ValueError("F01 raw RPC transcript lacks H-1/H/H+1 header or Config34")
        observed_id = rpc_block_id(observation.get("block_id"))
        native_ids = {tuple(event["id"]) for event in nodes[name]
                      if event["height"] == height}
        if native_ids:
            if native_ids != {observed_id}:
                raise ValueError("F01 native marker differs from exact raw header")
            if height == transition_height:
                h_proven_by[name] = "native"
        elif height == transition_height:
            # A key block's own finalization notice reaches no consensus bus: the
            # validator groups change before it is published (manager.cpp
            # new_masterchain_block, bridge.cpp notify_mc_finalized). H is then
            # proven by its successor: this node natively finalized H+1 (checked as
            # a strict H+1 pair), and every retained raw H+1 header of this node
            # names exactly H's full ID as its only predecessor.
            if not all(row["result"].get("is_key_block") is True for row in header_rows):
                raise ValueError("F01 native marker absent at H, and H is not a raw key block")
            successors = raw_rows.get((name, "getBlockHeader", height + 1), [])
            if not successors:
                raise ValueError("F01 raw transcript lacks the H+1 header for successor proof")
            for row in successors:
                if not names_predecessor(row["result"], observed_id):
                    raise ValueError("F01 raw H+1 header does not name H's exact ID as predecessor")
            h_proven_by[name] = "successor_prev"
        else:
            raise ValueError("F01 native marker differs from exact raw header")
        if any(rpc_block_id(row["result"]["id"]) != observed_id
               for row in header_rows):
            raise ValueError("F01 raw header differs from native marker")
        if any(rpc_config34_hash(row) != expected_hash for row in config_rows):
            raise ValueError("F01 raw Config34 differs at transition boundary")
    return {"capture_manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
            "raw_rpc_transcript_sha256": transcript_sha,
            "raw_header_heights": list(heights),
            "h_proven_by": dict(sorted(h_proven_by.items())),
            "raw_key_block_heights": sorted(facts["key"]),
            "raw_named_key_heights": sorted(facts["named"] - facts["key"])}


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
             before_set: str, after_set: str,
             exempt_heights: frozenset[int] = frozenset()) -> dict:
    """Compare the four nodes' native finalization markers.

    ``exempt_heights`` are heights the raw headers classify as key blocks. A key
    block's own finalization notice reaches no consensus bus, so a node may lack a
    marker there; that is a coverage exception, not a proof of the block's ID.
    Every marker that does exist is still compared across all nodes at every height.
    """
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
    # Every reported ID at every height, whichever nodes report it, must agree.
    reported: dict[int, set] = {}
    for rows in by_node.values():
        for height, block_id in rows.items():
            reported.setdefault(height, set()).add(block_id)
    for height, ids in sorted(reported.items()):
        if len(ids) != 1:
            raise ValueError(f"conflicting finalized full BlockIdExt at height {height}")
    common = set.intersection(*(set(rows) for rows in by_node.values()))
    around = {transition_height - 1, transition_height + 1}
    if not around <= common or not (transition_height in common
                                    or transition_height in exempt_heights):
        raise ValueError("absent all-node common-height IDs around set change")
    checked = sorted(common)
    missing = set(range(checked[0], checked[-1] + 1)) - common
    if missing - set(exempt_heights):
        raise ValueError("common-height finalization evidence has a gap")
    exempt_in_range = sorted(missing)

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
        # Key-block heights inside the checked range that lack a marker on at least
        # one node: classified as key blocks by raw headers, IDs not proven here.
        "coverage_exempt_key_heights": exempt_in_range,
        "common_height_count": len(checked),
        "final_node_heights": tips, "lag_events": lag_events,
        "max_lag_blocks": max((item["lag_blocks"] for item in lag_events), default=0),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-log", action="append", required=True, metavar="NAME=PATH")
    parser.add_argument("--capture-manifest", type=Path, required=True)
    parser.add_argument("--transition-height", type=int, required=True)
    parser.add_argument("--before-set", required=True, help="raw pre-change ConfigParam 34 cell SHA-256")
    parser.add_argument("--after-set", required=True, help="raw post-change ConfigParam 34 cell SHA-256")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    nodes = {}
    sources = {}
    source_paths = {}
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
        source_paths[name] = resolved
    # The raw capture first: its validated headers classify the key-block heights
    # whose missing native markers the node-log comparison may then exempt.
    capture = verify_capture(args.capture_manifest, nodes,
                             {name: (source_paths[name], sources[name]) for name in nodes},
                             args.transition_height, args.before_set, args.after_set)
    exempt = frozenset(capture["raw_key_block_heights"]) | frozenset(capture["raw_named_key_heights"])
    report = evaluate(nodes, args.transition_height, args.before_set, args.after_set,
                      exempt_heights=exempt)
    report.update(capture)
    report["raw_node_log_sha256"] = sources
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
