#!/usr/bin/env python3
"""Read retained live traces and verify first hops after a real PQ election."""

import argparse
import base64
import datetime
import importlib.util
import json
import re
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "local_elections", Path(__file__).with_name("local-pq-elections.py")
)
elections = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elections)


def check(directory):
    candidates = {
        i: json.loads((directory / f"candidate-{i}.json").read_text()) for i in (1, 2, 3, 4, 7)
    }
    by_controller = {c["controller"].split(":")[1]: i for i, c in candidates.items()}
    activations = [json.loads(p.read_text()) for p in sorted(directory.glob("activation-*.json"))]
    if len(activations) < 2:
        raise ValueError("no real elected-set transition has been retained yet")
    before, after = activations[-2:]
    old = {by_controller[v["controller_id_hex"]] for v in before["config34"]["validators"]}
    current = {by_controller[v["controller_id_hex"]] for v in after["config34"]["validators"]}
    if len(current) != 4 or len(old - current) != 1 or len(current - old) != 1:
        raise ValueError("expected one real replacement in a four-validator set")
    if after["config34"]["utime_until"] - after["config34"]["utime_since"] != 600:
        raise ValueError("elected interval is not 600 seconds")
    by_adnl = {c["adnl_id"].upper(): i for i, c in candidates.items()}
    # Exclude in-flight work from retired sessions, then compare the new group's actual send targets.
    cutoff = after["observed_at"] + 20
    broadcasts = {}
    with (directory / "relay-trace.jsonl").open() as f:
        for raw in f:
            row = json.loads(raw)
            line, node = row["line"], row["node"]
            timestamp = re.search(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d+)\]", line)
            if not timestamp or "overlay.valgroup" not in line:
                continue
            when = (
                datetime.datetime.strptime(
                    timestamp[1] + "." + timestamp[2][:6], "%Y-%m-%d %H:%M:%S.%f"
                )
                .replace(tzinfo=datetime.timezone.utc)
                .timestamp()
            )
            if when < cutoff:
                continue
            match = re.search(
                r"twostep (START|FIRST_HOP|FINISH) (sender|receiver) broadcast_id=([A-F0-9]{64})",
                line,
            )
            if not match:
                continue
            phase, role, bid = match.groups()
            record = broadcasts.setdefault(bid, {"first_hops": set(), "receivers": {}, "lines": []})
            record["lines"].append(row)
            if phase == "START" and role == "sender":
                record["sender"] = node
                record["hash"] = re.search(r"data_hash=([A-F0-9]{64})", line)[1]
            elif phase == "FIRST_HOP":
                destination = re.search(r"to=(\S+)", line)
                if not destination:
                    raise ValueError("first-hop destination is missing")
                adnl = base64.b64decode(destination[1], validate=True)
                if len(adnl) != 32 or adnl.hex().upper() not in by_adnl:
                    raise ValueError("first-hop destination is not a provisioned validator")
                record["first_hops"].add(by_adnl[adnl.hex().upper()])
            elif phase == "FINISH":
                record["receivers"][node] = re.search(r"data_hash=([A-F0-9]{64})", line)[1]
    checked, evidence = {}, []
    for bid, record in broadcasts.items():
        sender = record.get("sender")
        if sender not in current:
            continue
        if not record["first_hops"]:
            continue
        elections.require_first_hops(sender, record["first_hops"], current)
        recipients = current - {sender}
        if not all(record["receivers"].get(i) == record["hash"] for i in recipients):
            continue
        checked[sender] = checked.get(sender, 0) + 1
        if len(evidence) < 12:
            evidence.append(
                {
                    "broadcast_id": bid,
                    "sender": sender,
                    "first_hops": sorted(record["first_hops"]),
                    "data_hash": record["hash"],
                    "lines": record["lines"],
                }
            )
    if set(checked) != current:
        raise ValueError(
            f"not all current validators have a matched send/receive witness: {checked}"
        )
    return {
        "passed": True,
        "before_nodes": sorted(old),
        "after_nodes": sorted(current),
        "retired_nodes": sorted(old - current),
        "new_nodes": sorted(current - old),
        "interval_seconds": 600,
        "activation_height": after["height"],
        "activation_since": after["config34"]["utime_since"],
        "matched_broadcasts_by_sender": checked,
        "evidence": evidence,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("/data/elections"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check(args.data)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k != "evidence"}, indent=2))
