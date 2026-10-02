#!/usr/bin/env python3
"""Pack four operators' public PQ bootstrap identities for create-state."""

import argparse
import json
from pathlib import Path


def pack_manifest(records):
    if not isinstance(records, list) or len(records) != 4:
        raise ValueError("exactly four PQ validator records are required")
    fields = (("controller_id", 32), ("adnl_id", 32), ("public_key", 1312))
    seen = {name: set() for name, _ in fields}
    packed = []
    for record in records:
        if not isinstance(record, dict) or set(record) != set(seen):
            raise ValueError("each record requires only controller_id, adnl_id and public_key")
        for name, size in fields:
            value = record[name]
            if not isinstance(value, str) or len(value) != size * 2:
                raise ValueError(f"{name} must be exactly {size} bytes of hex")
            raw = bytes.fromhex(value)
            if len(raw) != size or not any(raw) or raw in seen[name]:
                raise ValueError(f"{name} must be nonzero, correctly sized and unique")
            seen[name].add(raw)
            packed.append(raw)
    return b"".join(packed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="ordered public JSON records")
    parser.add_argument("output", type=Path, help="new validator-pq.pub (never overwritten)")
    args = parser.parse_args()
    data = pack_manifest(json.loads(args.manifest.read_text()))
    with args.output.open("xb") as out:
        out.write(data)
    print(f"Wrote {len(data)} public bytes to {args.output}")


if __name__ == "__main__":
    main()
