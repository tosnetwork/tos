#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Migrate the vm-endstate scenarios (test/rescue-fee-gate) to vm-harness contexts.

    vm_endstate.py contexts <scenarios.tsv> <contexts.jsonl>
        Convert the 10-column scenario rows of vm_endstate_scenarios.py into contexts.
    vm_endstate.py check <fixtures.jsonl> <test-vm-endstate output.tsv>
        Require every fixture's effects to equal the original driver's output for the same row,
        field by field, so the migration is shown not to change what is compared.

Scenario columns, as test/rescue-fee-gate/vm-endstate.cpp reads them: id, global version, gas
budget, a label the driver ignores, the top stack value, four lower stack values (bottom first),
the code BOC. Stack values are ``skip``, ``int:<n>`` or a hex BOC pushed as a cell. The driver
runs with gas limit = max = budget, no credit, flags 0, no c4, no c7 and no libraries.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def stack_value(field: str) -> Json | None:
    if field == "skip":
        return None
    if field.startswith("int:"):
        return {"type": "int", "value": str(int(field[4:]))}
    return {"type": "cell", "boc": base64.b64encode(bytes.fromhex(field)).decode("ascii")}


def contexts(scenarios: Path) -> list[Json]:
    out: list[Json] = []
    for number, line in enumerate(scenarios.read_text().splitlines(), 1):
        f = line.split("\t")
        if len(f) != 10:
            raise SystemExit(f"{scenarios}:{number}: 10 columns required, got {len(f)}")
        budget = int(f[2])
        stack = [item for item in (stack_value(x) for x in [*f[5:9], f[4]]) if item is not None]
        out.append(
            {
                "fixture_id": f[0],
                "note": f"label {f[3]}",
                "context": {
                    "code": base64.b64encode(bytes.fromhex(f[9])).decode("ascii"),
                    "global_version": int(f[1]),
                    "gas": {"limit": budget, "max": budget},
                    "stack": stack,
                },
            }
        )
    if not out:
        raise SystemExit(f"{scenarios}: no scenarios")
    return out


def check(fixtures_path: Path, driver_output: Path) -> int:
    fixtures = [json.loads(line) for line in fixtures_path.read_text().splitlines()]
    rows = [line.split("\t") for line in driver_output.read_text().splitlines()]
    if len(fixtures) != len(rows):
        raise SystemExit(f"{len(fixtures)} fixtures but {len(rows)} driver rows")
    differences = 0
    for fixture, row in zip(fixtures, rows, strict=True):
        if len(row) != 8:
            raise SystemExit(f"driver row {row[0] if row else '?'}: 8 columns required")
        effects = fixture["effects"]
        fixture_id = fixture["metadata"]["fixture_id"]
        expected = {
            "id": row[0],
            "exit_code": int(row[1]),
            "gas_used": int(row[2]),
            "steps": int(row[3]),
            "committed": row[4] == "1",
            "c4_hash": None if row[5] == "-" else row[5],
            "c5_hash": None if row[6] == "-" else row[6],
            "stack": "-" if row[7] == "-" else row[7],
        }
        actual = {
            "id": fixture_id,
            "exit_code": effects["exit_code"],
            "gas_used": effects["gas_used"],
            "steps": effects["steps"],
            "committed": effects["committed"],
            "c4_hash": effects["c4_hash"],
            "c5_hash": effects["c5_hash"],
            "stack": " ".join(effects["stack"]) if effects["stack"] else "-",
        }
        if actual != expected:
            differences += 1
            print(f"DIFF {fixture_id}: driver {expected} fixture {actual}")
    print(f"checked {len(rows)} rows, {differences} differences")
    return 1 if differences else 0


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "contexts":
        entries = contexts(Path(argv[1]))
        Path(argv[2]).write_text(
            "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries)
        )
        print(f"{len(entries)} contexts")
        return 0
    if len(argv) == 3 and argv[0] == "check":
        return check(Path(argv[1]), Path(argv[2]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
