"""Compare credit limits using distinct, well-framed invalid LMS fee signatures.

Public fixture replay only. This is neither a worst-case ingress bound nor approval
to change gas credit. Native timings include BOC decoding and serialization.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from benchmark_transactions import fingerprint, run
from default_credit_timing import default_configuration
from fee_tx_parity import Cell, credit, from_boc

PREFIX = Cell().uint(0x46454534, 32).raw(b"TOS-RESCUE-FEE-v1").bits


def signature_bytes(cell):
    result = bytearray()
    while True:
        if len(cell.bits) % 8 or len(cell.refs) > 1:
            raise ValueError("unexpected signature framing")
        result.extend(int(cell.bits or "0", 2).to_bytes(len(cell.bits) // 8, "big"))
        if not cell.refs:
            break
        cell = cell.refs[0]
    if len(result) != 2832:
        raise ValueError("expected fixed H20/W4 signature")
    return bytes(result)


def chain(data):
    tail = None
    for start in reversed(range(0, len(data), 127)):
        cell = Cell().raw(data[start : start + 127])
        if tail is not None:
            cell.ref(tail)
        tail = cell
    return tail


def forge(message, index, mode):
    body = message.refs[0]
    original = signature_bytes(body.refs[1])
    signature = bytearray(original)
    offset = {"randomizer": 12, "last_path_node": len(signature) - 32}[mode]
    replacement = hashlib.sha256(
        b"PUBLIC-INVALID-LMS-ADMISSION" + mode.encode() + index.to_bytes(4, "big") + original
    ).digest()
    signature[offset : offset + 32] = replacement
    if signature == original:
        raise ValueError("forgery did not change signature")
    changed = Cell(bits=body.bits, refs=[body.refs[0], chain(signature)])
    return Cell(bits=message.bits, refs=[changed])


def select_routes(fixtures):
    rows = [line.split("\t") for line in (fixtures / "scenarios.tsv").read_text().splitlines()]
    receipts = (fixtures / "native.tsv").read_text().splitlines()
    selected = {}
    for row, receipt in zip(rows, receipts, strict=True):
        if len(row) != 6 or receipt.split("\t")[0] != row[0]:
            raise ValueError("fixture alignment mismatch")
        if receipt.split("\t")[1:3] != ["0", "0"]:
            continue
        message = from_boc(bytes.fromhex(row[4]))
        if not message.bits.startswith("1000") or len(message.refs) != 1:
            continue
        body = message.refs[0]
        if body.bits or len(body.refs) != 2 or not body.refs[0].bits.startswith(PREFIX):
            continue
        kind = int(body.refs[0].bits[len(PREFIX) : len(PREFIX) + 8], 2)
        if kind in (1, 2, 3) and kind not in selected:
            signature_bytes(body.refs[1])
            selected[kind] = row
    if set(selected) != {1, 2, 3}:
        raise ValueError("successful AUTH, POP and preparation fee fixtures required")
    return selected


def validate_rows(receipts, names, gas_credit):
    if gas_credit not in (10000, 20000):
        raise ValueError("unsupported credit comparison")
    rows = receipts.splitlines()
    if len(rows) != len(names) or not rows:
        raise ValueError("missing replay receipts")
    for name, row in zip(names, rows, strict=True):
        fields = row.split("\t")
        if len(fields) not in (5, 10):
            raise ValueError("malformed replay receipt")
        if fields[0] != name:
            raise ValueError("replay order mismatch")
        expected = "-14" if gas_credit == 10000 else ("0" if name.endswith("valid") else "2007")
        if fields[1] != expected:
            raise ValueError(f"unexpected admission outcome: {name}: {fields[1]} != {expected}")
        if expected != "0" and fields[2:] != ["0", "-", "-"]:
            raise ValueError("rejected input produced a transaction")
        if expected == "0" and (
            len(fields) != 10
            or fields[2] != "0"
            or fields[6] != "true"
            or fields[8:] != ["false", "true"]
        ):
            raise ValueError("positive fixture did not complete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variants", type=int, default=16)
    parser.add_argument("--iterations", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.variants <= 128:
        raise ValueError("variants must be 1..128")
    args.output.mkdir(parents=True, exist_ok=False)
    selected = select_routes(args.fixtures)
    scenarios = []
    for kind, original in sorted(selected.items()):
        message = from_boc(bytes.fromhex(original[4]))
        scenarios.append([f"class-{kind}-valid", *original[1:]])
        for mode in ("randomizer", "last_path_node"):
            for index in range(args.variants):
                row = list(original)
                row[0] = f"class-{kind}-{mode}-{index:03d}"
                row[4] = forge(message, index, mode).boc().hex()
                scenarios.append(row)
    names = [row[0] for row in scenarios]
    configuration = from_boc((args.fixtures / "config.boc").read_bytes())
    if credit(configuration.refs[0]) != 20000:
        raise ValueError("expected diagnostic 20000-credit source fixture")
    for gas_credit, root in [(10000, default_configuration(configuration)), (20000, configuration)]:
        out = args.output / str(gas_credit)
        out.mkdir()
        fixtures = out / "fixtures"
        fixtures.mkdir()
        (fixtures / "config.boc").write_bytes(root.boc())
        (fixtures / "scenarios.tsv").write_text(
            "\n".join("\t".join(row) for row in scenarios) + "\n"
        )
        result = subprocess.run(
            [
                str(args.driver.resolve()),
                str(fixtures / "config.boc"),
                str(fixtures / "scenarios.tsv"),
                "17",
                "--details",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        (out / "rust.log").write_text(result.stderr)
        (out / "rust.tsv").write_text(result.stdout)
        if result.returncode:
            raise ValueError("Rust replay failed")
        validate_rows(result.stdout, names, gas_credit)
        (fixtures / "native.tsv").write_text(result.stdout)
        run(fixtures, out / "timing", args.iterations, 3)
    report = {
        "scope": "Distinct invalid signatures; warm-cache native replay, not worst-case or release clearance",
        "source": [
            fingerprint(args.fixtures / p) for p in ("config.boc", "scenarios.tsv", "native.tsv")
        ],
        "driver": fingerprint(args.driver),
        "selected_sources": {kind: row[0] for kind, row in selected.items()},
        "scenarios_per_credit": len(scenarios),
        "variants_per_class_and_mode": args.variants,
        "expectations": "Rust executor; every native timing sample checked against its full receipt",
        "credits": {},
    }
    for gas_credit in (10000, 20000):
        timings = json.loads(
            (args.output / str(gas_credit) / "timing/measurements.json").read_text()
        )
        invalid = [r for r in timings["results"] if not r["name"].endswith("valid")]
        report["credits"][gas_credit] = {
            "invalid_scenarios": len(invalid),
            "max_invalid_scenario_median_ns": max(r["median_ns"] for r in invalid),
            "rejection": -14 if gas_credit == 10000 else 2007,
        }
    (args.output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
