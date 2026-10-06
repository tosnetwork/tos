"""Replay recorded inputs at default credit with independent Rust expectations.

Internal messages retain their recorded prestates. This is a collection of isolated
transaction probes, not a successful recovery sequence at default credit.
"""

import argparse
import json
import subprocess
from pathlib import Path

from benchmark_transactions import fingerprint, run
from cells import make_dict
from fee_tx_parity import Cell, credit, from_boc, read_dict


def default_configuration(root):
    entries = read_dict(root.refs[0], 32)
    prices = entries[21].refs[0]
    tag = int(prices.bits[:8], 2)
    offset = 136 if tag == 0xD1 else 0
    if int(prices.bits[offset : offset + 8], 2) != 0xDE:
        raise ValueError("unsupported gas configuration")
    offset += 8 + 64 * 3
    entries[21] = Cell().ref(
        Cell(
            bits=prices.bits[:offset] + format(10000, "064b") + prices.bits[offset + 64 :],
            refs=prices.refs,
        )
    )
    configuration = make_dict(entries, 32)
    if credit(configuration) != 10000:
        raise ValueError("default credit not installed")
    return Cell(bits=root.bits, refs=[configuration])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=30)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = args.fixtures.resolve()
    fixtures = output / "fixtures"
    fixtures.mkdir()
    (fixtures / "config.boc").write_bytes(
        default_configuration(from_boc((source / "config.boc").read_bytes())).boc()
    )
    (fixtures / "scenarios.tsv").write_bytes((source / "scenarios.tsv").read_bytes())
    command = [
        str(args.driver.resolve()),
        str(fixtures / "config.boc"),
        str(fixtures / "scenarios.tsv"),
        "17",
        "--details",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    (output / "rust.log").write_text(result.stderr)
    (output / "rust.tsv").write_text(result.stdout)
    if result.returncode:
        raise ValueError(f"Rust replay failed: {result.returncode}")
    rows = result.stdout.splitlines()
    original = (source / "native.tsv").read_text().splitlines()
    if len(rows) != len(original) or not rows:
        raise ValueError("missing Rust receipts")
    changed = [
        {"diagnostic": a, "default": b} for a, b in zip(original, rows, strict=True) if a != b
    ]
    if not changed or not any(row.split("\t")[1] == "-14" for row in rows):
        raise ValueError("probe did not expose the default-credit admission failure")
    # The timing runner's historical filename is native.tsv; expectations here
    # come from the independent Rust executor, recorded explicitly in provenance.
    (fixtures / "native.tsv").write_text(result.stdout)
    (output / "comparison.json").write_text(
        json.dumps(
            {
                "scope": "Isolated recorded prestates at default credit; not a continuous recovery",
                "expectation_source": "Rust executor --details",
                "command": command,
                "driver": fingerprint(args.driver),
                "source_inputs": [
                    fingerprint(source / name)
                    for name in ("config.boc", "scenarios.tsv", "native.tsv")
                ],
                "transactions": len(rows),
                "changed": changed,
            },
            indent=2,
        )
        + "\n"
    )
    run(fixtures, output / "timing", args.iterations, 3)


if __name__ == "__main__":
    main()
