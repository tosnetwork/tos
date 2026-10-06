"""Probe fee admission at cell and serialized-byte boundaries using public fixtures.

The extra cells replace the inner PQ signature. The outer LMS signature is then
invalid because the intent changed. This measures rejection, never authorization.
"""

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from admission_forgery_timing import select_routes
from benchmark_transactions import fingerprint, run
from default_credit_timing import default_configuration
from fee_tx_parity import Cell, credit, from_boc, native


def cells(root):
    found = {}
    todo = [root]
    while todo:
        cell = todo.pop()
        if cell.hash not in found:
            found[cell.hash] = cell
            todo.extend(cell.refs)
    return found


def tree(widths):
    def node(index):
        value = Cell().uint(0xADFE0001, 32).uint(index, 32).uint(0, widths[index] - 64)
        for child in range(index * 4 + 1, min(index * 4 + 5, len(widths))):
            value.ref(node(child))
        return value

    return node(0)


def replace_signature(message, padding):
    envelope = message.refs[0]
    intent = envelope.refs[0]
    payload = intent.refs[0]
    payload = Cell(bits=payload.bits, refs=[payload.refs[0], padding])
    intent = Cell(bits=intent.bits, refs=[payload])
    envelope = Cell(bits=envelope.bits, refs=[intent, envelope.refs[1]])
    return Cell(bits=message.bits, refs=[envelope])


def padded(message, target_cells, target_bytes=None):
    base = replace_signature(message, tree([256]))
    count = target_cells - len(cells(base)) + 1
    if count < 1:
        raise ValueError("target below required envelope cells")
    widths = [256] * count
    result = replace_signature(message, tree(widths))
    if target_bytes is not None:
        remaining = target_bytes - len(result.boc())
        if remaining < 0:
            raise ValueError("target below required envelope bytes")
        # All added widths are whole bytes. Cell count/index widths stay fixed;
        # the final exact-size assertion also checks the BOC offset-width case.
        for index in range(count):
            extra = min(remaining, (1016 - widths[index]) // 8)
            widths[index] += extra * 8
            remaining -= extra
        if remaining:
            raise ValueError("not enough cell bit capacity")
        result = replace_signature(message, tree(widths))
        if len(result.boc()) != target_bytes:
            raise ValueError("serialized-byte target mismatch")
    if len(cells(result)) != target_cells:
        raise ValueError("distinct-cell target mismatch")
    return result


def replace_code(root, old, new):
    if root.hash == old.hash:
        return new
    return Cell(bits=root.bits, refs=[replace_code(r, old, new) for r in root.refs])


def check(receipts, cases, gas_credit, deleted=False):
    rows = receipts.splitlines()
    if len(rows) != len(cases) or not rows:
        raise ValueError("missing boundary receipts")
    for row, case in zip(rows, cases, strict=True):
        fields = row.split("\t")
        expected = (
            "2015"
            if case["cells"] > 1024 and not deleted
            else "-14"
            if gas_credit == 10000
            else "0"
            if case["valid"]
            else "2007"
        )
        if len(fields) not in (5, 10) or fields[:2] != [case["name"], expected]:
            raise ValueError(
                f"unexpected boundary outcome: {case['name']}: {row}; expected {expected}"
            )
        if expected != "0" and fields[2:] != ["0", "-", "-"]:
            raise ValueError("rejected boundary input produced a transaction")
        if expected == "0" and (
            len(fields) != 10
            or fields[2] != "0"
            or fields[6] != "true"
            or fields[8:] != ["false", "true"]
        ):
            raise ValueError("positive boundary control did not complete")


def replay(driver, fixtures, out):
    result = subprocess.run(
        [
            str(driver.resolve()),
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
        raise ValueError("boundary replay failed")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=30)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    scenarios, cases = [], []
    for kind, original in sorted(select_routes(args.fixtures).items()):
        message = from_boc(bytes.fromhex(original[4]))
        variants = [("valid", message)]
        variants += [(f"cells-{n}", padded(message, n)) for n in (1023, 1024, 1025)]
        variants.append(("bytes-65535", padded(message, 1024, 65535)))
        for label, candidate in variants:
            name = f"class-{kind}-{label}"
            row = list(original)
            row[0], row[4] = name, candidate.boc().hex()
            scenarios.append(row)
            cases.append(
                {
                    "name": name,
                    "cells": len(cells(candidate)),
                    "bits": sum(len(c.bits) for c in cells(candidate).values()),
                    "bytes": len(candidate.boc()),
                    "depth": candidate.depth,
                    "valid": label == "valid",
                }
            )
    root = from_boc((args.fixtures / "config.boc").read_bytes())
    if credit(root.refs[0]) != 20000:
        raise ValueError("expected diagnostic source config")
    for gas_credit, config in [(10000, default_configuration(root)), (20000, root)]:
        out = args.output / str(gas_credit)
        fixtures = out / "fixtures"
        fixtures.mkdir(parents=True)
        (fixtures / "config.boc").write_bytes(config.boc())
        (fixtures / "scenarios.tsv").write_text("\n".join("\t".join(r) for r in scenarios) + "\n")
        receipts = replay(args.driver, fixtures, out)
        check(receipts, cases, gas_credit)
        (fixtures / "native.tsv").write_text(receipts)
        run(fixtures, out / "timing", args.iterations, 3)
    # Delete only the cell-count guard in a private compiler copy. Substituting
    # its code in the recorded account is a synthetic sensitivity control, not
    # an on-chain deployment. The forbidden envelope must reach LMS rejection.
    control = args.output / "deleted-cell-guard"
    control.mkdir()
    source = native.ROOT / "crypto/smartcont/wallet-v5r2-fee-vault.fc"
    text = source.read_text()
    guard = "  throw_unless(2015, r2fee_cells() <= r2fee::max_cells);\n"
    if text.count(guard) != 1:
        raise ValueError("ambiguous cell guard")
    original_code = from_boc((args.fixtures / "native/vault.boc").read_bytes())
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        shutil.copyfile(source.with_name("pq.fc"), work / "pq.fc")
        candidate = work / "vault.fc"
        candidate.write_text(text)
        compiled = native.compile_contract(str(candidate), control / "original.boc")
        if compiled.hash != original_code.hash:
            raise ValueError("source no longer matches recorded vault code")
        candidate.write_text(text.replace(guard, ""))
        mutant = native.compile_contract(str(candidate), control / "deleted.boc")
    changed = []
    selected = []
    for row, case in zip(scenarios, cases, strict=True):
        if case["cells"] not in (1024, 1025):
            continue
        account = from_boc(bytes.fromhex(row[3]))
        if original_code.hash not in cells(account):
            raise ValueError("control did not find executed vault code")
        changed.append(
            [*row[:3], replace_code(account, original_code, mutant).boc().hex(), *row[4:]]
        )
        selected.append(case)
    (control / "config.boc").write_bytes(root.boc())
    (control / "scenarios.tsv").write_text("\n".join("\t".join(r) for r in changed) + "\n")
    receipts = replay(args.driver, control, control)
    check(receipts, selected, 20000, deleted=True)
    try:
        check(receipts, selected, 20000)
    except ValueError as error:
        witness = str(error)
    else:
        raise ValueError("cell guard control did not detect forbidden envelope")
    (control / "native.tsv").write_text(receipts)
    run(control, control / "timing", 1, 1)
    if source.read_text() != text:
        raise ValueError("production source modified")
    (args.output / "results.json").write_text(
        json.dumps(
            {
                "scope": "External C API boundary replay; not network ingress or worst-case hardware clearance",
                "cases": cases,
                "deleted_cell_guard_witness": witness,
                "source": fingerprint(source),
                "driver": fingerprint(args.driver),
                "source_fixtures": [
                    fingerprint(args.fixtures / p)
                    for p in ("config.boc", "scenarios.tsv", "native.tsv", "native/vault.boc")
                ],
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
