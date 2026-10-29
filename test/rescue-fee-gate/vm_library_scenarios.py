"""Authored v16 SHA256C effects with a populated library collection.

The driver receives the raw 256-bit dictionary root as a separate bounded BOC.
Library lookup is free; the reference cell is charged, while its resolved cell
is not charged or marked warm. Hash entries and later explicit loads still cost.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-extensions"))
from cells import Cell, LibraryReference, make_dict  # noqa: E402
from suite_scenarios import op, prog  # noqa: E402

EMPTY_HASH = Cell().hash.hex().upper()


def fixtures():
    target = Cell().raw(b"hello library")
    tail = Cell().raw(b"tail")
    tail_ref = LibraryReference(int.from_bytes(tail.hash, "big"))
    head = Cell().raw(b"head").ref(tail_ref)
    unaligned = Cell().uint(1, 1)
    recursive = LibraryReference(int.from_bytes(target.hash, "big"))
    cells = (target, tail, head, unaligned, recursive)
    libraries = make_dict({int.from_bytes(c.hash, "big"): Cell().ref(c) for c in cells}, 256)
    rows, effects = [], {}

    def digest(payload):
        return str(int.from_bytes(hashlib.sha256(payload).digest(), "big"))

    def ref(cell):
        return op([0x88], LibraryReference(int.from_bytes(cell.hash, "big")))

    def add(name, code, gas, steps, stack, budget=1_000_000, exit_code=0):
        name = "sha256c-library-" + name
        state = EMPTY_HASH if exit_code == 0 else "-"
        effects[name] = [
            str(exit_code),
            str(gas),
            str(steps),
            str(int(exit_code == 0)),
            state,
            state,
            stack,
        ]
        rows.append(
            [name, "16", str(budget), "V", "skip", "skip", "skip", "skip", "skip", code.boc().hex()]
        )

    cold = prog(ref(target), op([0xF9, 0x03]))
    add("cold", cold, 150, 3, digest(b"hello library"))
    add("exact-budget", cold, 150, 3, digest(b"hello library"), budget=150)
    add("ret-one-short", cold, 150, 4, "150", budget=149, exit_code=-14)
    add("load-one-short", cold, 144, 3, "144", budget=143, exit_code=-14)
    warm = prog(ref(target), op([0x20, 0xF9, 0x03, 0x01, 0xF9, 0x03]))
    add("warm-reference", warm, 238, 6, digest(b"hello library") + " " + digest(b"hello library"))
    probe = prog(ref(target), op([0xF9, 0x03, 0x30]), op([0x88], target), op([0xD0, 0x30]))
    add("resolved-target-stays-cold", probe, 322, 7, "-")
    before = prog(op([0x88], target), op([0xD0, 0x30]), ref(target), op([0xF9, 0x03]))
    add("direct-target-first", before, 304, 6, digest(b"hello library"))
    add("snake-library-tail", prog(ref(head), op([0xF9, 0x03])), 251, 3, digest(b"headtail"))
    add("resolved-unaligned", prog(ref(unaligned), op([0xF9, 0x03])), 194, 3, "0", exit_code=9)
    add(
        "resolved-library-reference",
        prog(ref(recursive), op([0xF9, 0x03])),
        194,
        3,
        "0",
        exit_code=9,
    )
    return libraries, rows, effects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-native", type=Path)
    args = parser.parse_args()
    libraries, rows, effects = fixtures()
    if args.output:
        assert not args.output.exists(), "library fixture output must be fresh"
        args.output.mkdir(parents=True)
        (args.output / "libraries.boc").write_bytes(libraries.boc())
        (args.output / "scenarios.tsv").write_text("".join("\t".join(row) + "\n" for row in rows))
        (args.output / "expected.tsv").write_text(
            "".join("\t".join([name, *effect]) + "\n" for name, effect in effects.items())
        )
        (args.output / "effects.json").write_text(json.dumps(effects, indent=2) + "\n")
    if args.check_native:
        actual = {}
        for line in args.check_native.read_text().splitlines():
            name, *fields = line.split("\t")
            assert name not in actual and len(fields) == 7, "invalid library native row"
            actual[name] = fields
        assert actual == effects, (
            "native library effects differ from authored reference",
            actual,
            effects,
        )
        print("PASS:", len(effects), "native library gas/cache/hash effects")
    assert args.output or args.check_native, "choose output or native validation"


if __name__ == "__main__":
    main()
