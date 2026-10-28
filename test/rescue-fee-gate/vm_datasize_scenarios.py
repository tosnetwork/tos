"""Authored bounded DATASIZE traversal/cache effects for the v16 endstate gate."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-extensions"))
from cells import Cell  # noqa: E402
from suite_scenarios import op, prog  # noqa: E402

# C++ VmStorageStat (boc.cpp) descends ref0 before ref1. At a two-cell bound,
# only parent/ref0 are loaded, so a later CTOS costs25 for ref0 or100 for ref1.
# Base prices:18 for each one-byte instruction,26 for DATASIZE,5 implicit RET.
EMPTY_HASH = Cell().hash.hex().upper()


def cases():
    left, right = Cell().uint(1, 8), Cell().uint(2, 8)
    parent = Cell().ref(left).ref(right)
    rows = []
    for kind, bound in (("cell", 2), ("slice", 1)):
        for side, probe in (("left", left), ("right", right)):
            code = prog(
                op([0x88], parent),
                op([0xD0]) if kind == "slice" else [],
                op([0x70 + bound, 0xF9, 0x40 if kind == "cell" else 0x42, 0x30]),
                op([0x88], probe),
                op([0xD0, 0x30]),
            )
            gas = 6 * 18 + 26 + 2 * 100 + (25 if side == "left" else 100) + 5
            steps = 8
            if kind == "slice":
                gas += 18
                steps += 1
            effect = ["0", str(gas), str(steps), "1", EMPTY_HASH, EMPTY_HASH, "-"]
            rows.append((f"datasize-order-{kind}-{side}", code, 1_000_000, effect))
    for side, probe in (("left", left), ("right", right)):
        code = prog(
            op([0x88], parent),
            op([0x73, 0xF9, 0x40, 0x30, 0x30, 0x30, 0x30]),
            op([0x88], probe),
            op([0xD0, 0x30]),
        )
        effect = ["0", str(9 * 18 + 26 + 3 * 100 + 25 + 5), "11", "1", EMPTY_HASH, EMPTY_HASH, "-"]
        rows.append((f"datasize-order-complete-{side}", code, 1_000_000, effect))
    return rows


def check_native(path):
    expected = {name: effect for name, _, _, effect in cases()}
    actual = {}
    for line in Path(path).read_text().splitlines():
        fields = line.split("\t")
        if fields[0].startswith("datasize-order-"):
            assert len(fields) == 8 and fields[0] not in actual, "invalid datasize native row"
            actual[fields[0]] = fields[1:]
    assert actual == expected, "native DATASIZE gas/cache effects differ from authored reference"
    print("PASS:6 native DATASIZE traversal/cache effects")


if __name__ == "__main__":
    check_native(sys.argv[1])
