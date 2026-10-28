"""GETEXTRABALANCE uses a permissive VM integer loader, not a strict TL-B decoder.

Write a bounded set of v16 programs, or validate native outcomes independently
before passing them to vm_endstate_compare.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-extensions"))
from cells import Cell, make_dict  # noqa: E402
from suite_scenarios import op, prog, runvm  # noqa: E402


def cases():
    rows = []

    def body(dictionary, keys):
        return [
            op([0x70] * 8),
            op([0x88], dictionary),
            op([0x6F, 0x02, 0x6F, 0x08, 0x6F, 0x01, 0xED, 0x57]),
            *[op([0x70 + key, 0xF8, 0x80]) for key in keys],
        ]

    def program(dictionary, keys):
        return prog(body(dictionary, keys))

    for width, value in [(0, 0), (1, 0), (1, 1), (2, 0), (2, 1), (31, 1)]:
        # A single-leaf Hashmap 32, key zero: hml_same$11, v=0, n=32.
        dictionary = Cell().uint(0b110, 3).uint(32, 6).uint(width, 5).uint(value, width * 8)
        for key in (0, 1):
            # c7 = [[0,0,0,0,0,0,0,[0,D]]]; then key GETEXTRABALANCE.
            code = program(dictionary, [key])
            rows.append(
                (f"extra-balance-{width}-{value}-{key}", code, str(value if key == 0 else 0))
            )
    # Fourteen loaded cells on key zero's path. Both cold and warm reads exceed
    # the 200-gas allowance of each of the first five calls; later calls pay all.
    keys = [0, *[1 << bit for bit in range(13)]]
    dictionary = make_dict({key: Cell().uint(2, 5).uint(1, 16) for key in keys}, 32)
    for count in (1, 5, 6, 7):
        rows.append(
            (
                f"extra-balance-deep-{count}",
                program(dictionary, [0] * count),
                " ".join(["1"] * count),
            )
        )
    for flags in (0, 128):
        for parent_count, child_count in ((5, 1), (0, 5)):
            code = prog(
                body(dictionary, [0] * parent_count),
                runvm(program(dictionary, [0] * child_count), flags),
                op([0x70, 0xF8, 0x80]),
            )
            expected = " ".join([*(["1"] * (parent_count + child_count)), "0", "1"])
            rows.append(
                (f"extra-balance-child-{flags}-{parent_count}-{child_count}", code, expected)
            )
    for fee in (0, 100, 1 << 63, (1 << 64) - 1):
        prices = Cell().uint(0xD1, 8).uint(0, 64).uint(fee, 64).uint(0xDE, 8)
        for value in (65536, 1000, 1000, 10000, 1000000, 1000000, 1000000):
            prices.uint(value, 64)
        for simple, opcode in ((False, 0x36), (True, 0x3B)):
            code = prog(
                op([0x6D] * 14),
                op([0x6D, 0x6D]),
                op([0x89], prices),
                op([0x89], prices),
                op([0x6D] * 3),
                op(
                    [0x6F, 0x07, 0x6F, 0x0F, 0x6F, 0x01, 0xED, 0x57, 0x80, 0x1F, 0x70, 0xF8, opcode]
                ),
            )
            signed_fee = fee if fee < (1 << 63) else fee - (1 << 64)
            value = 31 if simple else 31 + signed_fee
            rows.append((f"gasfee-{fee}-{int(simple)}", code, str(value)))
    return rows


def main(args):
    if len(args) != 2 or args[0] not in ("--write", "--check"):
        raise SystemExit(
            "usage: vm_varuint_scenarios.py --write scenarios.tsv | --check native.tsv"
        )
    rows = cases()
    if args[0] == "--write":
        Path(args[1]).write_text(
            "".join(
                "\t".join([name, "16", "1000000", "R", *(["skip"] * 5), code.boc().hex()]) + "\n"
                for name, code, value in rows
            )
        )
    else:
        actual = [line.split("\t") for line in Path(args[1]).read_text().splitlines()]
        assert len(actual) == len(rows), "missing or extra native outcomes"
        for row, (name, _, value) in zip(actual, rows, strict=True):
            assert len(row) == 8 and row[0] == name, (name, row)
            assert row[1] == "0" and row[4] == "1" and row[7] == value, (name, row)
            assert row[5] == row[6] == Cell().hash.hex().upper(), (name, row)
            # Eight PUSHINTs, PUSHREF, PAIR, TUPLE 8, SINGLE and POP c7
            # cost 277. Each query costs 18+26, plus cell loads; RET is 5.
            if name.startswith("gasfee-"):
                # NULLs 342, ref slices 36+100+25, tuples 101, POP 26,
                # arguments 44, fee opcode 26 and implicit RET 5.
                assert int(row[2]) == 705 and int(row[3]) == 29, (name, row)
            elif "-child-" not in name:
                count = int(name.rsplit("-", 1)[1]) if "-deep-" in name else 1
                loads = (
                    min(count, 5) * 200 + max(count - 5, 0) * (14 * 25) if "-deep-" in name else 100
                )
                assert int(row[2]) == 277 + 44 * count + loads + 5, (name, row)
                assert int(row[3]) == 14 + 2 * count, (name, row)
        print(f"{len(rows)} native extra-balance/fee outcomes satisfy authored rules")


if __name__ == "__main__":
    main(sys.argv[1:])
