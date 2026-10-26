"""Programs for the C++ VM's variable-length (Ext) instructions, for vm-endstate on both VMs.

These instructions carry data bits and references after a fixed header. The C++ VM charges the
header width as base gas and checks only that the header is present; each instruction's own
function then checks its data and references. For every family and a few arguments a program is
the instruction with its data and references complete (data all ones, and all zeros where that
leaves a slice without a completion tag), one data bit short, one reference short, and complete
or one data bit short with the budget one below and at the base gas. Each runs on an empty stack and, where the family
takes operands, again after an instruction that pushes them.

Usage: vm_ext_scenarios.py <out.tsv>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from suite_scenarios import Cell  # noqa: E402

VERSION = 16
BUDGET = 1_000_000
NEWC = "11001000"
PUSHINT_5 = "01110101"
PUSHSLICE_EMPTY = "100010110000" + "1000"  # PUSHSLICE x{} (8B0 followed by a completion tag)

# (name, header -> (value, width), arguments, data bits, references, setup bits)
FAMILIES = [
    (
        "pushint",
        lambda a: (0x82 << 5 | a, 13),
        (0, 31),
        lambda a: 3 + ((a & 31) + 2) * 8,
        lambda a: 0,
        "",
    ),
    ("pushref", lambda a: (0x88, 8), (0,), lambda a: 0, lambda a: 1, ""),
    ("pushrefslice", lambda a: (0x89, 8), (0,), lambda a: 0, lambda a: 1, ""),
    ("pushrefcont", lambda a: (0x8A, 8), (0,), lambda a: 0, lambda a: 1, ""),
    (
        "pushslice",
        lambda a: (0x8B << 4 | a, 12),
        (0, 1, 15),
        lambda a: (a & 15) * 8 + 4,
        lambda a: 0,
        "",
    ),
    (
        "pushslice-refs",
        lambda a: (0x8C << 7 | a, 15),
        (0, 0x25, 0x7F),
        lambda a: (a & 31) * 8 + 1,
        lambda a: ((a >> 5) & 3) + 1,
        "",
    ),
    (
        "pushslice-long",
        lambda a: (0x8D << 10 | a, 18),
        (0, 3, 0x80 | 10, 4 << 7 | 5),
        lambda a: (a & 127) * 8 + 6,
        lambda a: (a >> 7) & 7,
        "",
    ),
    (
        "pushcont",
        lambda a: (0x47 << 9 | a, 16),
        (0, 5, 0x80 | 3, 0x180 | 2),
        lambda a: (a & 127) * 8,
        lambda a: (a >> 7) & 3,
        "",
    ),
    (
        "pushcont-short",
        lambda a: (9 << 4 | a, 8),
        (0, 1, 15),
        lambda a: (a & 15) * 8,
        lambda a: 0,
        "",
    ),
    ("strefconst", lambda a: (0xCF20 | a, 16), (0, 1), lambda a: 0, lambda a: (a & 1) + 1, NEWC),
    (
        "stsliceconst",
        lambda a: (0x19F << 5 | a, 14),
        (0, 3, 0x1F),
        lambda a: (a & 7) * 8 + 2,
        lambda a: (a >> 3) & 3,
        NEWC,
    ),
    (
        "sdbegins",
        lambda a: (0x1AE5 << 8 | a, 21),
        (0, 2, 0x80 | 2),
        lambda a: (a & 127) * 8 + 3,
        lambda a: 0,
        PUSHSLICE_EMPTY,
    ),
    ("callref", lambda a: (0xDB3C, 16), (0,), lambda a: 0, lambda a: 1, ""),
    ("jmpref", lambda a: (0xDB3D, 16), (0,), lambda a: 0, lambda a: 1, ""),
    ("jmprefdata", lambda a: (0xDB3E, 16), (0,), lambda a: 0, lambda a: 1, ""),
    ("ifref", lambda a: (0xE300 | a, 16), (0, 1, 2, 3), lambda a: 0, lambda a: 1, PUSHINT_5),
    ("ifrefelse", lambda a: (0xE30D, 16), (0,), lambda a: 0, lambda a: 1, PUSHINT_5),
    ("ifelseref", lambda a: (0xE30E, 16), (0,), lambda a: 0, lambda a: 1, PUSHINT_5),
    ("ifrefelseref", lambda a: (0xE30F, 16), (0,), lambda a: 0, lambda a: 2, PUSHINT_5),
    (
        "ifbitjmpref",
        lambda a: (0x38F << 6 | a, 16),
        (0, 2, 0x22),
        lambda a: 0,
        lambda a: 1,
        PUSHINT_5,
    ),
    ("dictpushconst", lambda a: (0xF4A400 | a, 24), (0, 0x3FF), lambda a: 0, lambda a: 1, ""),
    ("pfxdictswitch", lambda a: (0xF4AC00 | a, 24), (0, 0x3FF), lambda a: 0, lambda a: 1, ""),
    (
        "debugstr",
        lambda a: (0xFEF << 4 | a, 16),
        (0, 15),
        lambda a: ((a & 15) + 1) * 8,
        lambda a: 0,
        "",
    ),
    # Not Ext, but the debug opcodes around DEBUGSTR: each does nothing on a node.
    (
        "debug",
        lambda a: (0xFE00 | a, 16),
        (0x0F, 0x16, 0x1D, 0x2F, 0x3F, 0x40, 0xEF),
        lambda a: 0,
        lambda a: 0,
        "",
    ),
]


def program(setup, header, width, data, refs):
    bits = setup + format(header, f"0{width}b") + data
    if len(bits) > 1023 or refs > 4:
        return None
    cell = Cell(bits)
    for _ in range(refs):
        cell.ref(Cell())
    return cell


def row(name, cell, budget=BUDGET):
    return [name, str(VERSION), str(budget), "V", "skip", "skip", "skip", "skip", "skip"] + [
        cell.boc().hex()
    ]


def scenarios():
    rows = []
    for name, header, args, data_bits, ref_count, setup in FAMILIES:
        for a in args:
            value, width = header(a)
            n, r = data_bits(a), ref_count(a)
            for prefix, pre in (("", ""), ("setup-", setup)) if setup else (("", ""),):
                cases = [("complete-ones", "1" * n, r), ("short-ref", "1" * n, r - 1)]
                if n:
                    cases += [("complete-zeros", "0" * n, r), ("short-bit", "1" * (n - 1), r)]
                for case, data, refs in cases:
                    if refs < 0:
                        continue
                    cell = program(pre, value, width, data, refs)
                    if cell is not None:
                        rows.append(row(f"ext-{name}-{a:x}-{prefix}{case}", cell))
            base = 10 + width
            cell = program("", value, width, "1" * n, r)
            if cell is not None:
                for budget in (base - 1, base):
                    rows.append(row(f"ext-{name}-{a:x}-budget-{budget}", cell, budget))
            # Out of gas comes before the data check: short data must not raise invalid opcode.
            cell = program("", value, width, "1" * (n - 1), r) if n else None
            if cell is not None:
                for budget in (base - 1, base):
                    rows.append(row(f"ext-{name}-{a:x}-short-bit-budget-{budget}", cell, budget))
    return rows


def main(args):
    if len(args) != 1:
        sys.exit(__doc__)
    rows = scenarios()
    assert len({r[0] for r in rows}) == len(rows), "duplicate ids"
    Path(args[0]).write_text("".join("\t".join(r) + "\n" for r in rows))
    print(f"{len(rows)} scenarios")


if __name__ == "__main__":
    main(sys.argv[1:])
