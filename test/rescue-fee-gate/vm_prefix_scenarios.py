"""Programs that are a single truncated, unassigned or version-gated instruction prefix, generated
from the C++ VM's codepage 0 table (vm_opcode_table.py), for vm-endstate on both VMs.

For every assigned range and every length k shorter than its prefix, the program is the first
k-bit code in the range (the VM pads it with zeros to 24 bits, which must land in the same range).
For a range enabled from version v > 0, its full prefix runs at v - 1 (invalid) and at v. Each
unassigned range gets its first 8-bit code, if it has one, and its first 24-bit code. The rows of
vm_ext_scenarios.py follow.

KNOWN lists the rows whose difference is still open; vm_endstate_compare.py requires each of them
to differ, so a fix must remove its rows from the list.

Usage: vm_prefix_scenarios.py <table.tsv> <out.tsv> [--without-known] | --known
--without-known leaves out the KNOWN rows, for the mutation runner, which needs equal rows.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from suite_scenarios import Cell  # noqa: E402
from vm_ext_scenarios import scenarios as ext_scenarios  # noqa: E402
from vm_opcode_table import TOP, read  # noqa: E402

# BLS_G1_ADD and BLS_G2_ADD run on an empty stack: the Rust VM charges the operation before it
# checks the stack depth, the C++ VM after. Open; the BLS instructions are fixed separately.
KNOWN = ["version-f93010-24-at-4", "version-f93020-24-at-4"]

VERSION = 16
BUDGET = 1_000_000


def first_aligned(first, end, k):
    """The first opcode in [first, end) whose low 24 - k bits are zero, or None."""
    step = 1 << (24 - k)
    o = -(-first // step) * step
    return o if o < end else None


def code(opcode, k):
    return Cell().uint(opcode >> (24 - k), k)


def row(name, cell, version=VERSION):
    return [name, str(version), str(BUDGET), "V", "skip", "skip", "skip", "skip", "skip"] + [
        cell.boc().hex()
    ]


def scenarios(ranges):
    rows = []
    ends = [r[0] for r in ranges[1:]] + [TOP]
    for (first, bits, version), end in zip(ranges, ends):
        if bits == 0:
            for k in (8, 24):
                if (o := first_aligned(first, end, k)) is not None:
                    rows.append(row(f"unassigned-{o:06x}-{k}", code(o, k)))
            continue
        for k in range(1, bits):
            if (o := first_aligned(first, end, k)) is not None:
                rows.append(row(f"truncated-{o:06x}-{k}-of-{bits}", code(o, k)))
        if version > 0:
            for v in (version - 1, version):
                rows.append(row(f"version-{first:06x}-{bits}-at-{v}", code(first, bits), v))
    return rows


def main(args):
    if args == ["--known"]:
        print(",".join(KNOWN))
        return
    if len(args) not in (2, 3) or args[2:] not in ([], ["--without-known"]):
        sys.exit(__doc__)
    rows = scenarios(read(args[0])) + ext_scenarios()
    if args[2:] == ["--without-known"]:
        rows = [r for r in rows if r[0] not in KNOWN]
    assert len({r[0] for r in rows}) == len(rows), "duplicate ids"
    Path(args[1]).write_text("".join("\t".join(r) + "\n" for r in rows))
    print(f"{len(rows)} scenarios")


if __name__ == "__main__":
    main(sys.argv[1:])
