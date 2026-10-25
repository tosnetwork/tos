"""EXPERIMENT: compare how the C++ and Rust VMs end the same programs.

Reads the outputs of test-vm-endstate (C++) and the vm-endstate example (Rust) for one scenario
file and requires, for every scenario:
  - equal exit code, gas, steps, committed flag, committed c4/c5 hashes and final stack;
  - when the Rust VM returned an error, its error argument equals the final stack top of the
    C++ VM ("missing" when that stack is empty), which is what transactions report as exit_arg.

Stack items are canonical text: integers in decimal or NaN, null, cell:<hash>, slice:<cell
hash>:<bit range>:<reference range>, builder:<bits>:<refs>:<hash>, a tuple in parentheses, and
cont:<class>:nargs=<n>:save=<registers>:stack=[<items>]. Not compared: the code and codepage a
continuation carries, the values of its saved registers (only which are set), and the fields
specific to loop continuations. Equal text therefore does not prove equal continuations.

--known <ids> lists scenarios whose difference is known and accepted (comma-separated); each must
still differ, so that a fixed difference is noticed. --known-stack <ids> lists scenarios that may
differ only in the final stack and the error argument; everything else must still be equal, and
they too must still differ. --expected <file> also requires the C++ output to equal a frozen file.

Usage: vm_endstate_compare.py <cpp-output> <rust-output> [--known a,b] [--known-stack c,d]
                              [--expected <file>]
"""

import argparse
import sys
from pathlib import Path

COMMON = 8  # id exit gas steps committed c4 c5 stack
STACK_ONLY = ("stack:", "error argument:")


def read(path, fields):
    rows = [line.split("\t") for line in Path(path).read_text().splitlines()]
    assert rows, f"no rows: {path}"
    assert all(len(row) == fields for row in rows), f"invalid rows: {path}"
    assert len({row[0] for row in rows}) == len(rows), f"duplicate ids: {path}"
    return rows


def top(stack):
    # Items are separated by spaces at the outermost level only.
    if stack == "-":
        return "missing"
    depth, start = 0, 0
    last = stack
    for i, ch in enumerate(stack):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == " " and depth == 0:
            start = i + 1
    last = stack[start:]
    return last


def differences(cpp_row, rust_row):
    found = []
    names = ["id", "exit", "gas", "steps", "committed", "c4", "c5", "stack"]
    for i in range(1, COMMON):
        if cpp_row[i] != rust_row[i]:
            found.append(f"{names[i]}: C++ {cpp_row[i]!r} Rust {rust_row[i]!r}")
    kind, arg = rust_row[COMMON], rust_row[COMMON + 1]
    if kind != "ok":
        want = top(cpp_row[7])
        if arg != want:
            found.append(f"error argument: Rust {arg!r}, C++ stack top {want!r}")
    elif arg != "-":
        found.append(f"error argument {arg!r} without an error")
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cpp")
    parser.add_argument("rust")
    parser.add_argument("--known", default="")
    parser.add_argument("--known-stack", default="")
    parser.add_argument("--expected")
    args = parser.parse_args()
    cpp = read(args.cpp, COMMON)
    rust = read(args.rust, COMMON + 2)
    assert [r[0] for r in cpp] == [r[0] for r in rust], "scenario ids differ"
    known = {k for k in args.known.split(",") if k}
    known_stack = {k for k in args.known_stack.split(",") if k}
    assert not known & known_stack, f"listed twice: {sorted(known & known_stack)}"
    unknown = (known | known_stack) - {r[0] for r in cpp}
    assert not unknown, f"known differences not in the scenarios: {sorted(unknown)}"
    failed = False
    for cpp_row, rust_row in zip(cpp, rust):
        found = differences(cpp_row, rust_row)
        name = cpp_row[0]
        if name in known:
            if not found:
                print(f"{name}: listed as a known difference but now equal")
                failed = True
            continue
        if name in known_stack:
            if not found:
                print(f"{name}: listed as a known stack difference but now equal")
                failed = True
            found = [line for line in found if not line.startswith(STACK_ONLY)]
        for line in found:
            print(f"{name}: {line}")
        failed |= bool(found)
    if args.expected:
        if Path(args.expected).read_text() != Path(args.cpp).read_text():
            print("C++ output differs from the expected file")
            failed = True
    if failed:
        sys.exit(1)
    print(
        f"PASS: {len(cpp)} scenarios, {len(known)} known differences and"
        f" {len(known_stack)} known stack differences still present"
    )


if __name__ == "__main__":
    main()
