"""EXPERIMENT: programs whose end state (exit, gas, steps, committed state, final stack and the
Rust error argument) the C++ and Rust VMs must agree on; compared by vm_endstate_compare.py.

Writes rows in the scenario format of suite_scenarios.py, always with a program and no operands.
KNOWN lists the rows whose difference is still open; vm_endstate_compare.py requires each of them
to differ, so a fix must remove its rows from the list.

Usage: vm_endstate_scenarios.py <out.tsv> [--known]
--known prints KNOWN as one comma-separated line instead.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from suite_scenarios import DROP, op, prog, pushint  # noqa: E402

VERSION = 16
BUDGET = 1_000_000

PUSH_C2 = op([0xED, 0x42])
POP_C2 = op([0xED, 0x52])
JMPX = op([0xD9])
PUSHNULL = op([0x6D])
PUSHNAN = op([0x83, 0xFF])
UNASSIGNED = op([0xF4, 0xFF])
BOOLEVAL = op([0xED, 0xF9])
AGAIN_FOREVER = (op([0x90]), op([0xEA]))  # PUSHCONT {} AGAIN


def throw(n):
    return op([0xF2, n]) if n < 64 else op([0xF2, 0xC0 | n >> 8, n & 0xFF])


def throwarg(n):
    return op([0xF2, 0xC8 | n >> 8, n & 0xFF])


def handler_with_nargs(n, *body):
    """PUSHCONT { body } with nargs n (SETCONTARGS 0,n), installed as c2."""
    return (op([0x8A], prog(*body)), op([0xEC, n]), POP_C2)


ROWS = []


def add(name, code, budget=BUDGET, version=VERSION):
    ROWS.append(
        [name, str(version), str(budget), "V", "skip", "skip", "skip", "skip", "skip", code]
    )


def scenarios():
    # How a VM ends: normally, by an exception through the default handler, out of gas, or by a
    # direct jump into the default handler (ExcQuit) with each kind of top of stack.
    add("end-normal", prog(pushint(7)))
    add("end-throw-6", prog(pushint(7), throw(6)))
    add("end-throw-0", prog(pushint(7), throw(0)))
    add("end-throwarg-5-42", prog(pushint(5), throwarg(42)))
    add("end-out-of-gas", prog(pushint(7), *AGAIN_FOREVER), budget=300)
    add("end-unassigned-opcode", prog(pushint(7), UNASSIGNED))
    add("excquit-13-keeps-below", prog(pushint(5), pushint(7), pushint(13), PUSH_C2, JMPX))
    add("excquit-13-alone", prog(pushint(13), PUSH_C2, JMPX))
    add("excquit-0-ends-normally", prog(pushint(5), pushint(0), PUSH_C2, JMPX))
    add("excquit-1-ends-normally", prog(pushint(5), pushint(1), PUSH_C2, JMPX))
    add("excquit-empty-stack", prog(PUSH_C2, JMPX))
    add("excquit-after-drop", prog(pushint(5), DROP, PUSH_C2, JMPX))
    add("excquit-not-an-integer", prog(pushint(5), PUSHNULL, PUSH_C2, JMPX))
    add("excquit-out-of-range", prog(pushint(5), pushint(-1), PUSH_C2, JMPX))
    add("excquit-nan", prog(pushint(5), PUSHNAN, PUSH_C2, JMPX))
    # A handler that needs three arguments cannot take the two an exception passes. An error the
    # VM raises is dispatched once; an explicit THROW is dispatched again after that fails.
    add(
        "handler-nargs-3-vm-error", prog(*handler_with_nargs(3, pushint(9)), pushint(7), UNASSIGNED)
    )
    add("handler-nargs-3-throw-6", prog(*handler_with_nargs(3, pushint(9)), pushint(7), throw(6)))
    # BOOLEVAL returns through implicit PUSHINT continuations, which are not counted as steps.
    add("booleval-true", prog(op([0x91, 0x77]), BOOLEVAL))
    add("booleval-false", prog(op([0x92, 0xDB, 0x31]), BOOLEVAL))


KNOWN = [
    # The Rust VM leaves the exit code on the stack and its error carries no argument.
    "end-throw-6",
    "end-throwarg-5-42",
    "end-unassigned-opcode",
    "end-out-of-gas",
    "excquit-13-keeps-below",
    "excquit-13-alone",
    "excquit-empty-stack",
    "excquit-after-drop",
    "excquit-not-an-integer",
    "excquit-out-of-range",
    "excquit-nan",
    # The Rust VM removes c2 and runs the handler with two arguments despite its nargs.
    "handler-nargs-3-vm-error",
    "handler-nargs-3-throw-6",
]


def main(args):
    scenarios()
    if args == ["--known"]:
        print(",".join(KNOWN))
        return
    (out,) = args
    rows = [row[:9] + [row[9].boc().hex()] for row in ROWS]
    assert len({row[0] for row in rows}) == len(rows), "duplicate ids"
    Path(out).write_text("".join("\t".join(row) + "\n" for row in rows))
    print(f"{len(rows)} scenarios")


if __name__ == "__main__":
    main(sys.argv[1:])
