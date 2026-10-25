"""EXPERIMENT: programs whose end state (exit, gas, steps, committed state, final stack and the
Rust error argument) the C++ and Rust VMs must agree on; compared by vm_endstate_compare.py.

Writes rows in the scenario format of suite_scenarios.py, always with a program and no operands.
KNOWN and KNOWN_STACK list the rows whose difference is still open; vm_endstate_compare.py
requires each of them to differ, so a fix must remove its rows from the lists.

Usage: vm_endstate_scenarios.py <out.tsv> | --known | --known-stack
--known and --known-stack print that list as one comma-separated line instead.
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
SETCPX = op([0xFF, 0xF0])
INC = op([0xA4])
DEC = op([0xA5])
NEGATE = op([0xA3])
SETGASLIMIT = op([0xF8, 0x01])


def pushpow2(n):
    return op([0x83, n - 1])


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
    # Running out of gas while entering the default handler (THROW 6 costs 94 gas in all).
    for budget in (60, 93, 94):
        add(f"throw-out-of-gas-in-dispatch-{budget}", prog(pushint(7), throw(6)), budget=budget)
    # BOOLEVAL returns through implicit PUSHINT continuations, which are not counted as steps.
    add("booleval-true", prog(op([0x91, 0x77]), BOOLEVAL))
    add("booleval-false", prog(op([0x92, 0xDB, 0x31]), BOOLEVAL))
    # Only codepage 0 exists. Selecting any other is an invalid opcode; SETCPX takes a signed
    # 16-bit codepage.
    add("setcp-0", prog(pushint(7), op([0xFF, 0x00])))
    add("setcp-1", prog(pushint(7), op([0xFF, 0x01])))
    add("setcp-minus-1", prog(pushint(7), op([0xFF, 0xFF])))
    add("setcpx-0", prog(pushint(7), pushint(0), SETCPX))
    add("setcpx-1", prog(pushint(7), pushint(1), SETCPX))
    add("setcpx-16384", prog(pushint(7), pushint(16384), SETCPX))
    add("setcpx-32767", prog(pushint(7), pushint(32767), SETCPX))
    add("setcpx-32768", prog(pushint(7), pushint(32767), INC, SETCPX))
    add("setcpx-minus-32768", prog(pushint(7), pushint(-32768), SETCPX))
    add("setcpx-minus-32769", prog(pushint(7), pushint(-32768), DEC, SETCPX))
    add("setcpx-nan", prog(pushint(7), PUSHNAN, SETCPX))
    add("setcpx-null", prog(pushint(7), PUSHNULL, SETCPX))
    add("setcpx-empty", prog(SETCPX))
    add("setcp-5", prog(pushint(7), op([0xFF, 0x05])))
    add("setcpx-20000", prog(pushint(7), pushint(20000), SETCPX))
    # A refused SETCP caught by TRY: execution goes on in codepage 0.
    add(
        "setcp-1-caught-by-try",
        prog(op([0x92, 0xFF, 0x01]), op([0x92, 0x5B, 0x79]), op([0xF2, 0xFF]), pushint(7)),
    )
    # SETGASLIMIT: at most 0 means 0, 2^63 and more mean unlimited (capped by the maximum), NaN is
    # an integer overflow. A limit below the gas already used is out of gas.
    add("setgaslimit-5000", prog(pushint(5000), SETGASLIMIT, pushint(7)))
    add("setgaslimit-2-pow-62", prog(pushpow2(62), SETGASLIMIT, pushint(7)))
    add("setgaslimit-2-pow-63-minus-1", prog(pushpow2(63), DEC, SETGASLIMIT, pushint(7)))
    add("setgaslimit-2-pow-63", prog(pushpow2(63), SETGASLIMIT, pushint(7)))
    add("setgaslimit-2-pow-200", prog(pushpow2(200), SETGASLIMIT, pushint(7)))
    add("setgaslimit-0", prog(pushint(7), pushint(0), SETGASLIMIT))
    add("setgaslimit-minus-1", prog(pushint(7), pushint(-1), SETGASLIMIT))
    add("setgaslimit-minus-2-pow-200", prog(pushint(7), pushpow2(200), NEGATE, SETGASLIMIT))
    add("setgaslimit-nan", prog(pushint(7), PUSHNAN, SETGASLIMIT))
    add("setgaslimit-null", prog(pushint(7), PUSHNULL, SETGASLIMIT))
    add("setgaslimit-empty", prog(SETGASLIMIT))


# Rows that may differ only in the final stack and the error argument; exit code, gas, steps
# and committed state must be equal.
KNOWN_STACK = []

# Rows that differ in more than that.
KNOWN = []


def main(args):
    scenarios()
    if args in (["--known"], ["--known-stack"]):
        print(",".join(KNOWN if args == ["--known"] else KNOWN_STACK))
        return
    (out,) = args
    rows = [row[:9] + [row[9].boc().hex()] for row in ROWS]
    assert len({row[0] for row in rows}) == len(rows), "duplicate ids"
    Path(out).write_text("".join("\t".join(row) + "\n" for row in rows))
    print(f"{len(rows)} scenarios")


if __name__ == "__main__":
    main(sys.argv[1:])
