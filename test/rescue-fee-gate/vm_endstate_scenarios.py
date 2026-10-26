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
from suite_scenarios import DROP, op, prog, pushint, runvm  # noqa: E402

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
POP_C4 = op([0xED, 0x54])
POP_C5 = op([0xED, 0x55])
COMMIT = op([0xF8, 0x0F])
RETALT = op([0xDB, 0x31])
POP_C0 = op([0xED, 0x50])
POP_C1 = op([0xED, 0x51])
SETCONTCTR_C0 = op([0xED, 0x60])
SETCONTCTR_C2 = op([0xED, 0x62])
TRY = op([0xF2, 0xFF])
TRYARGS_1_1 = op([0xF3, 0x11])
IFJMP = op([0xE0])
PUSH_C3 = op([0xED, 0x43])
CALLDICT_5 = op([0xF0, 0x05])


def cont(*body):
    """PUSHREFCONT { body }."""
    return op([0x8A], prog(*body))


def cell_of_depth(depth):
    """An empty cell wrapped depth times: NEWC ENDC, then depth times NEWC STREF ENDC."""
    return (op([0xC8, 0xC9]), pushint(depth), op([0x93, 0xC8, 0xCC, 0xC9]), op([0xE4]))


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
    # Automatic commit at a normal end: data or actions deeper than 512 cells cannot be
    # committed, which clears the stack, leaves 0 and ends with cell overflow (8), keeping any
    # state committed before. An explicit COMMIT that fails is an ordinary exception.
    for depth in (512, 513):
        add(f"autocommit-c4-depth-{depth}", prog(*cell_of_depth(depth), POP_C4, pushint(7)))
        add(f"autocommit-c5-depth-{depth}", prog(*cell_of_depth(depth), POP_C5, pushint(7)))
    add("autocommit-alt-exit-c4-depth-513", prog(*cell_of_depth(513), POP_C4, pushint(7), RETALT))
    add("autocommit-throw-0-c4-depth-513", prog(*cell_of_depth(513), POP_C4, pushint(7), throw(0)))
    add("commit-c4-depth-513", prog(*cell_of_depth(513), POP_C4, pushint(7), COMMIT))
    add(
        "autocommit-fails-after-commit",
        prog(COMMIT, *cell_of_depth(513), POP_C4, pushint(7)),
    )
    child = prog(*cell_of_depth(513), POP_C4, pushint(7))
    add("child-autocommit-c4-depth-513", prog(*runvm(child, 4 | 32)))
    child = prog(*cell_of_depth(512), POP_C4, pushint(7))
    add("child-autocommit-c4-depth-512", prog(*runvm(child, 4 | 32)))
    # Only exits 0 and 1 commit. c3 starts as quit(11), so a CALLDICT or a jump to c3 ends the
    # VM with 11 and leaves the data uncommitted; a child run without its own c3 does the same.
    calldict = prog(*cell_of_depth(1), POP_C4, pushint(7), CALLDICT_5)
    add("calldict-quits-with-11", calldict)
    add("c3-jump-quits-with-11", prog(*cell_of_depth(1), POP_C4, pushint(7), PUSH_C3, JMPX))
    add("child-calldict-quits-with-11", prog(*runvm(calldict, 4 | 32)))
    # Throwing jumps to c2 and leaves it in place, so a handler that throws enters itself again
    # unless entering it restored another c2. TRY saves c0, c1 and c2 in the return continuation
    # (c1 is quit1 inside the body) and gives the handler c0 and c2 only where it has none.
    add("handler-rethrows-until-out-of-gas", prog(cont(throw(5)), POP_C2, throw(5)), budget=2000)
    rethrow_once = cont(op([0xC0, 5]), cont(throw(7)), IFJMP)
    add("handler-rethrows-once", prog(rethrow_once, POP_C2, pushint(3), throw(5)))
    inner = (cont(throw(5)), cont(throw(6)), TRY)
    add("nested-try-rethrow-reaches-outer-handler", prog(cont(*inner), cont(pushint(9)), TRY))
    add("throw-after-try-returns", prog(cont(pushint(1)), cont(pushint(9)), TRY, throw(6)))
    add(
        "throw-after-try-returns-to-own-handler",
        prog(cont(pushint(8)), POP_C2, cont(pushint(1)), cont(pushint(9)), TRY, throw(6)),
    )
    add(
        "try-handler-defines-c2",
        prog(cont(throw(5)), cont(pushint(8)), cont(throw(7)), SETCONTCTR_C2, TRY, pushint(3)),
    )
    add(
        "try-body-alt-exit",
        prog(
            cont(pushint(77)), POP_C1, cont(pushint(5), RETALT), cont(pushint(9)), TRY, pushint(3)
        ),
    )
    add(
        "try-handler-replaces-c0-then-throws",
        prog(cont(pushint(8), RETALT), POP_C2, cont(throw(5)), cont(cont(throw(6)), POP_C0), TRY),
    )
    add(
        "try-handler-defines-c0",
        prog(cont(throw(5)), cont(pushint(4)), cont(pushint(9)), SETCONTCTR_C0, TRY, pushint(3)),
    )
    # A body's own c0 and c2 replace the return continuation and the handler.
    add(
        "try-body-defines-c0",
        prog(cont(pushint(4)), cont(pushint(1)), SETCONTCTR_C0, cont(pushint(9)), TRY, pushint(3)),
    )
    add(
        "try-body-defines-c2",
        prog(cont(pushint(8)), cont(throw(5)), SETCONTCTR_C2, cont(pushint(9)), TRY, pushint(3)),
    )
    # TRYARGS 1,1 passes one value to the body and keeps one of its results or the handler's.
    add("tryargs-returns", prog(pushint(5), pushint(6), cont(INC), cont(pushint(9)), TRYARGS_1_1))
    add("tryargs-handler", prog(pushint(5), pushint(6), cont(throw(5)), cont(INC), TRYARGS_1_1))
    # XCHG s(i),s(j) (10ij) is valid only for 1 <= i < j; anything else is an invalid opcode,
    # whatever the stack holds.
    three = (pushint(1), pushint(2), pushint(3))
    add("xchg-long-1-2", prog(*three, op([0x10, 0x12])))
    add("xchg-long-0-2-invalid", prog(*three, op([0x10, 0x02])))
    add("xchg-long-2-2-invalid", prog(*three, op([0x10, 0x22])))
    add("xchg-long-2-1-invalid", prog(*three, op([0x10, 0x21])))
    add("xchg-long-1-5-underflow", prog(*three, op([0x10, 0x15])))
    # HASHEXT: every id byte decodes; 255 takes the id from the stack, after a depth check. The
    # count is popped before the id is checked, so an unknown id on an empty stack is an
    # underflow, and on a valid count a range check. The appending forms need a builder below.
    one_byte = (pushint(0x61), op([0xC8, 0xCB, 7, 0xC9, 0xD0]))  # 'a' as a slice
    add("hashext-sha256-one-byte", prog(*one_byte, pushint(1), op([0xF9, 0x04, 0x00])))
    add("hashext-sha512-one-byte", prog(*one_byte, pushint(1), op([0xF9, 0x04, 0x01])))
    add("hashext-id-5-empty", prog(op([0xF9, 0x04, 0x05])))
    add("hashext-id-5-count-0", prog(pushint(0), op([0xF9, 0x04, 0x05])))
    add("hashext-id-255-sha512", prog(*one_byte, pushint(1), pushint(1), op([0xF9, 0x04, 0xFF])))
    add("hashext-id-255-only", prog(pushint(0), op([0xF9, 0x04, 0xFF])))
    add("hashexta-count-0-no-builder", prog(pushint(0), op([0xF9, 0x06, 0x00])))
    # BLS: the depth is checked before the operation is charged; a scalar must be finite before
    # its point is decoded; the aggregate checks decode their message and signature last, also
    # for a count of zero.
    empty_slice = op([0xC8, 0xC9, 0xD0])
    add("bls-g1-add-empty-stack", prog(op([0xF9, 0x30, 0x10])))
    add("bls-g1-mul-nan-short-point", prog(empty_slice, PUSHNAN, op([0xF9, 0x30, 0x13])))
    add("bls-g2-mul-nan-short-point", prog(empty_slice, PUSHNAN, op([0xF9, 0x30, 0x23])))
    add(
        "bls-fastaggregateverify-0-short",
        prog(pushint(0), empty_slice, empty_slice, op([0xF9, 0x30, 0x02])),
    )
    add("bls-aggregateverify-0-short", prog(pushint(0), empty_slice, op([0xF9, 0x30, 0x03])))
    # Continuations. A jump applies the target's whole savelist, c0 and c1 included; a call to
    # a continuation that defines c0 is a jump; CALLCC captures c0 and c1; a loop keeps its
    # whole body; savelist definitions keep a slot that is taken.
    k0 = (cont(pushint(9)), cont(pushint(5)), SETCONTCTR_C0)  # { 5 } returning to { 9 }
    add("jump-applies-saved-c0", prog(*k0, JMPX))
    add("ifjmp-applies-saved-c0", prog(pushint(-1), *k0, IFJMP))
    add("callxargs-to-saved-c0-is-a-jump", prog(pushint(4), pushint(6), *k0, op([0xDA, 0x10])))
    add("callcc-captures-c0-c1", prog(cont(), op([0xDB, 0x34])))
    add(
        "callcc-generated-argument",
        prog(cont(DROP, pushint(5)), op([0xEC, 0x01]), op([0xDB, 0x34])),
    )
    add("repeat-body-defines-c0", prog(pushint(2), *k0, op([0xE4]), pushint(3)))
    add(
        "setcontctr-keeps-taken-slot",
        prog(
            cont(pushint(9)),
            cont(pushint(7)),
            cont(pushint(5)),
            SETCONTCTR_C0,
            SETCONTCTR_C0,
            op([0xD8]),
        ),
    )
    add(
        "saveboth-c0",
        prog(cont(pushint(5)), POP_C0, cont(pushint(6)), POP_C1, op([0xED, 0xC0]), RETALT),
    )
    add(
        "setcontargs-copies-into-closure",
        prog(
            pushint(1),
            pushint(2),
            op([0xC8, 0xC9, 0xD0]),
            op([0xEE, 0x22]),
            pushint(1),
            op([0x01]),
            pushint(2),
            op([0x01]),
            pushint(3),
            op([0x01]),
            op([0xEC, 0x22]),
        ),
    )
    # The default handler pops its exit code when it is entered; an exception that reaches it
    # ends the VM with that exception.
    add("excquit-custom-13", prog(pushint(99), pushint(13), PUSH_C2, JMPX))
    add(
        "excquit-in-envelope",
        prog(pushint(99), pushint(13), op([0xC8, 0xC9]), PUSH_C2, op([0xED, 0x64]), JMPX),
    )
    # One jump through nine continuations pays one gas for the ninth dispatch (version 9 on).
    nine = [p for _ in range(8) for p in (pushint(1), op([0xE5]))]
    add("dispatch-chain-of-nine", prog(*nine))
    add("dispatch-chain-of-nine-v8", prog(*nine), version=8)
    add(
        "dict-key-out-of-range-is-a-miss",
        prog(pushint(300), PUSHNULL, pushint(8), op([0xF4, 0xBC]), pushint(9)),
    )


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
