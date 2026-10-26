"""Programs for whole instruction families, for vm-endstate on both VMs.

Each family runs every opcode it covers, or one instruction over many continuations, on a set of
stack set-ups that reach each of its checks: stack depth, operand types, ranges, slice lengths,
gas, and for continuations what their savelists restore. vm_prefix_scenarios.py appends these rows
to the prefix rows; both drivers run them and must agree, except for the rows in KNOWN.

Families:
- xchg: XCHG s(i),s(j) (10ij) on an empty and on a deep stack; i = 0 or i >= j is invalid.
- hashext: every HASHEXT opcode (F904..F907 xx) and the hash id from the stack.
- bls: every BLS instruction on 45 set-ups and three gas budgets.
- save: SAVECTR, SAVEALTCTR and SAVEBOTHCTR, then what c0 and c1 restore.
- ctrmany: SETCONTCTRMANY and SETCONTCTRMANYX, on a continuation whose c0 is already set.
- jump: every jump, call and loop instruction on a continuation whose savelist sets c0 (or c1).
- compose: the instructions that compose savelists (BOOLAND ... THENRETALT, INVERT, SAMEALT, TRY).
- loop, loop2: every loop instruction; closure bodies and conditions, bodies that save
  registers, invalid flags, loops inside TRY and RUNVM.
- terminal: the default handler (ExcQuit) entered by a jump, through an envelope and by an
  exception, with each kind of exit code, and as the ninth dispatch of one jump.
- capture: CALLCC*, JMPXDATA, JMPREFDATA, RETDATA; the captured continuation as an argument and
  invoked; copies around the free stack depth.
- varargs: the count bounds of CALLXVARARGS, CALLCCVARARGS, JMPXVARARGS, RETVARARGS.
- closure: SETCONTARGS, SETCONTVARARGS, SETNUMVARARGS, BLESS*, RETURNARGS, RETURNVARARGS.
- popsave: POPSAVE with valid and invalid values, a taken slot, both exits.
- dict: dictionary and prefix dictionary jumps and calls, found and not found.
- chain: one jump dispatching 7 to 11 continuations, around the gas of the dispatches past the
  eighth, at versions 8, 9 and 16.
- stackgas: jumps, calls and closures copying stacks around the free depth.
- compose2, ctrmany2, save2: conflicting definitions, single-register setters at versions 13,
  14 and 16, live register operations.
- fuzz: the seeded programs of vm_closure_fuzz.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from suite_scenarios import op, prog, pushint  # noqa: E402
from vm_closure_fuzz import scenarios as fuzz_scenarios  # noqa: E402

VERSION = 16
BUDGET = 1_000_000

# Rows of the compared families that still differ.
KNOWN = []

PUSHC0, PUSHC1 = op([0xED, 0x40]), op([0xED, 0x41])
POPC0, POPC1, POPC4 = op([0xED, 0x50]), op([0xED, 0x51]), op([0xED, 0x54])
JMPX, CALLX = op([0xD9]), op([0xD8])
RET, RETALT = op([0xDB, 0x30]), op([0xDB, 0x31])
G1Z, G2Z = op([0xF9, 0x30, 0x15]), op([0xF9, 0x30, 0x25])
EMPTY_SLICE = op([0xC8, 0xC9, 0xD0])  # NEWC ENDC CTOS
NEWC = op([0xC8])
NULL = op([0x6D])
I7 = pushint(7)


def setc(i):
    """SETCONTCTR c(i): (x cont - cont), cont.savelist[i] = x."""
    return op([0xED, 0x60 | i])


def cont(*body):
    return op([0x8A], prog(*body))


def setcontargs(copy, more):
    return op([0xEC, copy << 4 | (more & 15)])


ROWS = []


def add(name, *parts, budget=BUDGET, version=VERSION):
    ROWS.append(
        [f"family-{name}", str(version), str(budget), "V", "skip", "skip", "skip", "skip", "skip"]
        + [prog(*parts).boc().hex()]
    )


def add_boc(name, boc_hex, budget=BUDGET, version=VERSION):
    """A row whose program is given as a code BOC (for cells the builder does not make)."""
    ROWS.append(
        [f"family-{name}", str(version), str(budget), "V", "skip", "skip", "skip", "skip", "skip"]
        + [boc_hex]
    )


def xchg():
    deep = [pushint(i) for i in range(17)]
    for args in range(256):
        add(f"xchg-10{args:02x}-empty", op([0x10, args]))
        add(f"xchg-10{args:02x}-deep", *deep, op([0x10, args]))
    # The other exchange forms may name s0 or the same register twice.
    others = {
        **{f"{b:02x}": [b] for b in range(0x01, 0x10)},  # XCHG s0,s(i)
        **{f"11{a:02x}": [0x11, a] for a in (0, 1, 2, 16, 255)},  # XCHG s0,s(ii)
        **{f"{b:02x}": [b] for b in range(0x12, 0x20)},  # XCHG s1,s(i)
        "5000": [0x50, 0x00],  # XCHG2 s0,s0
        "5011": [0x50, 0x11],  # XCHG2 s1,s1
    }
    for name, code in others.items():
        add(f"xchg-other-{name}-deep", *deep, op(code))
        add(f"xchg-other-{name}-empty", op(code))
    # A valid long form with too few entries, and the basic gas of 10ij (10 + 16 bits).
    for depth in (15, 16):
        add(f"xchg-101f-depth-{depth}", *deep[:depth], op([0x10, 0x1F]))
    for budget in (43, 44, 45):
        add(f"xchg-1012-budget-{budget}", I7, I7, I7, op([0x10, 0x12]), budget=budget)
        add(f"xchg-1011-budget-{budget}", I7, I7, I7, op([0x10, 0x11]), budget=budget)


HASHEXT_SETUPS = {
    "empty": (),
    "count-0": (pushint(0),),
    "not-integer": (NULL,),
    "slice-1": (EMPTY_SLICE, pushint(1)),
    "builder-0": (NEWC, pushint(0)),
    "builder-slice-1": (NEWC, EMPTY_SLICE, pushint(1)),
    "int-1": (I7, pushint(1)),
    "slices-2": (EMPTY_SLICE, EMPTY_SLICE, pushint(2)),
}
SWAP = op([0x01])
ENDC_CTOS = op([0xC9, 0xD0])


def stu(n):
    """STU n: (x b - b')."""
    return op([0xCB, n - 1])


def bits_builder(value, n):
    """A builder holding value as n bits."""
    return (pushint(value), NEWC, stu(n))


def bits_slice(value, n):
    return (*bits_builder(value, n), ENDC_CTOS)


def slice_with_ref(value, n):
    """A slice of n data bits and one reference to an empty cell."""
    return (*bits_builder(value, n), op([0xC8, 0xC9]), SWAP, op([0xCC]), ENDC_CTOS)


def zero_builder(bits):
    """A builder of bits zero bits, built 256 bits at a time."""
    out = [NEWC]
    while bits > 0:
        step = min(bits, 256)
        out += [pushint(0), SWAP, stu(step)]
        bits -= step
    return tuple(out)


# Data with content, for results and gas: (name, items pushed before the count).
HASHEXT_DATA = {
    "one-byte": (bits_slice(0x61, 8),),
    "seven-plus-one": (bits_slice(0x30, 7), bits_slice(1, 1)),
    "seven": (bits_slice(0x30, 7),),
    "unequal": (bits_slice(0x6162, 16), bits_builder(0x63, 8), bits_slice(0x6465, 15)),
    "with-ref": (slice_with_ref(0x61, 8), bits_slice(0x62, 8)),
    "many": (bits_slice(0x0102, 16),) * 5,
}
# Gas budgets that cut a two-element run at each of its charges (immediate SHA-256 forms).
HASHEXT_BUDGETS = range(1420, 1475)  # the run uses 1471 in all


def hashext():
    for o in range(0xF904 << 8, 0xF908 << 8):
        code = op(list(o.to_bytes(3, "big")))
        for name, setup in HASHEXT_SETUPS.items():
            add(f"hashext-{o:06x}-{name}", *setup, code)
        hid = o & 0xFF
        append = (o >> 9) & 1
        if hid not in (0, 1, 2, 3, 4, 5, 0xFF):
            continue
        # The id from the stack comes after the count.
        id_push = (pushint(hid),) if hid != 0xFF else ()
        for idv in (0, 1, 2, 3, 4) if hid == 0xFF else (None,):
            suffix = f"-id-{idv}" if idv is not None else ""
            id_part = (pushint(idv),) if idv is not None else ()
            for name, data in HASHEXT_DATA.items():
                head = (zero_builder(0),) if append else ()
                add(
                    f"hashext-{o:06x}-{name}{suffix}",
                    *head,
                    *data,
                    pushint(len(data)),
                    *id_part,
                    code,
                )
            if append:
                # A builder with exactly room for the digest, and one bit less.
                size = 512 if (idv if idv is not None else hid) in (1, 2, 4) else 256
                for spare, label in ((0, "full"), (1, "one-short")):
                    add(
                        f"hashext-{o:06x}-builder-{label}{suffix}",
                        zero_builder(1023 - size + spare),
                        *bits_slice(0x61, 8),
                        pushint(1),
                        *id_part,
                        code,
                    )
        del id_push
        if hid == 0xFF:
            for hidv, label in ((5, "5"), (254, "254"), (255, "255"), (-1, "minus-1")):
                add(
                    f"hashext-{o:06x}-slice-id-{label}",
                    EMPTY_SLICE,
                    pushint(1),
                    pushint(hidv),
                    code,
                )
            add(f"hashext-{o:06x}-id-nan", EMPTY_SLICE, pushint(1), op([0x83, 0xFF]), code)
            add(f"hashext-{o:06x}-id-null", EMPTY_SLICE, pushint(1), NULL, code)
            add(f"hashext-{o:06x}-id-only", pushint(0), code)
            add(f"hashext-{o:06x}-count-negative", pushint(-1), pushint(0), code)
            add(f"hashext-{o:06x}-count-too-big", EMPTY_SLICE, pushint(5), pushint(0), code)
        else:
            add(f"hashext-{o:06x}-count-negative", pushint(-1), code)
            add(f"hashext-{o:06x}-count-nan", op([0x83, 0xFF]), code)
            add(f"hashext-{o:06x}-count-too-big", EMPTY_SLICE, pushint(5), code)
    for budget in HASHEXT_BUDGETS:
        data = (bits_slice(0x61, 8), bits_slice(0x62, 8), pushint(2))
        add(f"hashext-f90400-budget-{budget}", *data, op([0xF9, 0x04, 0x00]), budget=budget)
        add(
            f"hashext-f904ff-budget-{budget}",
            *data,
            pushint(0),
            op([0xF9, 0x04, 0xFF]),
            budget=budget,
        )


BLS_SETUPS = {
    "empty": (),
    "i": (I7,),
    "ii": (I7, I7),
    "iii": (I7, I7, I7),
    "null": (NULL,),
    "s": (EMPTY_SLICE,),
    "b": (NEWC,),
    "g1": (G1Z,),
    "g2": (G2Z,),
    "g1-g1": (G1Z, G1Z),
    "g2-g2": (G2Z, G2Z),
    "g1-s": (G1Z, EMPTY_SLICE),
    "s-g1": (EMPTY_SLICE, G1Z),
    "g1-i": (G1Z, I7),
    "g2-i": (G2Z, I7),
    "i-g1": (I7, G1Z),
    "g1-null": (G1Z, NULL),
    "s-i": (EMPTY_SLICE, I7),
    "0": (pushint(0),),
    "1": (pushint(1),),
    "m1": (pushint(-1),),
    "g1-1": (G1Z, pushint(1)),
    "g1-i-1": (G1Z, I7, pushint(1)),
    "g2-i-1": (G2Z, I7, pushint(1)),
    "g1-g2-1": (G1Z, G2Z, pushint(1)),
    "g1-s-1": (G1Z, EMPTY_SLICE, pushint(1)),
    "s-s-1": (EMPTY_SLICE, EMPTY_SLICE, pushint(1)),
    "g1-s-s": (G1Z, EMPTY_SLICE, EMPTY_SLICE),
    "g1-s-g2": (G1Z, EMPTY_SLICE, G2Z),
    "s-s-g2": (EMPTY_SLICE, EMPTY_SLICE, G2Z),
    "g1-1-s-g2": (G1Z, pushint(1), EMPTY_SLICE, G2Z),
    "g1-s-0-s-g2": (G1Z, EMPTY_SLICE, pushint(0), EMPTY_SLICE, G2Z),
    "g1-1-s-s": (G1Z, pushint(1), EMPTY_SLICE, EMPTY_SLICE),
    "g1-s-1-s-g2": (G1Z, EMPTY_SLICE, pushint(1), EMPTY_SLICE, G2Z),
    "g1-1-s-g2-msg": (G1Z, pushint(1), EMPTY_SLICE, G2Z, EMPTY_SLICE),
    "g2-1": (G2Z, pushint(1)),
    "g2-2": (G2Z, pushint(2)),
    "s-1": (EMPTY_SLICE, pushint(1)),
    "i-1": (I7, pushint(1)),
    "null-1": (NULL, pushint(1)),
    "s-0": (EMPTY_SLICE, pushint(0)),
    "b-s-1": (NEWC, EMPTY_SLICE, pushint(1)),
    "s-s-2": (EMPTY_SLICE, EMPTY_SLICE, pushint(2)),
    "g1-nan-1": (G1Z, op([0x83, 0xFF]), pushint(1)),
    "g1-nan": (G1Z, op([0x83, 0xFF])),
    "g2-nan": (G2Z, op([0x83, 0xFF])),
    # A scalar that is not finite or not an integer, below or above a malformed point.
    "s-nan": (EMPTY_SLICE, op([0x83, 0xFF])),
    "s-null": (EMPTY_SLICE, NULL),
    "nan-s": (op([0x83, 0xFF]), EMPTY_SLICE),
    "g1-big": (G1Z, op([0x83, 200])),
    "g2-minus-1": (G2Z, pushint(-1)),
    # Counts of zero with a malformed or valid message and signature, and type errors in front.
    "0-s-s": (pushint(0), EMPTY_SLICE, EMPTY_SLICE),
    "0-s-g2": (pushint(0), EMPTY_SLICE, G2Z),
    "0-s": (pushint(0), EMPTY_SLICE),
    "0-g2": (pushint(0), G2Z),
    "0-null-s": (pushint(0), NULL, EMPTY_SLICE),
    "0-s-null": (pushint(0), EMPTY_SLICE, NULL),
    "null-s": (NULL, EMPTY_SLICE),
    "g1-1-s-null": (G1Z, pushint(1), EMPTY_SLICE, NULL),
    "s-1-s-g2": (EMPTY_SLICE, pushint(1), EMPTY_SLICE, G2Z),
    "g1-s-1-g2": (G1Z, EMPTY_SLICE, pushint(1), G2Z),
    "s-s-1-g2": (EMPTY_SLICE, EMPTY_SLICE, pushint(1), G2Z),
    "g1-s-s-1-s": (G1Z, EMPTY_SLICE, pushint(1), EMPTY_SLICE),
}
BLS_OPS = [0x00, 0x01, 0x02, 0x03, *range(0x10, 0x19), *range(0x20, 0x29), 0x30, 0x31]


def bls():
    for o in BLS_OPS:
        for name, setup in BLS_SETUPS.items():
            for budget in (BUDGET, 4_000, 300):
                add(f"bls-f930{o:02x}-{name}-{budget}", *setup, op([0xF9, 0x30, o]), budget=budget)


def save():
    for fam, name in ((0xA, "save"), (0xB, "savealt"), (0xC, "saveboth")):
        for i in (0, 1, 2, 3, 4, 5, 7):
            code = op([0xED, fam << 4 | i])
            add(f"save-{name}-c{i}-plain", code, PUSHC0, PUSHC1)
            # c0 = { 5 }, c1 = { 6 }, then the save and a return: what c0 and c1 restore decides
            # the stack.
            for exit_name, exit_op in (("ret", RET), ("retalt", RETALT)):
                add(
                    f"save-{name}-c{i}-{exit_name}",
                    cont(pushint(5)),
                    POPC0,
                    cont(pushint(6)),
                    POPC1,
                    code,
                    exit_op,
                    budget=5_000,
                )
            add(f"save-{name}-c{i}-twice", cont(pushint(5)), POPC0, code, code, PUSHC0, PUSHC1)


def ctrmany():
    for mask in range(256):
        code = op([0xED, 0xE3, mask])
        add(f"ctrmany-{mask:02x}-empty", code)
        add(f"ctrmany-{mask:02x}-cont", cont(I7), code)
        add(f"ctrmany-{mask:02x}-int", I7, code)
        # A continuation whose c0 is already set to c1 (quit1) keeps it: the jump ends with 1.
        add(f"ctrmany-{mask:02x}-preset-c0", PUSHC1, cont(pushint(5)), setc(0), code, JMPX)
        add(
            f"ctrmanyx-{mask:02x}-preset-c0",
            PUSHC1,
            cont(pushint(5)),
            setc(0),
            pushint(mask),
            op([0xED, 0xE4]),
            JMPX,
        )


K0 = (cont(pushint(9)), cont(pushint(5)), setc(0))  # { 5 } that returns to { 9 }
K1 = (cont(pushint(8)), cont(pushint(5), RETALT), setc(1))  # { 5 RETALT } that exits to { 8 }
# (operands below K, operands above K, instruction)
JUMPS = {
    "jmpx": ((), (), op([0xD9])),
    "jmpxargs-0": ((), (), op([0xDB, 0x10])),
    "jmpxargs-1": ((pushint(3),), (), op([0xDB, 0x11])),
    "jmpxvarargs": ((), (pushint(0),), op([0xDB, 0x3A])),
    "jmpxvarargs-1": ((pushint(4),), (pushint(1),), op([0xDB, 0x3A])),
    "jmpxdata": ((), (), op([0xDB, 0x35])),
    "ifjmp": ((pushint(-1),), (), op([0xE0])),
    "ifnotjmp": ((pushint(0),), (), op([0xE1])),
    "ifbitjmp-0": ((pushint(1),), (), op([0xE3, 0x80])),
    "ifnbitjmp-0": ((pushint(0),), (), op([0xE3, 0xA0])),
    "callx": ((), (), op([0xD8])),
    "callxargs-0-0": ((), (), op([0xDA, 0x00])),
    "callxargs-1-0": ((pushint(4), pushint(6)), (), op([0xDA, 0x10])),
    "callxargs-0-1": ((pushint(4),), (), op([0xDA, 0x01])),
    "callxvarargs": ((pushint(4),), (pushint(1), pushint(-1)), op([0xDB, 0x38])),
    "execute-if": ((pushint(-1),), (), op([0xDE])),
    "ifelse": ((pushint(-1),), (op([0x90]),), op([0xE2])),
    "repeat-1": ((pushint(1),), (), op([0xE4])),
    "repeat-2": ((pushint(2),), (), op([0xE4])),
    "until": ((), (), op([0xE6])),
    "while": ((), (cont(pushint(0)),), op([0xE8])),
    "again": ((), (), op([0xEA])),
    "repeatbrk-1": ((pushint(1),), (), op([0xE3, 0x14])),
    "callcc": ((), (), op([0xDB, 0x34])),
}


def jump():
    for kname, k in (("c0", K0), ("c1", K1)):
        for name, (below, above, code) in JUMPS.items():
            if name == "while":
                # WHILE (cond body - ): K is the condition here, { 0 } the body.
                add(f"jump-{kname}-{name}", *k, *above, code, budget=100_000)
            else:
                add(f"jump-{kname}-{name}", *below, *k, *above, code, budget=100_000)


def compose():
    plain = (cont(pushint(5)),)
    preset0 = (cont(pushint(7)), cont(pushint(5)), setc(0))
    preset1 = (cont(pushint(6)), cont(pushint(5), RETALT), setc(1))
    alt = (cont(pushint(5), RETALT),)
    for kname, k in (("plain", plain), ("preset0", preset0), ("preset1", preset1), ("alt", alt)):
        for name, enc in (("booland", 0xF0), ("boolor", 0xF1), ("composboth", 0xF2)):
            for how, code in (("jmpx", JMPX), ("callx", CALLX)):
                add(f"compose-{name}-{kname}-{how}", *k, cont(pushint(9)), op([0xED, enc]), code)
        add(f"compose-atexit-{kname}", *k, op([0xED, 0xF3]), pushint(1))
        add(f"compose-atexitalt-{kname}", *k, op([0xED, 0xF4]), pushint(1), RETALT)
        add(f"compose-setexitalt-{kname}", *k, op([0xED, 0xF5]), pushint(1), RETALT)
        add(f"compose-thenret-{kname}", *k, op([0xED, 0xF6]), JMPX)
        add(f"compose-thenretalt-{kname}", *k, op([0xED, 0xF7]), JMPX)
        add(f"compose-booleval-{kname}", *k, op([0xED, 0xF9]))
        add(f"compose-invert-{kname}", cont(pushint(8)), POPC1, *k, op([0xED, 0xF8]), JMPX)
        add(f"compose-samealtsave-{kname}", *k, POPC0, op([0xED, 0xFB]), RETALT)
        add(f"compose-samealt-{kname}", *k, POPC0, op([0xED, 0xFA]), RETALT)
        add(f"compose-pushctr-c0-after-pop-{kname}", *k, POPC0, PUSHC0, JMPX)
        add(f"compose-try-body-{kname}", *k, cont(pushint(9)), op([0xF2, 0xFF]), pushint(3))
        add(f"compose-try-handler-{kname}", cont(op([0xF2, 5])), *k, op([0xF2, 0xFF]), pushint(3))


def loop():
    empty_cell = op([0xC8, 0xC9])
    for name, code, before in (
        ("repeat", op([0xE4]), (pushint(2),)),
        ("until", op([0xE6]), ()),
        ("again", op([0xEA]), ()),
    ):
        # A closure body: 3 captured on its stack, added to whatever the body sees.
        step = pushint(-1) if name == "until" else op([0xA0])  # until: TRUE ends the loop
        add(
            f"loop-{name}-closure-body",
            pushint(1),
            *before,
            pushint(3),
            cont(step),
            setcontargs(1, -1),
            code,
            budget=3_000,
        )
        # A body whose savelist sets c4: every entry restores c4.
        body_end = pushint(-1) if name == "until" else op([])
        add(
            f"loop-{name}-body-saves-c4",
            *before,
            empty_cell,
            cont(body_end),
            setc(4),
            code,
            budget=3_000,
        )
    # A closure condition: WHILE (cond body - ).
    add(
        "loop-while-closure-cond",
        pushint(3),
        cont(op([0x20, 0x81, 0, 3, 0xBB])),
        setcontargs(1, -1),
        cont(op([0x30])),
        op([0xE8]),
        budget=3_000,
    )
    # The loop continuation itself reused as a loop body: chains of continuations that jump to
    # continuations, past the free nested jumps, with budgets around the end.
    body = cont(PUSHC0, pushint(1), op([0xE4]))  # { c0 1 REPEAT }
    for budget in (600, 1_000, 3_000):
        add(f"loop-nested-repeat-{budget}", pushint(1), body, op([0xE4]), budget=budget)
    # SETCONTCTR and SETRETCTR on a slot that is already set, at versions 13, 14 and 16.
    for v in (13, 14, 16):
        add(
            f"old-setcontctr-twice-v{v}" if v == 13 else f"loop-setcontctr-twice-v{v}",
            PUSHC1,
            PUSHC0,
            cont(pushint(5)),
            setc(0),
            setc(0),
            JMPX,
            version=v,
        )
        add(
            f"old-setretctr-twice-v{v}" if v == 13 else f"loop-setretctr-twice-v{v}",
            PUSHC1,
            op([0xED, 0x70]),
            PUSHC1,
            op([0xED, 0x70]),
            version=v,
        )


# Families of the continuation model ********************************************************

PUSHC2, PUSHC3 = op([0xED, 0x42]), op([0xED, 0x43])
POPC2 = op([0xED, 0x52])
SWAP = op([0x01])
DROP = op([0x30])
PUSHNAN = op([0x83, 0xFF])
COMMIT = op([0xF8, 0x0F])
EMPTY_CELL = op([0xC8, 0xC9])  # NEWC ENDC
ONE_CELL = op([0xC8, 0xC9, 0xC8, 0xCC, 0xC9])  # a cell with one reference
CALLCC, JMPXDATA, RETDATA = op([0xDB, 0x34]), op([0xDB, 0x35]), op([0xDB, 0x3F])
CALLXVARARGS, RETVARARGS, JMPXVARARGS = op([0xDB, 0x38]), op([0xDB, 0x39]), op([0xDB, 0x3A])
CALLCCVARARGS = op([0xDB, 0x3B])
TRY = op([0xF2, 0xFF])


def throw(n):
    return op([0xF2, n]) if n < 64 else op([0xF2, 0xC0 | n >> 8, n & 0xFF])


def callccargs(params, retvals):
    return op([0xDB, 0x36, params << 4 | (retvals & 15)])


def deep(n):
    return [pushint(i) for i in range(n)]


def terminal():
    # The default handler (ExcQuit) entered by a jump pops the exit code; what it pops decides
    # the exit, and everything below stays.
    codes = {
        "0": (pushint(0),),
        "1": (pushint(1),),
        "5": (pushint(5),),
        "13": (pushint(13),),
        "minus-1": (pushint(-1),),
        "65536": (pushint(256), pushint(256), op([0xA8])),  # 256 * 256
        "nan": (PUSHNAN,),
        "null": (NULL,),
        "sentinel-only": (),  # nothing above the sentinel: the sentinel is the exit code
    }
    for name, push in codes.items():
        add(f"terminal-excquit-{name}", pushint(99), *push, PUSHC2, JMPX)
        # The same handler wrapped in an envelope (it saves c4).
        add(
            f"terminal-envelope-excquit-{name}",
            pushint(99),
            *push,
            EMPTY_CELL,
            PUSHC2,
            setc(4),
            JMPX,
        )
    # A really empty stack: popping the exit code fails, and that error is the exit code.
    add("terminal-excquit-empty-stack", PUSHC2, JMPX)
    add("terminal-envelope-excquit-empty-stack", EMPTY_CELL, PUSHC2, setc(4), JMPX)
    # Entered by the exception dispatch.
    add("terminal-throw-13", pushint(99), throw(13))
    add("terminal-throw-0", pushint(99), throw(0))
    add("terminal-throwarg-13", pushint(99), pushint(7), op([0xF2, 0xC8, 13]))
    add("terminal-commit-then-13", ONE_CELL, POPC4, COMMIT, pushint(13), PUSHC2, JMPX)
    # ExcQuit as the ninth dispatch of one jump: c0 is the default handler, eight REPEATEND 1
    # wrap it, and the implicit RET dispatches all nine.
    chain = [pushint(1), op([0xE5])] * 8
    for budget in range(355, 376):  # the run uses 372, measured with the C++ VM
        add(
            f"terminal-excquit-ninth-hop-{budget}",
            pushint(13),
            PUSHC2,
            POPC0,
            *chain,
            budget=budget,
        )


def capture():
    # A target that takes one argument and drops it: the captured continuation (CALLCC) or the
    # remaining code (JMPXDATA, RETDATA) is the argument it receives.
    takes_one = (cont(DROP, pushint(5)), op([0xEC, 0x01]))  # SETCONTARGS 0,1
    add("capture-callcc-generated-arg", *takes_one, CALLCC)
    add("capture-jmpxdata-generated-arg", *takes_one, JMPXDATA)
    add("capture-jmprefdata-generated-arg", op([0xDB, 0x3E], prog(DROP, pushint(5))))
    add("capture-retdata-generated-arg", *takes_one, POPC0, RETDATA)
    # The captured continuation, invoked: it holds the caller's c0 and c1 and its stack.
    add("capture-callcc-invoke", pushint(3), cont(JMPX), CALLCC, pushint(4))
    add("capture-callcc-keeps-c0", cont(pushint(8)), POPC0, cont(JMPX), CALLCC, pushint(4))
    add("capture-callcc-keeps-c1", cont(pushint(8)), POPC1, cont(JMPX), CALLCC, RETALT)
    for params, retvals in ((0, -1), (1, -1), (1, 0), (2, 1), (3, 2), (0, 0)):
        add(
            f"capture-callccargs-{params}-{retvals}",
            pushint(1),
            pushint(2),
            pushint(3),
            cont(JMPX),
            callccargs(params, retvals),
            pushint(4),
        )
        add(
            f"capture-callccvarargs-{params}-{retvals}",
            pushint(1),
            pushint(2),
            pushint(3),
            cont(JMPX),
            pushint(params),
            pushint(retvals),
            CALLCCVARARGS,
            pushint(4),
        )
    add("capture-callccargs-too-few", pushint(1), cont(JMPX), callccargs(3, -1))
    # Copies at the free stack depth and around it.
    for depth in (31, 32, 33, 40):
        add(f"capture-callccargs-1-depth-{depth}", *deep(depth), cont(JMPX), callccargs(1, -1))
        add(f"capture-callccargs-all-depth-{depth}", *deep(depth), cont(JMPX), CALLCC)


def varargs():
    target = cont(pushint(5))
    for name, params, retvals in (
        ("minus-1", (pushint(-1),), (pushint(-1),)),
        ("254", (pushint(254),), (pushint(0),)),
        ("255", (pushint(255),), (pushint(0),)),
        ("minus-2", (pushint(-2),), (pushint(0),)),
        ("nan", (PUSHNAN,), (pushint(0),)),
        ("null", (NULL,), (pushint(0),)),
        ("ret-255", (pushint(0),), (pushint(255),)),
        ("ret-254", (pushint(0),), (pushint(254),)),
    ):
        add(f"varargs-callx-{name}", pushint(1), target, *params, *retvals, CALLXVARARGS)
        add(f"varargs-callcc-{name}", pushint(1), target, *params, *retvals, CALLCCVARARGS)
        add(f"varargs-jmpx-{name}", pushint(1), target, *params, JMPXVARARGS)
        add(f"varargs-ret-{name}", pushint(1), *params, RETVARARGS)
    add("varargs-callx-short", target, CALLXVARARGS)
    add("varargs-jmpx-short", target, JMPXVARARGS)
    add("varargs-jmpx-params-short", target, pushint(3), JMPXVARARGS)
    add("varargs-callcc-params-short", target, pushint(3), pushint(0), CALLCCVARARGS)
    add("varargs-ret-empty", RETVARARGS)
    add("varargs-callx-not-cont", pushint(1), pushint(1), pushint(0), CALLXVARARGS)


def closure():
    body = cont(op([0xA0]))  # { ADD }
    for copy, more in ((0, -1), (0, 1), (1, -1), (1, 1), (2, 0), (2, 2), (3, 1)):
        add(
            f"closure-setcontargs-{copy}-{more}-invoke",
            pushint(1),
            pushint(2),
            pushint(3),
            body,
            setcontargs(copy, more),
            JMPX,
        )
        add(
            f"closure-setcontargs-{copy}-{more}",
            pushint(1),
            pushint(2),
            pushint(3),
            body,
            setcontargs(copy, more),
        )
        add(
            f"closure-blessargs-{copy}-{more}",
            pushint(1),
            pushint(2),
            pushint(3),
            op([0xC8, 0xC9, 0xD0]),
            op([0xEE, copy << 4 | (more & 15)]),
        )
    # Copying into a closure that already has arguments: concatenation, decrement, and the
    # 0x40000000 count when it takes more than allowed.
    add(
        "closure-concat",
        pushint(1),
        pushint(2),
        body,
        setcontargs(1, 2),
        pushint(3),
        SWAP,
        setcontargs(1, -1),
    )
    add("closure-too-many", pushint(1), pushint(2), body, setcontargs(0, 1), setcontargs(2, -1))
    add("closure-poison", pushint(1), body, setcontargs(0, 3), setcontargs(0, 1))
    add("closure-poison-invoked", pushint(1), body, setcontargs(0, 3), setcontargs(0, 1), JMPX)
    for more in (-1, 0, 2, 255, 256):
        add(f"closure-setnumvarargs-{more}", body, pushint(more), op([0xED, 0x12]))
        add(
            f"closure-setcontvarargs-1-{more}",
            pushint(1),
            body,
            pushint(1),
            pushint(more),
            op([0xED, 0x11]),
        )
        add(
            f"closure-blessvarargs-1-{more}",
            pushint(1),
            EMPTY_SLICE,
            pushint(1),
            pushint(more),
            op([0xED, 0x1F]),
        )
    add(
        "closure-setcontvarargs-copy-256",
        pushint(1),
        body,
        pushint(256),
        pushint(0),
        op([0xED, 0x11]),
    )
    # RETURNARGS: all but the top entries move into c0's stack.
    for count in (0, 1, 2, 3):
        add(
            f"closure-returnargs-{count}",
            pushint(1),
            pushint(2),
            pushint(3),
            op([0xED, count]),
            PUSHC0,
        )
        add(
            f"closure-returnargs-{count}-ret", pushint(1), pushint(2), pushint(3), op([0xED, count])
        )
        add(
            f"closure-returnvarargs-{count}",
            pushint(1),
            pushint(2),
            pushint(3),
            pushint(count),
            op([0xED, 0x10]),
            PUSHC0,
        )
    add("closure-returnargs-4-underflow", pushint(1), pushint(2), pushint(3), op([0xED, 4]))
    add("closure-returnvarargs-256", pushint(1), pushint(256), op([0xED, 0x10]))
    add(
        "closure-returnargs-into-closure",
        cont(pushint(9)),
        setcontargs(0, 1),
        POPC0,
        pushint(1),
        pushint(2),
        pushint(3),
        op([0xED, 1]),
    )
    for depth in (31, 32, 33, 40):
        add(f"closure-setcontargs-15-depth-{depth}", *deep(depth), body, setcontargs(15, -1))
        add(
            f"closure-blessvarargs-depth-{depth}",
            *deep(depth),
            EMPTY_SLICE,
            pushint(depth),
            pushint(-1),
            op([0xED, 0x1F]),
        )
        add(f"closure-returnargs-depth-{depth}", *deep(depth), op([0xED, 0]))


def popsave():
    # POPSAVE c(i): the old c(i) is saved into c0, then c(i) is replaced; for c0 the new value
    # is checked first. c2 is a handler that shows c0 after a failure.
    show_c0 = cont(PUSHC0)
    for index, values in (
        (0, {"cont": cont(pushint(5)), "int": I7}),
        (1, {"cont": cont(pushint(6)), "int": I7}),
        (4, {"cell": EMPTY_CELL, "int": I7}),
        (7, {"tuple": op([0x6F, 0x00]), "int": I7}),
    ):
        code = op([0xED, 0x90 | index])
        for vname, value in values.items():
            add(f"popsave-c{index}-{vname}", show_c0, POPC2, value, code, PUSHC0, RET)
            # The second POPSAVE finds c0's slot taken by the first.
            add(
                f"popsave-c{index}-{vname}-occupied",
                show_c0,
                POPC2,
                cont(pushint(9)),
                POPC0,
                value,
                code,
                value,
                code,
                PUSHC0,
            )
            add(f"popsave-c{index}-{vname}-alt", show_c0, POPC2, value, code, RETALT)
    add("popsave-c0-aliased", cont(pushint(5)), POPC0, PUSHC0, op([0xED, 0x90]), RET)
    add("popsave-empty", op([0xED, 0x90]))


def dict_jumps():
    # A dictionary with key 5 (8 bits) holding { PUSHINT 7 }.
    value = (pushint(0x77), NEWC, op([0xCB, 7]), op([0xC9, 0xD0]))  # the code 77 as a slice
    for signed, (setop, keyname) in ((True, (0x14, "i")), (False, (0x16, "u"))):
        build = (*value, pushint(5), NULL, pushint(8), op([0xF4, setop]))
        for args, name in ((0, "jmp"), (2, "exec")):
            base = 0xA0 | args | (0 if signed else 1)
            add(
                f"dict-{keyname}get{name}-hit",
                pushint(1),
                pushint(5),
                *build,
                pushint(8),
                op([0xF4, base]),
                pushint(9),
            )
            add(
                f"dict-{keyname}get{name}-miss",
                pushint(1),
                pushint(6),
                *build,
                pushint(8),
                op([0xF4, base]),
                pushint(9),
            )
            zbase = 0xBC | (args & 2) | (0 if signed else 1)
            add(
                f"dict-{keyname}get{name}z-hit",
                pushint(1),
                pushint(5),
                *build,
                pushint(8),
                op([0xF4, zbase]),
                pushint(9),
            )
            add(
                f"dict-{keyname}get{name}z-miss",
                pushint(1),
                pushint(6),
                *build,
                pushint(8),
                op([0xF4, zbase]),
                pushint(9),
            )
            for kname, keyv in (("300", 300), ("minus-1", -1), ("minus-200", -200)):
                add(
                    f"dict-{keyname}get{name}z-key-{kname}",
                    pushint(1),
                    pushint(keyv),
                    *build,
                    pushint(8),
                    op([0xF4, zbase]),
                    pushint(9),
                )
                add(
                    f"dict-{keyname}get{name}-key-{kname}",
                    pushint(1),
                    pushint(keyv),
                    *build,
                    pushint(8),
                    op([0xF4, base]),
                    pushint(9),
                )
            add(
                f"dict-{keyname}get{name}-key-nan",
                pushint(1),
                PUSHNAN,
                *build,
                pushint(8),
                op([0xF4, base]),
                pushint(9),
            )
            add(
                f"dict-{keyname}get{name}-key-null",
                pushint(1),
                NULL,
                *build,
                pushint(8),
                op([0xF4, base]),
                pushint(9),
            )
    # A prefix dictionary with the key "1" holding { PUSHINT 7 }: PFXDICTSET (x k D n - D' f).
    key = (pushint(1), NEWC, op([0xCB, 0]), op([0xC9, 0xD0]))  # the bit 1 as a slice
    build = (*value, *key, NULL, pushint(8), op([0xF4, 0x70]), DROP)
    for code, name in ((0xAA, "jmp"), (0xAB, "exec")):
        hit = (pushint(0xC0), NEWC, op([0xCB, 7]), op([0xC9, 0xD0]))  # 1100 0000
        miss = (pushint(0x40), NEWC, op([0xCB, 7]), op([0xC9, 0xD0]))  # 0100 0000
        add(
            f"dict-pfxget{name}-hit",
            pushint(1),
            *hit,
            *build,
            pushint(8),
            op([0xF4, code]),
            pushint(9),
        )
        add(
            f"dict-pfxget{name}-miss",
            pushint(1),
            *miss,
            *build,
            pushint(8),
            op([0xF4, code]),
            pushint(9),
        )


# PFXDICTSWITCH 8 with its prefix dictionary in the code: the root cell is a short label 1 and a
# leaf holding the code 77 (PUSHINT 7). The program pushes 1, the key slice (C0 is found under
# the prefix 1, 40 is not), PFXDICTSWITCH, then PUSHINT 9, which only runs when not found.
PFXDICTSWITCH_HIT = "b5ee9c7201010301001200020e7188d0f4ac08790201000353bc0002c0"
PFXDICTSWITCH_MISS = "b5ee9c7201010301001200020e7188d0f4ac08790201000353bc000240"


def dict_switch():
    add_boc("dict-pfxdictswitch-const-hit", PFXDICTSWITCH_HIT)
    add_boc("dict-pfxdictswitch-const-miss", PFXDICTSWITCH_MISS)


def chain():
    # One jump that dispatches k + 1 continuations: REPEATEND 1 k times makes c0 a chain of k
    # finished repeat loops, each continuing with the one before; the implicit RET at the end
    # dispatches all of them and then what c0 held at the start. Gas around the charges for
    # dispatches past the eighth (from version 9).
    # (set-up, gas of the whole run for k = 6 before any dispatch charge, measured with the C++
    # VM; each further REPEATEND 1 adds 36)
    ends = {
        "quit": ((), 221),
        "ordinary": ((cont(pushint(5)), POPC0), 388),
        "envelope": ((EMPTY_CELL, PUSHC0, setc(4), POPC0), 835),
    }
    for k in (6, 7, 8, 9, 10):
        for ename, (setup, base) in ends.items():
            for version in (8, 9, 16):
                total = base + 36 * (k - 6)
                for budget in range(total - 12, total + 7):
                    add(
                        f"chain-{k}-{ename}-v{version}-{budget}",
                        *setup,
                        *([pushint(1), op([0xE5])] * k),
                        budget=budget,
                        version=version,
                    )


def stackgas():
    # A call to a continuation that defines c0 is a jump: with nargs equal to the whole stack of
    # 33 entries nothing is copied and nothing charged; a call would split the stack and pay
    # for it (the run takes 1095 gas, measured with the C++ VM).
    tail = (
        *deep(33),
        cont(pushint(5)),
        pushint(33),
        op([0xED, 0x12]),  # SETNUMVARARGS
        PUSHC0,
        SWAP,
        setc(0),
        pushint(-1),
        pushint(-1),
        CALLXVARARGS,
    )
    for budget in (1094, 1095, BUDGET):
        add(f"stackgas-tail-call-whole-stack-{budget}", *tail, budget=budget)
    # Jumps and calls that copy stacks at the free depth (32) and around it.
    body = cont(pushint(5))
    for depth in (31, 32, 33, 40):
        stack = deep(depth)
        add(f"stackgas-jmpxargs-1-depth-{depth}", *stack, body, op([0xDB, 0x11]))
        add(f"stackgas-jmpxargs-all-depth-{depth}", *stack, body, JMPX)
        add(f"stackgas-callxargs-2-1-depth-{depth}", *stack, body, op([0xDA, 0x21]))
        add(f"stackgas-callxargs-p-depth-{depth}", *stack, body, op([0xDB, 0x02]))
        add(
            f"stackgas-closure-jump-depth-{depth}",
            *stack,
            pushint(9),
            body,
            setcontargs(1, 1),
            JMPX,
        )
        add(
            f"stackgas-closure-call-depth-{depth}",
            *stack,
            pushint(9),
            body,
            setcontargs(1, 0),
            CALLX,
        )
        add(
            f"stackgas-closure-callargs-depth-{depth}",
            *stack,
            pushint(9),
            body,
            setcontargs(1, 1),
            op([0xDA, 0x31]),
        )
        add(f"stackgas-ret-1-depth-{depth}", *stack, op([0xDB, 0x21]))
    # pass less than, equal to and greater than nargs.
    for passed in (0, 1, 2, 3):
        add(
            f"stackgas-pass-{passed}-nargs-2",
            pushint(1),
            pushint(2),
            pushint(3),
            body,
            setcontargs(0, 2),
            op([0xDB, 0x10 | passed]),
        )
        add(
            f"stackgas-callpass-{passed}-nargs-2",
            pushint(1),
            pushint(2),
            pushint(3),
            body,
            setcontargs(0, 2),
            op([0xDA, passed << 4 | 1]),
        )


def loop_more():
    body = cont(pushint(5))
    flag_body = {
        "true": cont(pushint(-1)),
        "false": cont(pushint(0)),
        "null": cont(NULL),
        "nan": cont(PUSHNAN),
    }
    for count in (0, -1, 1, 2):
        for name, code in (("repeat", 0xE4), ("repeatbrk", None)):
            enc = [code] if code else [0xE3, 0x14]
            add(f"loop2-{name}-{count}", pushint(count), body, op(enc), pushint(3))
        add(f"loop2-repeatend-{count}", pushint(count), op([0xE5]), pushint(3))
        add(f"loop2-repeatendbrk-{count}", pushint(count), op([0xE3, 0x15]), pushint(3))
    for fname, fbody in flag_body.items():
        add(f"loop2-until-{fname}", fbody, op([0xE6]), pushint(3), budget=3_000)
        add(f"loop2-untilbrk-{fname}", fbody, op([0xE3, 0x16]), pushint(3), budget=3_000)
        add(f"loop2-while-{fname}", fbody, cont(pushint(7)), op([0xE8]), pushint(3), budget=3_000)
        add(
            f"loop2-whilebrk-{fname}",
            fbody,
            cont(pushint(7)),
            op([0xE3, 0x18]),
            pushint(3),
            budget=3_000,
        )
    add("loop2-untilend", pushint(-1), op([0xE7]), pushint(3))
    add("loop2-untilendbrk", pushint(-1), op([0xE3, 0x17]), pushint(3))
    add("loop2-whileend", cont(pushint(0)), op([0xE9]), pushint(3))
    add("loop2-whileendbrk", cont(pushint(0)), op([0xE3, 0x19]), pushint(3))
    add("loop2-again-retalt", cont(RETALT), op([0xEA]), pushint(3), budget=3_000)
    add("loop2-againbrk-retalt", cont(RETALT), op([0xE3, 0x1A]), pushint(3), budget=3_000)
    add("loop2-againend", op([0xEB]), RETALT, budget=3_000)
    add("loop2-againendbrk", op([0xE3, 0x1B]), RETALT, budget=3_000)
    add("loop2-againbrk-empty", op([0xE3, 0x1A]))
    # A BRK loop's exit restores the c1 of before the loop (here not quit1, so it shows).
    add(
        "loop2-repeatbrk-restores-c1",
        cont(pushint(8)),
        POPC1,
        pushint(1),
        cont(RETALT),
        op([0xE3, 0x14]),
        RETALT,
    )
    add(
        "loop2-untilbrk-restores-c1",
        cont(pushint(8)),
        POPC1,
        cont(RETALT),
        op([0xE3, 0x16]),
        RETALT,
    )
    add("loop2-empty-body", pushint(2), cont(), op([0xE4]), pushint(3))
    # Bodies that save registers and have captured stacks.
    for i, saved in (
        (0, cont(pushint(8))),
        (1, cont(pushint(8))),
        (2, cont(pushint(8))),
        (4, EMPTY_CELL),
        (7, op([0x6F, 0x00])),
    ):
        add(
            f"loop2-repeat-body-saves-c{i}",
            pushint(2),
            saved,
            cont(pushint(5)),
            setc(i),
            op([0xE4]),
            pushint(3),
            budget=5_000,
        )
        add(
            f"loop2-until-body-saves-c{i}",
            saved,
            cont(pushint(-1)),
            setc(i),
            op([0xE6]),
            pushint(3),
            budget=5_000,
        )
    add(
        "loop2-repeat-closure-nargs",
        pushint(4),
        pushint(2),
        cont(op([0xA0])),
        setcontargs(1, 1),
        op([0xE4]),
        budget=5_000,
    )
    # Loops inside TRY and inside RUNVM.
    add(
        "loop2-repeat-in-try",
        cont(pushint(2), cont(throw(9)), op([0xE4])),
        cont(pushint(8)),
        TRY,
        pushint(3),
    )
    child = prog(pushint(2), cont(pushint(5)), op([0xE4]))
    add("loop2-repeat-in-runvm", pushint(0), op([0x89], child), op([0xDB, 0x40, 0x00]))


def compose_more():
    # SETEXITALT defines c0 and c1 on the continuation whatever the current code holds.
    add(
        "compose2-setexitalt-c1",
        cont(pushint(7)),
        POPC1,
        cont(pushint(5), RETALT),
        op([0xED, 0xF5]),
        RETALT,
    )
    # Conflicting definitions on both exits.
    k = (cont(pushint(7)), cont(pushint(6)), cont(pushint(5), RETALT), setc(1), setc(0))
    for name, enc in (("booland", 0xF0), ("boolor", 0xF1), ("composboth", 0xF2)):
        add(f"compose2-{name}-both-preset", *k, cont(pushint(9)), op([0xED, enc]), CALLX)
    # INVERT and SAMEALT replace live registers.
    add(
        "compose2-invert-twice", cont(pushint(8)), POPC1, op([0xED, 0xF8]), op([0xED, 0xF8]), RETALT
    )
    add("compose2-samealt-then-retalt", cont(pushint(8)), POPC0, op([0xED, 0xFA]), RETALT)
    # BOOLEVAL both outcomes, and on continuations with c0/c1 preset.
    add("compose2-booleval-true", cont(pushint(5)), op([0xED, 0xF9]))
    add("compose2-booleval-false", cont(pushint(5), RETALT), op([0xED, 0xF9]))
    add("compose2-booleval-preset-both", *k, op([0xED, 0xF9]))
    # TRY with preset body and handler exits, returning normally and by an exception.
    add(
        "compose2-try-body-preset-c0-normal",
        cont(pushint(8)),
        cont(pushint(5)),
        setc(0),
        cont(pushint(9)),
        TRY,
        pushint(3),
    )
    add(
        "compose2-try-body-preset-c2-throw",
        cont(pushint(8)),
        cont(throw(5)),
        setc(2),
        cont(pushint(9)),
        TRY,
        pushint(3),
    )
    add(
        "compose2-try-handler-preset-c0",
        cont(throw(5)),
        cont(pushint(8)),
        cont(pushint(9)),
        setc(0),
        TRY,
        pushint(3),
    )
    add(
        "compose2-try-handler-preset-c2",
        cont(throw(5)),
        cont(pushint(8)),
        cont(pushint(9), throw(6)),
        setc(2),
        TRY,
        pushint(3),
    )


def ctrmany_more():
    target = (PUSHC1, cont(pushint(5)), setc(0))
    for name, mask in (
        ("minus-1", (pushint(-1),)),
        ("0", (pushint(0),)),
        ("63", (pushint(63),)),
        ("64", (pushint(64),)),
        ("128", (pushint(128),)),
        ("255", (pushint(255),)),
        ("256", (pushint(256),)),
        ("nan", (PUSHNAN,)),
        ("null", (NULL,)),
    ):
        add(f"ctrmany2-x-{name}", *target, *mask, op([0xED, 0xE4]), JMPX)
    add("ctrmany2-x-empty", op([0xED, 0xE4]))
    add("ctrmany2-x-short", pushint(1), op([0xED, 0xE4]))
    add("ctrmany2-x-not-cont", pushint(1), pushint(1), op([0xED, 0xE4]))
    add("ctrmany2-not-cont", pushint(1), op([0xED, 0xE3, 1]))
    add("ctrmany2-c7-occupied", op([0x6F, 0x00]), cont(pushint(5)), setc(7), op([0xED, 0xE3, 0x80]))
    # A taken slot does not excuse a value of the wrong type.
    add(
        "ctrmany2-setcontctr-taken-wrong-type",
        EMPTY_CELL,
        cont(pushint(5)),
        setc(4),
        I7,
        SWAP,
        setc(4),
    )
    # Live registers: null is not a continuation, and a register that does not exist or holds
    # nothing cannot be pushed by index.
    add("ctrmany2-popctr-c2-null", NULL, POPC2)
    add("ctrmany2-popctr-c0-int", I7, POPC0)
    for index in (2, 6, 7, 8, 16, 17):
        add(f"ctrmany2-pushctrx-{index}", pushint(index), op([0xED, 0xE0]))
        add(f"ctrmany2-popctrx-{index}", op([0x6F, 0x00]), pushint(index), op([0xED, 0xE1]))
    # A jump that cannot take its arguments changes no register: the handler sees c0 as it was.
    add(
        "ctrmany2-jump-depth-error-keeps-c0",
        cont(PUSHC0),
        POPC2,
        cont(pushint(9)),
        cont(pushint(5)),
        setc(0),
        setcontargs(0, 3),
        JMPX,
    )
    # Single-register setters with a conflicting value, at version 13, 14 and 16, invoked.
    for v in (13, 14, 16):
        add(
            f"ctrmany2-setcontctr-conflict-v{v}",
            cont(pushint(9)),
            cont(pushint(7)),
            cont(pushint(5)),
            setc(0),
            setc(0),
            CALLX,
            version=v,
        )
        add(
            f"ctrmany2-setcontctrx-conflict-v{v}",
            cont(pushint(9)),
            cont(pushint(7)),
            cont(pushint(5)),
            pushint(0),
            op([0xED, 0xE2]),
            pushint(0),
            op([0xED, 0xE2]),
            CALLX,
            version=v,
        )
        add(
            f"ctrmany2-setretctr-conflict-v{v}",
            cont(pushint(9)),
            op([0xED, 0x71]),
            cont(pushint(7)),
            op([0xED, 0x71]),
            RETALT,
            version=v,
        )
        add(
            f"ctrmany2-setaltctr-conflict-v{v}",
            cont(pushint(9)),
            op([0xED, 0x80]),
            cont(pushint(7)),
            op([0xED, 0x80]),
            RETALT,
            version=v,
        )
        add(
            f"ctrmany2-savectr-twice-v{v}",
            cont(pushint(5)),
            POPC0,
            op([0xED, 0xA1]),
            cont(pushint(6)),
            POPC1,
            op([0xED, 0xA1]),
            RET,
            version=v,
        )
        add(f"ctrmany2-savectr-c7-twice-v{v}", op([0xED, 0xA7]), op([0xED, 0xA7]), version=v)
        add(
            f"ctrmany2-many-conflict-v{v}",
            PUSHC1,
            cont(pushint(5)),
            setc(0),
            op([0xED, 0xE3, 1]),
            JMPX,
            version=v,
        )


def save_more():
    # SAVEBOTHCTR c0 with c0 and c1 different, invoked through both exits; the source changed
    # between two saves.
    setup = (cont(pushint(5)), POPC0, cont(pushint(6)), POPC1)
    add("save2-saveboth-c0-ret", *setup, op([0xED, 0xC0]), RET, budget=5_000)
    add("save2-saveboth-c0-retalt", *setup, op([0xED, 0xC0]), RETALT, budget=5_000)
    add("save2-saveboth-c1-ret", *setup, op([0xED, 0xC1]), RET, budget=5_000)
    add(
        "save2-save-changed-source",
        *setup,
        op([0xED, 0xA1]),
        cont(pushint(7)),
        POPC1,
        op([0xED, 0xA1]),
        RET,
        budget=5_000,
    )
    add("save2-saveboth-c4-commit", ONE_CELL, POPC4, op([0xED, 0xC4]), EMPTY_CELL, POPC4, RET)


def fuzz():
    # The seeded programs of vm_closure_fuzz.py, with their default seeds and count.
    for row in fuzz_scenarios():
        ROWS.append([f"family-{row[0]}"] + row[1:])


FAMILIES = {
    "xchg": xchg,
    "hashext": hashext,
    "bls": bls,
    "save": save,
    "ctrmany": ctrmany,
    "jump": jump,
    "compose": compose,
    "loop": loop,
    "terminal": terminal,
    "capture": capture,
    "varargs": varargs,
    "closure": closure,
    "popsave": popsave,
    "dict": dict_jumps,
    "dict-switch": dict_switch,
    "chain": chain,
    "stackgas": stackgas,
    "loop2": loop_more,
    "compose2": compose_more,
    "ctrmany2": ctrmany_more,
    "save2": save_more,
    "fuzz": fuzz,
}
# The families vm_prefix_scenarios.py runs.
COMPARED = tuple(FAMILIES)


def scenarios(families=COMPARED):
    ROWS.clear()
    for name in families:
        FAMILIES[name]()
    return list(ROWS)


def main(args):
    if not args or any(a not in FAMILIES for a in args[1:]):
        sys.exit("Usage: vm_family_scenarios.py <out.tsv> [family ...]")
    rows = scenarios(args[1:] or COMPARED)
    assert len({r[0] for r in rows}) == len(rows), "duplicate ids"
    Path(args[0]).write_text("".join("\t".join(r) + "\n" for r in rows))
    print(f"{len(rows)} scenarios")


if __name__ == "__main__":
    main(sys.argv[1:])
