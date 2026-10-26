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
- loop: loops over closure bodies and conditions, and bodies that save registers.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from suite_scenarios import op, prog, pushint  # noqa: E402

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


FAMILIES = {
    "xchg": xchg,
    "hashext": hashext,
    "bls": bls,
    "save": save,
    "ctrmany": ctrmany,
    "jump": jump,
    "compose": compose,
    "loop": loop,
}
# The families vm_prefix_scenarios.py runs; the others still differ (continuation model).
COMPARED = ("xchg", "hashext")


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
