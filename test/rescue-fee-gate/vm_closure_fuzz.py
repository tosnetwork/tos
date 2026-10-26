"""Seeded programs over continuations, for vm-endstate on both VMs.

Each program is a short random sequence of instructions that build, change and enter
continuations: closures, loops and their exits, savelist definitions, captures, TRY and THROW,
under small and large gas budgets and at a few global versions. The sequence is drawn from a
fixed grammar with a fixed seed, so every run produces the same rows; both drivers run them and
must agree. It complements the directed rows of vm_family_scenarios.py: it finds combinations
nobody wrote down.

Usage: vm_closure_fuzz.py <out.tsv> [--seeds a,b,...] [--count n]
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from suite_scenarios import op, prog, pushint  # noqa: E402

SEEDS = (1, 2, 3, 4, 5)
COUNT = 400  # programs per seed
VERSIONS = (16, 16, 16, 16, 9, 8, 13)
BUDGETS = (150, 400, 1_000, 3_000, 20_000, 100_000)
MAX_DEPTH = 2  # nesting of continuation literals
MAX_OPS = 10


def fixed(*bytes_):
    return lambda rng, depth: op(list(bytes_))


def small_int(rng, depth):
    return pushint(rng.choice((-1, 0, 1, 2, 3, 5)))


def cont_literal(rng, depth):
    if depth >= MAX_DEPTH:
        return op([0x8A], prog(pushint(rng.choice((0, 7)))))
    body = [small_int(rng, depth)] * rng.randint(0, 1)
    body += [draw(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return op([0x8A], prog(*body))


def setcontargs(rng, depth):
    return op([0xEC, rng.randint(0, 2) << 4 | (rng.choice((-1, 0, 1, 2)) & 15)])


def ctr(base, indexes):
    return lambda rng, depth: op([0xED, base | rng.choice(indexes)])


def args_byte(prefix):
    return lambda rng, depth: op([*prefix, rng.randint(0, 2) << 4 | rng.randint(0, 2)])


def nibble(prefix_byte, high):
    return lambda rng, depth: op([prefix_byte, high | rng.randint(0, 2)])


def throw(rng, depth):
    return op([0xF2, rng.choice((0, 1, 5, 13))])


def throwarg(rng, depth):
    return op([0xF2, 0xC8, rng.choice((0, 5, 13))])


def cell(rng, depth):
    return op([0xC8, 0xC9])


# (weight, generator)
GRAMMAR = [
    (6, small_int),
    (8, cont_literal),
    (2, setcontargs),
    (2, fixed(0x20)),  # DUP
    (2, fixed(0x30)),  # DROP
    (2, fixed(0x01)),  # SWAP
    (1, fixed(0xA4)),  # INC
    (1, cell),
    (3, ctr(0x40, (0, 1, 2, 3))),  # PUSHCTR
    (2, ctr(0x50, (0, 1, 2, 4))),  # POPCTR
    (3, ctr(0x60, (0, 1, 2, 4))),  # SETCONTCTR
    (1, ctr(0x70, (0, 1, 2))),  # SETRETCTR
    (1, ctr(0x80, (0, 1, 2))),  # SETALTCTR
    (1, ctr(0x90, (0, 1, 4))),  # POPSAVE
    (1, ctr(0xA0, (0, 1, 2, 4))),  # SAVECTR
    (1, ctr(0xB0, (0, 1, 2))),  # SAVEALTCTR
    (1, ctr(0xC0, (0, 1, 2))),  # SAVEBOTHCTR
    (3, fixed(0xD9)),  # JMPX
    (3, fixed(0xD8)),  # EXECUTE
    (2, args_byte([0xDA])),  # CALLXARGS p,r
    (1, nibble(0xDB, 0x10)),  # JMPXARGS p
    (1, nibble(0xDB, 0x20)),  # RETARGS p
    (2, fixed(0xDB, 0x30)),  # RET
    (2, fixed(0xDB, 0x31)),  # RETALT
    (1, fixed(0xDB, 0x32)),  # RETBOOL
    (2, fixed(0xDB, 0x34)),  # CALLCC
    (1, fixed(0xDB, 0x35)),  # JMPXDATA
    (1, args_byte([0xDB, 0x36])),  # CALLCCARGS p,r
    (2, fixed(0xE0)),  # IFJMP
    (1, fixed(0xE1)),  # IFNOTJMP
    (2, fixed(0xDE)),  # IF
    (2, fixed(0xE2)),  # IFELSE
    (2, fixed(0xE4)),  # REPEAT
    (1, fixed(0xE5)),  # REPEATEND
    (2, fixed(0xE6)),  # UNTIL
    (1, fixed(0xE7)),  # UNTILEND
    (2, fixed(0xE8)),  # WHILE
    (1, fixed(0xE9)),  # WHILEEND
    (1, fixed(0xEA)),  # AGAIN
    (1, fixed(0xE3, 0x14)),  # REPEATBRK
    (1, fixed(0xE3, 0x16)),  # UNTILBRK
    (1, fixed(0xE3, 0x18)),  # WHILEBRK
    (1, fixed(0xE3, 0x1A)),  # AGAINBRK
    (1, fixed(0xE3, 0x1B)),  # AGAINENDBRK
    (1, fixed(0xED, 0xF0)),  # BOOLAND
    (1, fixed(0xED, 0xF1)),  # BOOLOR
    (1, fixed(0xED, 0xF2)),  # COMPOSBOTH
    (1, fixed(0xED, 0xF3)),  # ATEXIT
    (1, fixed(0xED, 0xF4)),  # ATEXITALT
    (1, fixed(0xED, 0xF5)),  # SETEXITALT
    (1, fixed(0xED, 0xF6)),  # THENRET
    (1, fixed(0xED, 0xF7)),  # THENRETALT
    (1, fixed(0xED, 0xF8)),  # INVERT
    (2, fixed(0xED, 0xF9)),  # BOOLEVAL
    (1, fixed(0xED, 0xFA)),  # SAMEALT
    (1, fixed(0xED, 0xFB)),  # SAMEALTSAVE
    (1, fixed(0xED, 0xE3, 0x03)),  # SETCONTCTRMANY c0,c1
    (2, fixed(0xF2, 0xFF)),  # TRY
    (1, throw),
    (1, throwarg),
    (1, fixed(0xF8, 0x0F)),  # COMMIT
]
TOTAL = sum(w for w, _ in GRAMMAR)


def draw(rng, depth):
    pick = rng.randrange(TOTAL)
    for weight, gen in GRAMMAR:
        if pick < weight:
            return gen(rng, depth)
        pick -= weight
    raise AssertionError("weights")


def scenarios(seeds=SEEDS, count=COUNT):
    rows = []
    for seed in seeds:
        rng = random.Random(seed)
        for i in range(count):
            # Operands first, so that most instructions find what they take.
            ops = [rng.choice((small_int, cont_literal))(rng, 0) for _ in range(rng.randint(2, 5))]
            ops += [draw(rng, 0) for _ in range(rng.randint(1, MAX_OPS))]
            version = rng.choice(VERSIONS)
            budget = rng.choice(BUDGETS)
            rows.append(
                [f"fuzz-{seed}-{i}", str(version), str(budget), "V"]
                + ["skip"] * 5
                + [prog(*ops).boc().hex()]
            )
    return rows


def main(args):
    if not args:
        sys.exit(__doc__)
    seeds, count = SEEDS, COUNT
    rest = args[1:]
    while rest:
        if rest[0] == "--seeds":
            seeds = tuple(int(s) for s in rest[1].split(","))
        elif rest[0] == "--count":
            count = int(rest[1])
        else:
            sys.exit(__doc__)
        rest = rest[2:]
    rows = scenarios(seeds, count)
    Path(args[0]).write_text("".join("\t".join(r) + "\n" for r in rows))
    print(f"{len(rows)} scenarios")


if __name__ == "__main__":
    main(sys.argv[1:])
