"""EXPERIMENT: PQCHECKSIG_SUITE cross-VM scenarios (C++ VM against the Rust VM).

Writes one tab-separated scenario per line:
    id  version  budget  expect  suite  message  context  signature  public_key  [code]
where each operand is a BOC in hex, "int:N" for an integer, or "skip" (not pushed). The stack is
pushed bottom to top in that order (message first, suite last); the program is F93102, or the
code cell given as a BOC in the optional tenth column. `expect` is V (valid), I (invalid),
E<code> (exception), or R<n> (normal exit with n alone on the stack), checked against both VMs.

All inputs are PUBLIC TEST DATA. Needs SLH_TOOL, MLDSA_TOOL, LMS_TOOL and HASH_SIGS_DEMO.
Usage: suite_scenarios.py <out.tsv>
"""

# ruff: noqa: E402
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
sys.path.insert(0, str(HERE))
import fee_key
from cells import Cell

CTX_AUTH = b"TOS-AUTH-SLH-DSA-SHA2-128S-v1"
CTX_ML = b"TOS-AUTH-V2-ML-DSA-44-v1"
VERSION = 16  # unified development genesis
BUDGET = 1_000_000
# Gas each child out of gas consumed, measured with the C++ VM.
CHILD_GAS = {
    "instruction": 108,
    "out-of-range-top": 102,
    "implicit-ret": 104,
    "implicit-jmpref": 128,
    "exception-price": 86,
    "c2-switch": 1072,
    "setgaslimit": 106,
    "nested-restore": 301,
}
C2_SWITCH_LIMIT = 1_060  # exception price paid; its 47-value stack is not


def chain(data):
    parts = [data[i : i + 127] for i in range(0, len(data), 127)] or [b""]
    tail = None
    for part in reversed(parts):
        node = Cell().raw(part)
        if tail is not None:
            node.ref(tail)
        tail = node
    return tail


def boc(data):
    return chain(data).boc().hex()


def run(*args):
    return subprocess.run([str(a) for a in args], check=True, capture_output=True, text=True).stdout


# A minimal assembler for the program scenarios. Every instruction used is byte aligned; an
# instruction is (bytes, refs). A program longer than one cell continues in its last reference,
# which the VM enters by an implicit jump once the cell's bits are used up.
def op(data, *refs):
    return (bytes(data), list(refs))


def program(*ops):
    chunks, cur, bits, refs = [], [], 0, 0
    for data, rs in ops:
        if bits + 8 * len(data) > 1023 or refs + len(rs) > 3:
            chunks.append(cur)
            cur, bits, refs = [], 0, 0
        cur.append((data, rs))
        bits += 8 * len(data)
        refs += len(rs)
    chunks.append(cur)
    tail = None
    for chunk in reversed(chunks):
        node = Cell()
        for data, rs in chunk:
            node.raw(data)
            for r in rs:
                node.ref(r)
        if tail is not None:
            node.ref(tail)
        tail = node
    return tail


def pushint(n):
    if -5 <= n <= 10:
        return op([0x70 | (n & 0xF)])
    if -128 <= n <= 127:
        return op([0x80, n & 0xFF])
    assert -32768 <= n <= 32767
    return op([0x81, *(n & 0xFFFF).to_bytes(2, "big")])


DROP = op([0x30])
AND = op([0xB0])
TRY = op([0xF2, 0xFF])
ONLYTOP = (pushint(1), op([0x6A]))  # 1 ONLYTOPX: leave only the top of the stack


def blkdrop(n):
    return op([0x5F, n])


def call(operands, suite):
    """Pushes message, context, signature and key from references, then runs F93102."""
    return [op([0x88], chain(x)) for x in operands] + [pushint(suite), op([0xF9, 0x31, 0x02])]


def runvm(child, flags, gas_limit=None, ret_vals=None):
    """RUNVM with no arguments for the child: n=0, code, [ret_vals for +256], [an empty data cell
    for +4], [gas limit for +8]."""
    ops = [pushint(0), op([0x89], child)]
    if flags & 256:
        ops.append(pushint(ret_vals))
    if flags & 4:
        ops.append(op([0x88], Cell()))
    if flags & 8:
        ops.append(pushint(gas_limit))
    return ops + [op([0xDB, 0x40 | flags >> 8, flags & 0xFF])]


def flat(*parts):
    out = []
    for p in parts:
        if isinstance(p, tuple) and p and isinstance(p[0], bytes):
            out.append(p)
        else:
            out.extend(flat(*p))
    return out


def prog(*parts):
    return program(*flat(*parts))


def main(out):
    rows = []

    def add(
        name,
        expect,
        suite,
        message,
        context,
        signature,
        key,
        budget=BUDGET,
        version=VERSION,
        code=None,
    ):
        def field(v):
            if v is None:
                return "skip"
            if isinstance(v, str):
                return v
            return boc(v)

        rows.append(
            [
                name,
                str(version),
                str(budget),
                expect,
                suite,
                field(message),
                field(context),
                field(signature),
                field(key),
            ]
            + ([] if code is None else [code.boc().hex()])
        )

    def add_program(name, expect, code, budget=BUDGET, version=VERSION):
        add(name, expect, "skip", None, None, None, None, budget=budget, version=version, code=code)

    tmp = Path(tempfile.mkdtemp())
    msg = bytes(range(32))

    # Suite 1: ML-DSA-44.
    run(os.environ["MLDSA_TOOL"], "keygen", "11" * 32, tmp / "ml.pk", tmp / "ml.sk")
    (tmp / "m").write_bytes(msg)
    run(os.environ["MLDSA_TOOL"], "sign", tmp / "ml.sk", CTX_ML.hex(), tmp / "m", tmp / "ml.sig")
    mpk, msig = (tmp / "ml.pk").read_bytes(), (tmp / "ml.sig").read_bytes()

    def flip(b, i=10):
        return b[:i] + bytes([b[i] ^ 1]) + b[i + 1 :]

    add("s1-valid", "V", "int:1", msg, CTX_ML, msig, mpk)
    add("s1-bitflip", "I", "int:1", msg, CTX_ML, flip(msig), mpk)
    add("s1-other-context", "I", "int:1", msg, CTX_AUTH, msig, mpk)
    add("s1-short-key", "E9", "int:1", msg, CTX_ML, msig, mpk[:-1])
    # Priced as the Ed25519 check: the first check of a transaction is free, so what s1
    # costs is its operand cell loads. 3,338 is one gas short of s1-valid's measured 3,339;
    # 1,000 runs out while the operands are still being loaded.
    add("s1-out-of-gas", "E-14", "int:1", msg, CTX_ML, msig, mpk, budget=3_338)
    add("s1-out-of-gas-loading", "E-14", "int:1", msg, CTX_ML, msig, mpk, budget=1_000)

    # Suite 2: Falcon-512 padded, a known-valid vector from the Falcon suite.
    falcon = json.loads((ROOT / "test/pq-falcon512/vectors.json").read_text())["vectors"]
    fv = next(v for v in falcon if v["expected"] == "V" and v["message"])
    fmsg, fsig, fpk = (bytes.fromhex(fv[k]) for k in ("message", "signature", "public_key"))
    add("s2-valid", "V", "int:2", fmsg, b"", fsig, fpk)
    add("s2-bitflip", "I", "int:2", fmsg, b"", flip(fsig, 100), fpk)
    add("s2-nonempty-context", "E9", "int:2", fmsg, b"x", fsig, fpk)
    add("s2-refused-before-genesis", "E6", "int:2", fmsg, b"", fsig, fpk, version=15)

    # Suite 3: SLH-DSA-SHA2-128s.
    pk_hex, sk_hex = run(os.environ["SLH_TOOL"], "keygen", "22" * 48).split()
    run(os.environ["SLH_TOOL"], "sign", sk_hex, CTX_AUTH.hex(), tmp / "m", tmp / "slh.sig")
    spk, ssig = bytes.fromhex(pk_hex), (tmp / "slh.sig").read_bytes()
    add("s3-valid", "V", "int:3", msg, CTX_AUTH, ssig, spk)
    add("s3-bitflip", "I", "int:3", msg, CTX_AUTH, flip(ssig, 4000), spk)
    add("s3-no-context", "I", "int:3", msg, b"", ssig, spk)
    add("s3-long-signature", "E9", "int:3", msg, CTX_AUTH, ssig + b"\0", spk)
    add("s3-short-signature", "E9", "int:3", msg, CTX_AUTH, ssig[:-1], spk)
    add("s3-out-of-gas-base", "E-14", "int:3", msg, CTX_AUTH, ssig, spk, budget=749_000)

    # Suite 4: the fee profile H20/W4, from a key derived like a wallet's.
    seed, ident = fee_key.derive_fee_seed(bytes(32), bytes(32), 42, 0, 0, bytes(32))
    largs = [seed.hex(), ident.hex(), "20", tmp / "fee.tree"]
    lpk = bytes.fromhex(run(os.environ["LMS_TOOL"], "keygen", *largs).strip())
    run(os.environ["LMS_TOOL"], "sign", *largs, 3, tmp / "m", "00" * 32, tmp / "fee.sig")
    lsig = (tmp / "fee.sig").read_bytes()
    add("s4-h20w4-valid", "V", "int:4", msg, b"", lsig, lpk)
    add("s4-h20w4-bitflip", "I", "int:4", msg, b"", flip(lsig, 300), lpk)
    add("s4-h20w4-other-message", "I", "int:4", bytes(32), b"", lsig, lpk)
    add("s4-nonempty-context", "E9", "int:4", msg, b"x", lsig, lpk)
    add("s4-trailing-byte", "E9", "int:4", msg, b"", lsig + b"\0", lpk)
    add("s4-nspk-1", "I", "int:4", msg, b"", b"\0\0\0\1" + lsig[4:], lpk)
    add(
        "s4-q-out-of-range",
        "I",
        "int:4",
        msg,
        b"",
        lsig[:4] + (1 << 20).to_bytes(4, "big") + lsig[8:],
        lpk,
    )
    add(
        "s4-unsupported-lms-type",
        "E9",
        "int:4",
        msg,
        b"",
        lsig,
        lpk[:4] + (9).to_bytes(4, "big") + lpk[8:],
    )
    add("s4-l2-key", "E9", "int:4", msg, b"", lsig, (2).to_bytes(4, "big") + lpk[4:])
    add("s4-out-of-gas-before-signature", "E-14", "int:4", msg, b"", lsig, lpk, budget=3_000)
    for params, expect in (
        ("20/4", "V"),
        ("5/8", "E9"),
        ("10/4", "E9"),
        ("15/2", "E9"),
        ("20/2", "E9"),
    ):
        name = "k" + params.replace("/", "_")
        run(os.environ["HASH_SIGS_DEMO"], "genkey", tmp / name, params)
        (tmp / "m4").write_bytes(msg)
        subprocess.run(
            [os.environ["HASH_SIGS_DEMO"], "sign", name, "m4"],
            cwd=tmp,
            check=True,
            capture_output=True,
        )
        add(
            f"s4-h{params.replace('/', 'w')}-random-key",
            expect,
            "int:4",
            msg,
            b"",
            (tmp / "m4.sig").read_bytes(),
            (tmp / f"{name}.pub").read_bytes(),
        )

    # Dispatcher.
    add("unknown-suite-0", "E5", "int:0", msg, CTX_ML, msig, mpk)
    add("unknown-suite-5", "E5", "int:5", msg, CTX_ML, msig, mpk)
    add("suite-256", "E5", "int:256", msg, CTX_ML, msig, mpk)
    add("suite-negative", "E5", "int:-1", msg, CTX_ML, msig, mpk)
    add("suite-is-a-cell", "E7", Cell().boc().hex(), msg, CTX_ML, msig, mpk)
    add("key-is-an-int", "E7", "int:1", msg, CTX_ML, msig, "int:7")
    add("stack-underflow", "E2", "int:1", None, CTX_ML, msig, mpk)
    add("version-15", "E6", "int:1", msg, CTX_ML, msig, mpk, version=15)

    # Steps: the VM counts one step for every instruction it fetches, also for one that fails
    # before it is decoded. Each row pushes 7 first, so a correct count is 3 (PUSHINT, the
    # failing instruction, the exception).
    add_program("steps-unassigned-opcode", "E6", prog(pushint(7), op([0xF4, 0xFF])))
    add_program("steps-truncated-prefix-ff", "E6", prog(pushint(7), op([0xFF])))
    add_program("steps-truncated-prefix-f9", "E6", prog(pushint(7), op([0xF9])))

    # A child VM that runs out of gas: the parent ends normally, so every row observes what the
    # child returned, not the parent running out itself. A child out of gas returns exactly one
    # value, the gas it consumed, with exit code -14; +8 also returns that gas.
    exit_code = (DROP, op([0x31]))  # DROP the gas, NIP the value: the exit code is left
    value = (op([0x5B]),)  # 2DROP: the value the child returned is left
    depth = (op([0x68]), ONLYTOP)
    sevens = prog(*[pushint(7)] * 30)
    loop = (op([0x90]), op([0xEA]))  # PUSHCONT {} AGAIN: implicit returns until out of gas
    c2_switch = prog(
        *[pushint(7)] * 45,
        op([0x90]),
        *[op([0xEC, 0xFF])] * 3,  # SETCONTARGS 15: 45 values move into the continuation
        op([0xED, 0x52]),  # POP c2: switching to it pays for its 47-value stack
        pushint(1),
        pushint(0),
        op([0xA9, 0x04]),  # DIV by zero
    )
    children = {
        # In-range integers on the child's stack: the Rust VM used to take the top one for an
        # exit code.
        "instruction": (sevens, 100),
        "out-of-range-top": (prog(*[pushint(5000)] * 10), 100),
        "implicit-ret": (prog(pushint(7), *loop), 100),
        "implicit-jmpref": (Cell().raw(b"\x77").ref(Cell().raw(b"\x77")), 50),
        "exception-price": (prog(pushint(7), op([0x5B])), 40),
        "c2-switch": (c2_switch, C2_SWITCH_LIMIT),
        "setgaslimit": (prog(*[pushint(7)] * 3, pushint(20), op([0xF8, 0x01])), 1_000),
        "nested-restore": (prog(pushint(7), runvm(prog(*loop), 0)), 300),
    }
    for path, (child, limit) in children.items():
        add_program(f"child-oog-{path}-exit", "R-14", prog(runvm(child, 8, limit), exit_code))
        add_program(
            f"child-oog-{path}-value",
            f"R{CHILD_GAS[path]}",
            prog(runvm(child, 8, limit), value),
        )
    child, limit = children["instruction"]
    gas = CHILD_GAS["instruction"]
    for flags, suffix in ((8, ""), (136, "-isolated")):
        add_program(f"child-oog-gas{suffix}", f"R{gas}", prog(runvm(child, flags, limit), ONLYTOP))
        add_program(f"child-oog-depth{suffix}", "R3", prog(runvm(child, flags, limit), depth))
    add_program("child-oog-exit-isolated", "R-14", prog(runvm(child, 136, limit), exit_code))
    add_program("child-oog-value-isolated", f"R{gas}", prog(runvm(child, 136, limit), value))
    child, limit = children["implicit-ret"]
    for n in (0, 3):
        add_program(f"child-oog-ret-vals-{n}-depth", "R3", prog(runvm(child, 264, limit, n), depth))
    add_program(
        "child-oog-setgaslimit-gas",
        f"R{CHILD_GAS['setgaslimit']}",
        prog(runvm(children["setgaslimit"][0], 8, 1_000), ONLYTOP),
    )
    # Controls: the same child with enough gas; THROW 13, which is not out of gas; an ordinary
    # unhandled error; and too few return values.
    add_program("child-enough-gas-exit", "R0", prog(runvm(sevens, 8, 10_000), DROP, ONLYTOP))
    throw13 = prog(pushint(7), op([0xF2, 0x0D]))
    add_program("child-throw-13-exit", "R13", prog(runvm(throw13, 8, 1_000), exit_code))
    error = children["exception-price"][0]
    add_program("child-error-exit", "R2", prog(runvm(error, 8, 1_000), exit_code))
    add_program("child-too-few-values-exit", "R-3", prog(runvm(prog(), 264, 1_000, 3), exit_code))
    # A child that jumps to its default exception handler with an exit code it chose: 13 is not
    # out of gas. The handler pops only the exit code; what is below it is returned. A non-integer
    # exit code fails the type check (7) and is consumed.
    c2_jump = (op([0xED, 0x42]), op([0xD9]))  # PUSH c2, JMPX
    exits_13 = prog(pushint(5), pushint(7), pushint(13), c2_jump)
    add_program("child-exits-13-via-c2-exit", "R13", prog(runvm(exits_13, 8, 1_000), exit_code))
    add_program("child-exits-13-via-c2-value", "R7", prog(runvm(exits_13, 8, 1_000), value))
    add_program("child-exits-13-via-c2-depth", "R3", prog(runvm(exits_13, 8, 1_000), depth))
    exits_null = prog(pushint(5), op([0x6D]), c2_jump)  # PUSHNULL
    add_program("child-exits-null-via-c2-exit", "R7", prog(runvm(exits_null, 8, 1_000), exit_code))
    add_program("child-exits-null-via-c2-value", "R5", prog(runvm(exits_null, 8, 1_000), value))
    add_program("exits-13-via-c2", "E13", prog(pushint(7), pushint(13), c2_jump))
    add_program("throw-13", "E13", prog(pushint(7), op([0xF2, 0x0D])))

    # Data and actions (+4, +32) of a child: what it last committed, or from version 11 null if
    # it never committed. Each child stores a byte in a cell for c4 or c5; a cell costs 500 gas.
    def store(byte, ctr):
        return (pushint(byte), op([0xC8]), op([0xCB, 0x07]), op([0xC9]), op([0xED, 0x50 | ctr]))

    commit = op([0xF8, 0x0F])
    committed = prog(store(42, 4), store(43, 5), commit, store(99, 4), store(98, 5), *loop)
    byte = (DROP, op([0xD0]), op([0xD7, 0x0B, 0x07]), ONLYTOP)  # the cell's first byte
    is_null = (DROP, op([0x6E]), ONLYTOP)
    for flag, name, want in ((4, "data", 42), (32, "actions", 43)):
        add_program(
            f"child-oog-committed-{name}", f"R{want}", prog(runvm(committed, 8 | flag, 5_000), byte)
        )
        add_program(
            f"child-oog-uncommitted-{name}", "R-1", prog(runvm(prog(*loop), 8 | flag, 100), is_null)
        )
        add_program(
            f"child-error-uncommitted-{name}", "R-1", prog(runvm(error, 8 | flag, 1_000), is_null)
        )
        # A child that ends normally commits automatically.
        add_program(
            f"child-ends-normally-{name}", "R0", prog(runvm(prog(), 8 | flag, 1_000), is_null)
        )

    # RUNVM exists from version 4; data and actions can be returned before version 11.
    enough = prog(runvm(sevens, 8, 10_000), DROP, ONLYTOP)
    add_program("runvm-version-3", "E6", enough, version=3)
    add_program("runvm-version-4", "R0", enough, version=4)
    add_program(
        "runvmx-version-3",
        "E6",
        prog(pushint(0), op([0x89], sevens), pushint(0), op([0xDB, 0x50]), ONLYTOP),
        version=3,
    )
    committed_data = prog(runvm(committed, 12, 5_000), byte)
    add_program("child-oog-committed-data-version-10", "R42", committed_data, version=10)
    ends_normally = prog(runvm(prog(), 12, 1_000), is_null)
    add_program("child-ends-normally-data-version-10", "R0", ends_normally, version=10)

    Path(out).write_text("\n".join("\t".join(r) for r in rows) + "\n")
    print(f"{len(rows)} scenarios")


if __name__ == "__main__":
    main(sys.argv[1])
