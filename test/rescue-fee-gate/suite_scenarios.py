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


def runvm(child, flags, gas_limit=None):
    """RUNVM with no arguments for the child: n=0, code, [gas limit when flags has +8]."""
    ops = [pushint(0), op([0x89], child)]
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

    def add_program(name, expect, code, budget=BUDGET):
        add(name, expect, "skip", None, None, None, None, budget=budget, code=code)

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

    Path(out).write_text("\n".join("\t".join(r) for r in rows) + "\n")
    print(f"{len(rows)} scenarios")


if __name__ == "__main__":
    main(sys.argv[1])
