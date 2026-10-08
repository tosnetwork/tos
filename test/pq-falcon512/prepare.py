"""Frozen PUBLIC TEST DATA KATs and bounded negative corpus (same-source oracle)."""

# Repository-local imports require the explicit path bootstrap below.
# ruff: noqa: E402

import argparse
import ctypes
import hashlib
import json
import sys
from pathlib import Path

R = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(R / "test/falcon-auth"))
from protocol import Cell, Signer, chain, signing_message


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--library", required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    signer = Signer(a.library)
    b = signer.backend
    oracle = b.lib.falcon_verify
    oracle.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    oracle.restype = ctypes.c_int
    vectors = []
    cs = []

    def add(name, m, s, k, result):
        vectors.append(
            dict(id=name, message=m.hex(), signature=s.hex(), public_key=k.hex(), expected=result)
        )

    for name, m in [
        ("empty", b""),
        ("auth", signing_message((-1, 123), bytes(range(32)))),
        ("max", b"A" * 8192),
    ]:
        k, s = signer.sign(m)
        assert b.verify(m, s, k)
        scratch = ctypes.create_string_buffer(8192)
        assert oracle(s, len(s), 2, k, len(k), m, len(m), scratch, len(scratch)) == 0
        add(name, m, s, k, "V")
    good = vectors[1]
    for field in ("public_key", "signature", "message"):
        (a.out / (field + ".bin")).write_bytes(bytes.fromhex(good[field]))
    m, s, k = [bytes.fromhex(good[x]) for x in ("message", "signature", "public_key")]
    for n in (665, 667):
        add("signature-length-" + str(n), m, (s + b"\0")[:n], k, "M")
    for n in (896, 898):
        add("key-length-" + str(n), m, s, (k + b"\0")[:n], "M")
    add("message-overlong", b"A" * 8193, s, k, "M")
    for name, new_s in [
        ("nonzero-padding", s[:-1] + b"\1"),
        ("ct-header", b"\x59" + s[1:]),
        ("wrong-degree", b"\x3a" + s[1:]),
        ("negative-zero", s[:41] + bytes([0x80]) + bytes(624)),
        ("zero-proof", bytes(666)),
    ]:
        add(name, m, new_s, k, "I")
    add("illegal-key-coefficient", m, s, k[:1] + b"\xff\xff" + k[3:], "I")
    add("wrong-key-degree", m, s, b"\x0a" + k[1:], "I")
    for pos in (0, 28, 29, 33, 65, 96):
        mm = bytearray(m)
        mm[pos] ^= 1
        add("domain-byte-" + str(pos), bytes(mm), s, k, "I")
    for pos in (1, 40, 42, 300):
        ss = bytearray(s)
        ss[pos] ^= 1
        add("signature-byte-" + str(pos), m, bytes(ss), k, "I")
    # Real valid alternative encodings, rather than only mutated header bytes.
    # Use the reference API only in this public test harness. The wallet signer
    # continues to expose PADDED exclusively and never truncates/extends proofs.
    native_sign = b.lib.falcon_sign_dyn
    native_sign.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    native_sign.restype = ctypes.c_int
    seed_rng = b.lib.shake256_init_prng_from_seed
    seed_rng.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    seed_rng.restype = None
    for label, sig_type in [("compressed", 1), ("ct", 3)]:
        seed = hashlib.sha384(b"PUBLIC TEST DATA ALTERNATIVE FALCON " + label.encode()).digest()
        rng = (ctypes.c_uint64 * 26)()
        scratch = (ctypes.c_uint64 * 4993)()  # >= FALCON_TMPSIZE_SIGNDYN(9), aligned
        signature = ctypes.create_string_buffer(1024)
        size = ctypes.c_size_t(1024)
        seed_rng(rng, seed, len(seed))
        assert (
            native_sign(
                rng,
                signature,
                ctypes.byref(size),
                sig_type,
                b._buffer(signer.handle(0)._secret),
                1281,
                m,
                len(m),
                scratch,
                ctypes.sizeof(scratch),
            )
            == 0
        )
        alternate = signature.raw[: size.value]
        assert (
            oracle(
                alternate,
                len(alternate),
                sig_type,
                k,
                len(k),
                m,
                len(m),
                scratch,
                ctypes.sizeof(scratch),
            )
            == 0
        )
        assert len(alternate) != 666
        add("actual-" + label, m, alternate, k, "M")
        if sig_type == 3:
            add("truncated-actual-ct", m, alternate[:666], k, "I")
    # Every fixed verdict is checked both through the adapter and the explicit
    # reference PADDED API. This is API differential testing, not independent audit.
    for v in vectors:
        mm, ss, kk = [bytes.fromhex(v[x]) for x in ("message", "signature", "public_key")]
        status = b.lib.tos_falcon512_padded_verify(mm, len(mm), ss, len(ss), kk, len(kk))
        assert status == {"V": 1, "I": 0, "M": -1}[v["expected"]], v["id"]
        scratch = ctypes.create_string_buffer(8192)
        oracle_valid = oracle(ss, len(ss), 2, kk, len(kk), mm, len(mm), scratch, len(scratch)) == 0
        assert oracle_valid == (v["expected"] == "V"), v["id"]
        cs.append(
            (v["id"], [chain(mm), "skip", chain(ss), chain(kk)], 19, 1000000, 0, 1, v["expected"])
        )
    inp = [chain(m), "skip", chain(s), chain(k)]
    for version in range(19):
        cs.append((f"version-{version}", inp, version, 1000000, 0, 1, "E6"))
    for budget in (0, 9, 10, 33, 34, 20033, 20034, 22000):
        cs.append((f"gas-{budget}", inp, 19, budget, 0, 1, "E-14"))
    for i in (0, 2, 3):
        for marker, expected in [("int", "E7"), ("skip", "E2")]:
            cells = inp.copy()
            cells[i] = marker
            cs.append((f"{marker}-{i}", cells, 19, 1000000, 0, 1, expected))
        for label, bad in [
            ("unaligned", Cell().uint(1, 1)),
            ("fork", Cell().ref(Cell()).ref(Cell())),
            ("empty-tail", Cell().raw(bytes(127)).ref(Cell())),
            ("short-middle", Cell().raw(bytes(126)).ref(Cell().raw(b"x"))),
        ]:
            cells = inp.copy()
            cells[i] = bad
            cs.append((f"{label}-{i}", cells, 19, 1000000, 0, 1, "M"))
    cs.append(("eleven-paid", inp, 19, 1000000, 0, 11, "V"))
    cs.append(
        (
            "invalid-ignore-classic",
            [chain(m), "skip", chain(bytes(666)), chain(k)],
            19,
            1000000,
            1,
            1,
            "I",
        )
    )
    for ver in range(19):
        for budget in (0, 9, 10, 59, 60):
            cs.append(
                (
                    f"preactivation-{ver}-{budget}",
                    inp,
                    ver,
                    budget,
                    0,
                    1,
                    "E-14" if budget < 60 else "E6",
                )
            )
    rows = []
    for name, cells, ver, budget, ignore, repeats, expected in cs:
        rows.append(
            "\t".join(
                [name, str(ver), str(budget), str(ignore), str(repeats), expected]
                + [c if isinstance(c, str) else c.boc().hex() for c in cells]
            )
        )
    (a.out / "vectors.json").write_text(
        json.dumps(
            {"notice": "PUBLIC TEST DATA; same-source API oracle", "vectors": vectors}, indent=2
        )
        + "\n"
    )
    frozen = json.loads((R / "test/pq-falcon512/vectors.json").read_text())["vectors"]
    assert vectors == frozen, "fixed profile KAT drift"
    (a.out / "scenarios.tsv").write_text("\n".join(rows) + "\n")
    print(len(vectors), "vectors;", len(cs), "VM scenarios")


if __name__ == "__main__":
    main()
