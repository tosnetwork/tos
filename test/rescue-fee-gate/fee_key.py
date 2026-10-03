"""EXPERIMENT: a fee key derived from the wallet master, so that a mnemonic-only restore can
rebuild the exact LMS tree whose public key the wallet and vault already hold.

- HKDF-SHA256 (RFC 5869) under the dual-root salt with a third label, binding the public
  fee_tree_id, gives SEED[32] || I[16].
- RFC 8554 Appendix A turns (SEED, I) into the LM-OTS private keys; the tree is built per
  RFC 8554 sections 4 and 5.

Checked against RFC 8554 Appendix F Test Case 2, whose top-level tree is the fee profile
(LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W4) and was generated with Appendix A.

PUBLIC TEST CODE: no side-channel care, no durable signer state.
Usage: fee_key.py [--check]  (validates fee-kdf-vectors.json beside this script)
"""

import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

PROFILE_SALT = b"TOS-WALLET-DUALROOT-KDF-v1"
FEE_LABEL = "TOS-FEE-LMS-SHA256-M32-v1"
D_PBLC, D_MESG, D_LEAF, D_INTR = 0x8080, 0x8181, 0x8282, 0x8383
N = 32
LMS_TYPES = {5: 5, 6: 10, 7: 15, 8: 20}
OTS_TYPES = {1: (1, 265, 7), 2: (2, 133, 6), 3: (4, 67, 4), 4: (8, 34, 0)}


def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def hkdf(master, info, length):
    prk = hmac.new(PROFILE_SALT, master, hashlib.sha256).digest()
    out, block = b"", b""
    for counter in range(1, (length + 31) // 32 + 1):
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
    return out[:length]


def fee_info(network_tag, global_id, account_index, key_generation, fee_tree_id):
    for name, value, size in (("network_tag", network_tag, 32), ("fee_tree_id", fee_tree_id, 32)):
        if not isinstance(value, bytes) or len(value) != size:
            raise ValueError(f"{name} must be {size} bytes")
    label = FEE_LABEL.encode("ascii")
    return (
        b"\x01"
        + bytes([len(label)])
        + label
        + network_tag
        + struct.pack(">iII", global_id, account_index, key_generation)
        + fee_tree_id
    )


def derive_fee_seed(master, network_tag, global_id, account_index, key_generation, fee_tree_id):
    if not isinstance(master, bytes) or len(master) != 32:
        raise ValueError("master must be 32 bytes")
    material = hkdf(master, fee_info(network_tag, global_id, account_index, key_generation, fee_tree_id), 48)
    return material[:32], material[32:]


def coef(s, i, w):
    return (s[(i * w) // 8] >> (8 - (w * (i % (8 // w)) + w))) & ((1 << w) - 1)


def checksum(q, w, ls):
    total = sum((1 << w) - 1 - coef(q, i, w) for i in range(N * 8 // w))
    return struct.pack(">H", (total << ls) & 0xFFFF)


class LmsKey:
    """One-level HSS key over one LMS tree, keys from RFC 8554 Appendix A."""

    def __init__(self, seed, ident, lms_type=6, ots_type=3):
        if len(seed) != 32 or len(ident) != 16:
            raise ValueError("SEED is 32 bytes and I is 16 bytes")
        self.seed, self.I = seed, ident
        self.lms_type, self.ots_type = lms_type, ots_type
        self.h = LMS_TYPES[lms_type]
        self.w, self.p, self.ls = OTS_TYPES[ots_type]
        leaves = 1 << self.h
        self.nodes = [b""] * (2 * leaves)
        for q in range(leaves):
            self.nodes[leaves + q] = sha256(
                self.I, struct.pack(">IH", leaves + q, D_LEAF), self.ots_public(q)
            )
        for r in range(leaves - 1, 0, -1):
            self.nodes[r] = sha256(
                self.I, struct.pack(">IH", r, D_INTR), self.nodes[2 * r], self.nodes[2 * r + 1]
            )

    def x(self, q, i):
        return sha256(self.I, struct.pack(">IHB", q, i, 0xFF), self.seed)

    def chain(self, q, i, tmp, start, stop):
        for j in range(start, stop):
            tmp = sha256(self.I, struct.pack(">IHB", q, i, j), tmp)
        return tmp

    def ots_public(self, q):
        top = (1 << self.w) - 1
        ys = [self.chain(q, i, self.x(q, i), 0, top) for i in range(self.p)]
        return sha256(self.I, struct.pack(">IH", q, D_PBLC), *ys)

    @property
    def lms_public(self):
        return struct.pack(">II", self.lms_type, self.ots_type) + self.I + self.nodes[1]

    @property
    def hss_public(self):
        return struct.pack(">I", 1) + self.lms_public

    def sign(self, q, message, randomizer):
        if not 0 <= q < 1 << self.h:
            raise ValueError("leaf out of range")
        if len(randomizer) != N:
            raise ValueError("randomizer must be 32 bytes")
        digest = sha256(self.I, struct.pack(">IH", q, D_MESG), randomizer, message)
        qc = digest + checksum(digest, self.w, self.ls)
        ys = b"".join(
            self.chain(q, i, self.x(q, i), 0, coef(qc, i, self.w)) for i in range(self.p)
        )
        ots = struct.pack(">I", self.ots_type) + randomizer + ys
        node, path = (1 << self.h) + q, b""
        while node > 1:
            path += self.nodes[node ^ 1]
            node //= 2
        lms = struct.pack(">I", q) + ots + struct.pack(">I", self.lms_type) + path
        return struct.pack(">I", 0) + lms


RFC8554_TC2_TOP = {
    "seed": "558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439",
    "I": "d08fabd4a2091ff0a8cb4ed834e74534",
    "K": "32a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e",
}


def vectors():
    master = bytes(range(32))
    network_tag = bytes(range(32, 64))
    out = []
    for account_index, key_generation, tree_byte in ((0, 0, 0xA5), (0, 0, 0xA6), (1, 1, 0xA5)):
        fee_tree_id = bytes([tree_byte]) * 32
        seed, ident = derive_fee_seed(master, network_tag, -239, account_index, key_generation, fee_tree_id)
        key = LmsKey(seed, ident)
        out.append(
            {
                "account_index": account_index,
                "key_generation": key_generation,
                "fee_tree_id_hex": fee_tree_id.hex(),
                "info_hex": fee_info(network_tag, -239, account_index, key_generation, fee_tree_id).hex(),
                "SEED_hex": seed.hex(),
                "I_hex": ident.hex(),
                "hss_public_key_hex": key.hss_public.hex(),
            }
        )
    return {
        "scope": "Public test vectors for a proposed fee-key derivation; never use for production keys.",
        "kdf": "HKDF-SHA256, salt TOS-WALLET-DUALROOT-KDF-v1, output SEED[32] || I[16]",
        "label": FEE_LABEL,
        "info_encoding": "0x01 || uint8(len(label)) || ASCII(label) || network_tag[32] || int32be(global_id) || uint32be(account_index) || uint32be(key_generation) || fee_tree_id[32]",
        "keygen": "RFC 8554 Appendix A; LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4; one-level HSS public key",
        "inputs": {"master_hex": master.hex(), "network_tag_hex": network_tag.hex(), "global_id": -239},
        "vectors": out,
    }


def check_rfc():
    tc = RFC8554_TC2_TOP
    key = LmsKey(bytes.fromhex(tc["seed"]), bytes.fromhex(tc["I"]))
    if key.nodes[1].hex() != tc["K"]:
        raise AssertionError("RFC 8554 Test Case 2 top-level root mismatch")
    # The instrument must be able to disagree.
    wrong = bytearray.fromhex(tc["seed"])
    wrong[0] ^= 1
    if LmsKey(bytes(wrong), bytes.fromhex(tc["I"])).nodes[1].hex() == tc["K"]:
        raise AssertionError("root does not depend on SEED")


def main():
    check_rfc()
    generated = vectors()
    path = Path(__file__).with_name("fee-kdf-vectors.json")
    if "--check" in sys.argv[1:]:
        if json.loads(path.read_text()) != generated:
            raise AssertionError("fee-kdf-vectors.json differs from generated vectors")
        print("OK: RFC 8554 Test Case 2 top-level root and committed fee-key vectors")
    else:
        print(json.dumps(generated, indent=2))


if __name__ == "__main__":
    main()
