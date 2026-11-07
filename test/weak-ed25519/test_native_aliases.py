#!/usr/bin/env python3
"""Forged signatures under the sign-bit aliases of the identity and the order-2 point,
run through the native transaction emulator (the C++ VM and its Ed25519 verifier).

0100..0080 and ecff..ffff name the identity and the order-2 point with x's sign bit set.
Both have x = 0, so the bit names no other point; their y is in range, so a y range check
misses them; and the verifier accepts a signature R = identity, S = 0 under them that needs
no secret (always for the identity, and whenever k = H(R || A || M) is even for the order-2
point). Each case runs twice: against the shipped contract, which must refuse the forgery,
and against the same source with the weak-key guard removed, which must accept it. The
second run is what shows the forgery is real on this verifier and that the guard is what
stops it.

Needs FUNC_PATH, FIFT_PATH and EMULATOR_PATH (see test/auth-extensions) and the
`cryptography` package.
"""

# Repository-local imports require the explicit path bootstrap below.
# ruff: noqa: E402

import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, make_dict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from native import (
    GLOBAL_ID,
    NOW,
    Emulator,
    active_account,
    compile_contract,
    external,
    state_init,
)

IDENTITY_ALIAS = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000080")
ORDER2_ALIAS = bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
R_IDENTITY = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000")
L = (1 << 252) + 27742317777372353535851937790883648493
SENDER = (0, 0x1111111111111111111111111111111111111111111111111111111111111111)


def forge(public_key: bytes, message: bytes):
    """R = identity, S = 0, when -[k]A is the identity; None otherwise."""
    k = int.from_bytes(hashlib.sha512(R_IDENTITY + public_key + message).digest(), "little") % L
    if public_key == IDENTITY_ALIAS or (public_key == ORDER2_ALIAS and k % 2 == 0):
        return R_IDENTITY + bytes(32)
    return None


def signer(seed: int):
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key, public


def compile_without(source: str, guard: str) -> Cell:
    """The contract compiled from its source with one guard line removed."""
    text = (ROOT / "crypto/smartcont" / source).read_text()
    assert text.count(guard + "\n") == 1, f"{source}: mutation target is not unique"
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        shutil.copy2(ROOT / "crypto/smartcont/strong-ed25519-key.fc", work)
        (work / source).write_text(text.replace(guard + "\n", ""))
        return compile_contract(str(work / source), work / "mutant.boc")


def send(emulator, shard, message):
    result = emulator.send(shard, message)
    if result["success"]:
        return result["details"]["exit"], result
    return result.get("vm_exit_code"), result


# --- k-of-n multisig (crypto/smartcont/multisig-code.fc) ----------------------------------

MULTISIG_GUARD = "  require_strong_owner_key(public_key);"  # the root check
MULTISIG_ERR_WEAK_OWNER = 45
WALLET_ID = 0x51570001


def multisig_data(owners, k):
    infos = make_dict(
        {
            i: Cell().uint(int.from_bytes(key, "big"), 256).uint(0, 8)
            for i, key in enumerate(owners)
        },
        8,
    )
    return (
        Cell()
        .uint(WALLET_ID, 32)
        .uint(len(owners), 8)
        .uint(k, 8)
        .uint(0, 64)
        .maybe(infos)
        .maybe(None)
    )


def multisig_root_query(root, query_id, sign):
    signed = (
        Cell().uint(root, 8).uint(0, 1).uint(WALLET_ID, 32).uint(GLOBAL_ID, 32).uint(query_id, 64)
    )
    signature = sign(signed.hash)
    if signature is None:
        return None
    query = Cell().raw(signature)
    query.bits += signed.bits
    return query


class ForgedAliasTests(unittest.TestCase):
    def test_multisig_stored_alias_cannot_sign_as_root(self):
        _, first = signer(0x72)
        _, second = signer(0x73)
        shipped = compile_contract("multisig-code.fc", Path(tempfile.mkdtemp()) / "multisig.boc")
        mutant = compile_without("multisig-code.fc", MULTISIG_GUARD)
        owners = [first, second, IDENTITY_ALIAS, ORDER2_ALIAS]
        for root, alias in ((2, IDENTITY_ALIAS), (3, ORDER2_ALIAS)):
            for code, guarded in ((shipped, True), (mutant, False)):
                with self.subTest(alias=alias.hex()[:4], guarded=guarded):
                    data = multisig_data(owners, 2)
                    address = (0, int.from_bytes(state_init(code, data).hash, "big"))
                    shard = active_account(address, code, data)
                    for offset in range(1, 64):
                        query = multisig_root_query(
                            root, ((NOW + 7200) << 32) | offset, lambda h, a=alias: forge(a, h)
                        )
                        if query is not None:
                            break
                    else:
                        self.fail("no forgeable query id")
                    emulator = Emulator()
                    try:
                        exit_code, result = send(emulator, shard, external(address, query))
                    finally:
                        emulator.close()
                    if guarded:
                        # Refused before acceptance: no transaction, so nothing is
                        # recorded and the wallet pays no fee.
                        self.assertFalse(result["success"], "a forged alias root was accepted")
                        self.assertEqual(exit_code, MULTISIG_ERR_WEAK_OWNER)
                    else:
                        self.assertTrue(result["success"], str(result)[:400])
                        self.assertEqual(exit_code, 0, "without the guard the forgery must pass")


if __name__ == "__main__":
    unittest.main()
