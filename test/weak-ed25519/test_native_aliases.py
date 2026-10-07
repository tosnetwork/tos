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

import base64
import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc, make_dict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from native import (
    GLOBAL_ID,
    NOW,
    Emulator,
    active_account,
    compile_contract,
    external,
    internal,
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


# --- Native Service Registry -------------------------------------------------------------

REGISTRY_GUARD = "    throw_if(err::weak_key, weak_ed25519_key?(public_key));"
REG_MAGIC_DATA, REG_MAGIC_ACTION, REG_MAGIC_STATE, REG_MAGIC_POLICY = (
    0x4E564431,
    0x4E564131,
    0x4E565331,
    0x4E565031,
)
REG_OP_SUBMIT, REG_DELEGATE, REG_ERR_WEAK_KEY = 0x4E560001, 3, 2214
GENESIS = (0x11 * (2**256 - 1) // 255, 0x22 * (2**256 - 1) // 255, 0x33 * (2**256 - 1) // 255)
OBJECT_ID = 0x44 * (2**256 - 1) // 255


def registry_code():
    encoded = (ROOT / "crypto/smartcont/tos-service-native-registry-v1.boc.base64").read_text()
    return from_boc(base64.b64decode("".join(encoded.split())))


def registry_policy(controllers, threshold):
    """controllers: (public key bytes, weight); all purposes, recovery-capable."""
    nxt = None
    for public, weight in sorted(controllers, reverse=True):
        key = int.from_bytes(public, "big")
        c = Cell().uint(key, 256).uint(key, 256).uint(weight, 32).uint(0x0F, 16).uint(1, 1)
        if nxt is not None:
            c.ref(nxt)
        nxt = c
    return (
        Cell()
        .uint(REG_MAGIC_POLICY, 32)
        .uint(1, 16)
        .uint(threshold, 32)
        .uint(1, 32)
        .uint(10, 64)
        .uint(len(controllers), 8)
        .ref(nxt)
    )


class Registry:
    """An agent whose stored policy was placed in its data directly, as a hand-built
    account state could carry it."""

    def __init__(self, code, policy):
        runtime = (
            Cell()
            .sint(0, 32)
            .uint(int.from_bytes(code.hash, "big"), 256)
            .ref(Cell().raw(b"tos-testnet"))
            .ref(code)
        )
        self.code_hash = int.from_bytes(code.hash, "big")
        self.config = (
            Cell().uint(GENESIS[0], 256).uint(GENESIS[1], 256).uint(GENESIS[2], 256).ref(runtime)
        )
        initial = (
            Cell()
            .uint(REG_MAGIC_DATA, 32)
            .uint(1, 16)
            .uint(1, 8)
            .uint(OBJECT_ID, 256)
            .ref(self.config)
            .uint(0, 1)
        )
        init = Cell().uint(0, 1).uint(0, 1).uint(1, 1).ref(code).uint(1, 1).ref(initial).uint(0, 1)
        self.address = (0, int.from_bytes(init.hash, "big"))
        self.state = (
            Cell()
            .uint(REG_MAGIC_STATE, 32)
            .uint(1, 16)
            .uint(1, 8)
            .uint(0, 1)
            .uint(1, 64)
            .uint(1, 64)
            .uint(1, 256)
            .ref(policy)
            .ref(Cell().uint(0, 16).uint(0, 1))
            .ref(Cell().uint(0, 1))
        )
        data = (
            Cell()
            .uint(REG_MAGIC_DATA, 32)
            .uint(1, 16)
            .uint(1, 8)
            .uint(OBJECT_ID, 256)
            .ref(self.config)
            .uint(1, 1)
            .ref(self.state)
        )
        self.shard = active_account(self.address, code, data)

    def delegate(self, nonce):
        domain = (
            Cell()
            .uint(GENESIS[0], 256)
            .uint(GENESIS[1], 256)
            .uint(GENESIS[2], 256)
            .ref(Cell().uint(self.code_hash, 256))
        )
        return (
            Cell()
            .uint(REG_MAGIC_ACTION, 32)
            .uint(1, 16)
            .uint(REG_DELEGATE, 8)
            .uint(1, 8)
            .uint(1, 64)
            .uint(2, 64)
            .uint(OBJECT_ID, 256)
            .uint(int.from_bytes(self.state.hash, "big"), 256)
            .uint(nonce, 256)
            .ref(domain)
            .ref(Cell().uint(nonce, 256))
        )

    @staticmethod
    def signatures(entries):
        nxt = None
        for public, signature in sorted(entries, reverse=True):
            c = Cell().uint(int.from_bytes(public, "big"), 256).raw(signature)
            if nxt is not None:
                c.ref(nxt)
            nxt = c
        return Cell().uint(len(entries), 8).ref(nxt)

    def submit(self, action, authority):
        body = (
            Cell()
            .uint(REG_OP_SUBMIT, 32)
            .uint(1, 64)
            .ref(action)
            .ref(authority)
            .ref(Cell().uint(0, 8))
        )
        return internal(SENDER, self.address, body)


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
    def test_registry_stored_alias_does_not_complete_a_threshold(self):
        strong_key, strong = signer(0x71)
        shipped = registry_code()
        mutant = compile_without("native-registry-code.fc", REGISTRY_GUARD)
        for alias in (IDENTITY_ALIAS, ORDER2_ALIAS):
            for code, expected in ((shipped, REG_ERR_WEAK_KEY), (mutant, 0)):
                with self.subTest(alias=alias.hex()[:4], guarded=expected != 0):
                    agent = Registry(code, registry_policy([(strong, 1), (alias, 1)], 2))
                    for nonce in range(1, 64):
                        action = agent.delegate(nonce)
                        forged = forge(alias, action.hash)
                        if forged:
                            break
                    else:
                        self.fail("no forgeable nonce")
                    authority = Registry.signatures(
                        [(strong, strong_key.sign(action.hash)), (alias, forged)]
                    )
                    emulator = Emulator(global_version=14)
                    try:
                        exit_code, result = send(
                            emulator, agent.shard, agent.submit(action, authority)
                        )
                    finally:
                        emulator.close()
                    self.assertEqual(exit_code, expected, str(result.get("details", result))[:400])

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
